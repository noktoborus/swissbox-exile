/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/simplepq.c
 */
#include "simplepq.h"
#include "junk/xsyslog.h"

#include <inttypes.h>
#include <stdlib.h>

#include <errno.h>
#include <string.h>

#include <time.h>
#include <libpq-fe.h>
#include <pthread.h>
#include <sys/time.h>

#ifndef MIN
# define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

struct spq {
	PGconn *conn;

	struct timeval lc; /* последняя проверка статуса */
	uint32_t errhash;
	bool mark_active;

	struct spq *next;
	struct spq *prev;
};

static struct spq_root {
	char pgstring[PATH_MAX + 1];

	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t mgm;

	bool inited;
	bool end;
	unsigned pool;

	struct {
		struct spq *sc;
	} acquire;

	struct spq *first;
} _spq;

/* */
static inline bool
_spq_f_chunkRename(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *chunk_new, guid_t *revision_new)
{
	PGresult *res;
	ExecStatusType pqs;
	char errstr[1024];
	const char *tb = "INSERT INTO file_records "
		"SELECT "
		"	time,"
		"	username,"
		"	chunk_hash,"
		"	$5,"
		"	rootdir_guid,"
		"	file_guid,"
		"	$6,"
		"	chunk_path,"
		"	\"offset\","
		"	origin "
		"FROM file_records "
		"WHERE "
		"	username = $1 AND"
		"	rootdir_guid = $2 AND"
		"	file_guid = $3 AND"
		"	chunk_guid =  $4"
		"RETURNING time;";
	const int format[6] = {0, 0, 0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _chunk_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _chunk_new_guid[GUID_MAX + 1];
	char _revision_new_guid[GUID_MAX + 1];

	char *val[6];
	int length[6];

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = guid2string(chunk, _chunk_guid, sizeof(_chunk_guid));
	length[4] = guid2string(chunk_new,
			_chunk_new_guid, sizeof(_chunk_new_guid));
	length[5] = guid2string(revision_new,
			_revision_new_guid, sizeof(_revision_new_guid));

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = _chunk_guid;
	val[4] = _chunk_new_guid;
	val[5] = _revision_new_guid;

	res = PQexecParams(pgc, tb, 6, NULL,
			(const char *const*)val, length, format, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: chunkRename exec error: %s",
				PQresultErrorMessage(res));
			syslog(LOG_INFO, errstr);
			PQclear(res);
			return false;
	}
	if (PQntuples(res) <= 0) {
		PQclear(res);
		return false;
	}
	PQclear(res);
	return true;
}

static inline bool
_spq_f_getChunkPath(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		char *path, size_t path_len, size_t *offset, size_t *origin)
{
	PGresult *res;
	char errstr[1024];
	const char *tb = "SELECT chunk_path, \"offset\", origin "
		"FROM file_records WHERE "
		"username = $1 AND "
		"rootdir_guid = $2 AND "
		"file_guid = $3 AND "
		"chunk_guid = $4;";
	const int format[4] = {0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _chunk_guid[GUID_MAX + 1];

	char *val[4];
	int length[4];

	char *value;
	size_t value_len;

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = guid2string(chunk, _chunk_guid, sizeof(_chunk_guid));

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = _chunk_guid;

	res = PQexecParams(pgc, tb, 4, NULL,
			(const char *const*)val, length, format, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: getChunkPath exec error: %s",
			PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return false;
	}

	value = PQgetvalue(res, 0, 0);
	value_len = PQgetlength(res, 0, 0);

	/* декрементируем длину, что бы можно было втиснуть венчающий \0 */
	path_len--;
	memcpy(path, value, MIN(value_len, path_len));
	path[MIN(value_len, path_len)] = '\0';

	if (offset && PQgetlength(res, 0, 1))
		*offset = strtoul(PQgetvalue(res, 0, 1), NULL, 10);
	if (origin && PQgetlength(res, 0, 2))
		*origin = strtoul(PQgetvalue(res, 0, 2), NULL, 10);

	PQclear(res);
	return true;
}


static inline bool
_spq_f_chunkNew(PGconn *pgc, char *username, char *hash, char *path,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file,
		uint32_t offset, uint32_t origin_len)
{
	PGresult *res;
	char errstr[1024];
	const char *tb = "INSERT INTO file_records"
		"("
		"	username, "
		"	rootdir_guid, "
		"	file_guid,"
		"	revision_guid, "
		"	chunk_guid, "
		"	chunk_hash, "
		"	chunk_path, "
		"	\"offset\","
		"	origin"
		") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);";
	const int format[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _revision_guid[GUID_MAX + 1];
	char _chunk_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _offset[16];
	char _origin[16];

	char *val[9];
	int length[9];

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = guid2string(revision, _revision_guid, sizeof(_revision_guid));
	length[4] = guid2string(chunk, _chunk_guid, sizeof(_chunk_guid));
	length[5] = strlen(hash);
	length[6] = strlen(path);
	length[7] = snprintf(_offset, sizeof(_offset), "%"PRIu32, offset);
	length[8] = snprintf(_origin, sizeof(_origin),"%"PRIu32, origin_len);

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = _revision_guid;
	val[4] = _chunk_guid;
	val[5] = hash;
	val[6] = path;
	val[7] = _offset;
	val[8] = _origin;

	res = PQexecParams(pgc, tb, 9, NULL,
			(const char *const*)val, length, format, 0);

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		snprintf(errstr, sizeof(errstr), "spq: chunkNew exec error: %s",
			PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return false;
	}

	PQclear(res);
	return true;
}


static inline uint64_t
_spq_f_chunkFile(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *file, guid_t *revision,
		guid_t *parent_revision, guid_t *dir,
		char *enc_filename, uint64_t deviceid, char *pkey)
{
	PGresult *res;
	ExecStatusType pqs;
	char errstr[1024];
	const char tb[] = "INSERT INTO file_keys"
		"("
		"	username,"
		"	rootdir_guid,"
		"	file_guid,"
		"	revision_guid,"
		"	parent_revision_guid,"
		"	directory_guid,"
		"	enc_filename,"
		"	deviceid,"
		"	public_key"
		") VALUES ($1, $2, $3, $4::UUID, $5, $6, $7, $8, $9)"
		"RETURNING trunc(extract(epoch from time));";
	const int format[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	char _s_rootdir[GUID_MAX + 1];
	char _s_file[GUID_MAX + 1];
	char _s_revision[GUID_MAX + 1];
	char _s_parent[GUID_MAX + 1];
	char _s_dir[GUID_MAX + 1];
	char _deviceid[sizeof(uint64_t) * 8 + 1];

	char *val[9];
	int length[9];

	uint64_t checkpoint = 0u;

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _s_rootdir, sizeof(_s_rootdir));
	length[2] = guid2string(file, _s_file, sizeof(_s_file));
	length[3] = guid2string(revision, _s_revision, sizeof(_s_revision));
	length[4] = guid2string(parent_revision, _s_parent, sizeof(_s_parent));
	length[5] = guid2string(dir, _s_dir, sizeof(_s_dir));
	length[6] = strlen(enc_filename);
	length[7] = snprintf(_deviceid, sizeof(_deviceid), "%"PRIu64, deviceid);
	length[8] = strlen(pkey);

	val[0] = username;
	val[1] = _s_rootdir;
	val[2] = _s_file;
	val[3] = _s_revision;
	val[4] = length[4] ? _s_parent : NULL;
	val[5] = _s_dir;
	val[6] = enc_filename;
	val[7] = _deviceid;
	val[8] = pkey;

	res = PQexecParams(pgc, tb, 9, NULL,
			(const char *const*)val, length, format, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: chunkFile exec error: %s",
			PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
	} else if (PQgetlength(res, 0, 0)) {
		checkpoint = strtoul(PQgetvalue(res, 0, 0), NULL, 10);
	}

	PQclear(res);
	return checkpoint;
}

/* поиск и захват ближайшего доступного ресурса в пуле */
static struct spq*
_acquire_conn(struct spq_root *spq)
{
	struct spq *c = NULL;
	while(c == NULL) {
		/* процедура выполняется параллельно */
		pthread_mutex_lock(&spq->mutex);
		if (spq->end)
			break;
		if (!spq->acquire.sc) {
			pthread_cond_signal(&spq->cond);
		} else {
			c = spq->acquire.sc;
			c->mark_active = true;
			spq->acquire.sc = NULL;
		}
		pthread_mutex_unlock(&spq->mutex);
	}
	return c;
}

/* возвращение захваченного ресурса в пул */
static void
_release_conn(struct spq_root *spq, struct spq *sc)
{
	/* процедура выполняется параллельно */
	pthread_mutex_lock(&spq->mutex);
	sc->mark_active = false;
	pthread_mutex_unlock(&spq->mutex);
	return;
}
#if 0
static inline struct spq*
__acquire_conn(struct spq_root *spq, const char *funcname)
{
	struct spq *c;
	if ((c = _acquire_conn(spq)))
		xsyslog(LOG_DEBUG, "acquire %p in %s", (void*)c, funcname);
	return c;
}

static inline void
__release_conn(struct spq_root *spq, struct spq *sc, const char *funcname)
{
	xsyslog(LOG_DEBUG, "release %p in %s", (void*)sc, funcname);
	_release_conn(spq, sc);
	return;
}

# define acquire_conn(x) __acquire_conn(x, __func__)
# define release_conn(x, y) __release_conn(x, y, __func__)
#else
# define acquire_conn(x) _acquire_conn(x)
# define release_conn(x, y) _release_conn(x, y)
#endif


static void*
_thread_mgm(struct spq_root *spq)
{
	char errstr[1024];
	struct timeval tvc;
	struct timespec ts;
	struct spq *sc;
	unsigned spq_c; /* счётчик активных коннекшенов */
	ConnStatusType pgstatus;
	/* инициализация */
	pthread_mutex_lock(&spq->mutex);
#if __USE_GNU
	pthread_setname_np(pthread_self(), "SimplePQ");
#endif
	pthread_mutex_unlock(&spq->mutex);
	/* глубже */
	while (true) {
		gettimeofday(&tvc, NULL);
		spq_c = 0u;
		pthread_mutex_lock(&spq->mutex);
		/* проверка статуса и выполнение переподключений */
		for (sc = spq->first; sc; sc = sc->next) {
			spq_c++;
			pgstatus = PQstatus(sc->conn);
			if (pgstatus != CONNECTION_OK
					&& !sc->mark_active
					&& spq_c <= spq->pool) {
				/*
				 * переподключение должно происходить при соблюдении условий:
				 * 1. структура не помечена для отчистки
				 * 2. счётчик подключений меньше или равен пулу
				 * 3. подключение сбоило (!= CONNECTION_OK)
				 */
				if (sc->conn != NULL) {
					uint32_t errhash;
					char *errmsg;
					errmsg = PQerrorMessage(sc->conn);
					errhash = hash_pjw(errmsg, strlen(errmsg));
					/* обновляем хеш ошибки, если не совпадает и
					 * печатаем в лог
					 */
					if (errhash != sc->errhash) {
						sc->errhash = errhash;
						snprintf(errstr, sizeof(errstr) - 1,
								"spq: [%p] error: %s",
								(void*)sc, errmsg);
						syslog(LOG_INFO, errstr);
					}
					PQfinish(sc->conn);
				}
				sc->conn = PQconnectdb(spq->pgstring);
				PQsetErrorVerbosity(sc->conn, PQERRORS_TERSE);
			} else if (sc->conn && pgstatus == CONNECTION_OK && sc->errhash) {
				/* сообщаем что успешно подключились и подчищаем хеш */
				sc->errhash = 0u;
				syslog(LOG_INFO, "spq: [%p] connected", (void*)sc);
			} else if ((sc->conn && pgstatus == CONNECTION_BAD)
					|| (spq_c > spq->pool && !sc->mark_active)) {
				/*
				 * удаление ненужнех структур
				 */
				struct spq *sc_p = sc;
				PQfinish(sc->conn);
				sc = sc->next;
				/* удаление из списка */
				if (spq->first == sc_p)
					spq->first = sc;
				if (sc_p->prev)
					sc_p->prev->next = sc_p->next;
				if (sc_p->next)
					sc_p->next->prev = sc_p->prev;
				/* подчистка */
				snprintf(errstr, sizeof(errstr) - 1, "spq: [%p] destroy",
						(void*)sc_p);
				syslog(LOG_INFO, errstr);
				free(sc_p);
				/* если список закончился, то нужно выйти из цикла чуть раньше
				 */
				if (!sc)
					break;
			} else if (tvc.tv_sec - sc->lc.tv_sec > 10) {
				/* еже-десятисекундная проверка соеденения
				 * на самом деле не очень ок, потому что зафлуживает бд
				 * TODO: добавить в конфигурашку
				 */
				PQclear(PQexec(sc->conn, "SELECT;"));
				memcpy(&sc->lc.tv_sec, &tvc.tv_sec, sizeof(struct timeval));
			}
		}
		if (spq_c == 0u && spq->pool == 0u) {
			syslog(LOG_INFO, "spq: empty pool, drop thread");
			break;
		}
		/* создание новых структур для пула */
		while (spq_c < spq->pool) {
			sc = calloc(1, sizeof(struct spq));
			if (sc) {
				snprintf(errstr, sizeof(errstr) - 1,
						"spq: [%p] new connection", (void*)sc);
				syslog(LOG_INFO, errstr);
				/* назначем какое-нибудь безумное значение
				 * что бы получить красивенье "... connected" в логе
				 */
				sc->errhash = (uint32_t)-1;
				sc->next = spq->first;
				if (sc->next)
					sc->next->prev = sc;
				spq->first = sc;
			} else {
				snprintf(errstr, sizeof(errstr) - 1, "spq: new connection: %s",
						strerror(errno));
			}
			spq_c++;
		}
		/* выбор активного соеденения */
		if (!spq->acquire.sc) {
			for (sc = spq->first; sc; sc = sc->next) {
				if (sc->mark_active || PQstatus(sc->conn) != CONNECTION_OK)
					continue;
				spq->acquire.sc = sc;
			}
		}
		/* проверка всяких состояний,
		 */
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1u;
		ts.tv_nsec += 30u;
		/* TODO: выполнять проверку до timedwait и после */
		pthread_cond_timedwait(&spq->cond, &spq->mutex, &ts);
		if (spq->end) {
			spq->pool = 0u;
		}
		pthread_mutex_unlock(&spq->mutex);
	}

	syslog(LOG_WARNING, "spq: manager exit");
	return NULL;
}

void
spq_open(unsigned pool, char *pgstring)
{
	size_t pgstring_len;
	if (_spq.inited)
		return;
	if (!pgstring || !*pgstring) {
		syslog(LOG_WARNING, "spq: pgstring not passed");
		return;
	}
	pthread_cond_init(&_spq.cond, NULL);
	pthread_mutex_init(&_spq.mutex, NULL);
	pthread_mutex_lock(&_spq.mutex);
	if (pthread_create(&_spq.mgm, NULL,
				(void*(*)(void*))_thread_mgm, (void*)&_spq)) {
		syslog(LOG_INFO, "spq: manager thread started");
	}
	_spq.pool = pool;
	pgstring_len = strlen(pgstring);
	memcpy(_spq.pgstring, pgstring, MIN(pgstring_len, PATH_MAX));
	pthread_mutex_unlock(&_spq.mutex);
}

void
spq_resize(unsigned pool)
{
	if (pool == _spq.pool)
		return;
	syslog(LOG_INFO, "spq: resize pool: %u -> %u", _spq.pool, pool);
}

void
spq_close()
{
	void *n;
	/* сообщаем треду что пора бы закругляться */
	pthread_mutex_lock(&_spq.mutex);
	_spq.end = true;
	pthread_cond_broadcast(&_spq.cond);
	pthread_mutex_unlock(&_spq.mutex);
	syslog(LOG_INFO, "spq: wait manager exit");
	pthread_join(_spq.mgm, &n);
	pthread_mutex_destroy(&_spq.mutex);
	pthread_cond_destroy(&_spq.cond);
}

/*
 *
 * TABLE file_records # записи FileUpdate + WriteAsk
 *	time
 *	user
 *	rootdir_guid
 *	chunk_hash
 *	file_guid
 *	revision_guid
 *	parent_revision_guid
 *
 */

bool
spq_create_tables()
{
	char errstr[4096];
	const char *const tbs[] = {"CREATE TABLE IF NOT EXISTS file_records "
		"("
		"	time timestamp with time zone NOT NULL DEFAULT now(), "
		"	username varchar(1024) NOT NULL, "
		"	chunk_hash varchar(1024) NOT NULL, "
		"	chunk_guid UUID NOT NULL, "
		"	rootdir_guid UUID NOT NULL, "
		"	file_guid UUID NOT NULL, "
		"	revision_guid UUID NOT NULL, "
		"	chunk_path varchar(1024) NOT NULL, "
		"	\"offset\" integer NOT NULL DEFAULT 0, "
		"	origin integer NOT NULL DEFAULT 0 "
		");",
		"CREATE TABLE IF NOT EXISTS file_keys "
		"("
		"	time timestamp with time zone NOT NULL DEFAULT now(), "
		"	username varchar(1024) NOT NULL,"
		"	rootdir_guid UUID NOT NULL, "
		"	file_guid UUID NOT NULL, "
		"	revision_guid UUID DEFAULT NULL, "
		"	directory_guid UUID NOT NULL, "
		"	parent_revision_guid UUID DEFAULT NULL, "
		"	enc_filename varchar(1024) NOT NULL, "
		"	deviceid bigint NOT NULL, "
		"	public_key varchar(4096) NOT NULL"
		");", /* таблица directory_tree должна заполняться автоматически
				 по триггеру в таблице directory_log
				 содержит текущий список каталогов
				 */
		"CREATE TABLE IF NOT EXISTS directory_tree "
		"("
		"	username varchar(1024) NOT NULL,"
		"	rootdir_guid UUID NOT NULL,"
		"	directory_guid UUID NOT NULL,"
		"	path varchar(4096) NOT NULL"
		");",
		"CREATE TABLE IF NOT EXISTS directory_log "
		"("
		"	time timestamp with time zone NOT NULL DEFAULT now(),"
		"	username varchar(1024) NOT NULL,"
		"	rootdir_guid UUID NOT NULL,"
		"	directory_guid UUID NOT NULL,"
		"	path varchar(4096) DEFAULT NULL,"
		"	deviceid bigint NOT NULL"
		");",
		"CREATE UNIQUE INDEX file_keys_urfr_idx "
		"ON file_keys "
		"("
		"	lower(username),"
		"	rootdir_guid,"
		"	file_guid,"
		"	revision_guid"
		");",
		"CREATE UNIQUE INDEX file_records_urfcr_idx "
		"ON file_records "
		"("
		"	lower(username),"
		"	rootdir_guid,"
		"	file_guid,"
		"	revision_guid,"
		"	chunk_guid"
		");",
		NULL
	};
	char **p;
	struct spq *sc;
	PGresult *res;
	sc = acquire_conn(&_spq);
	if (!sc)
		return false;
	for (p = (char**)tbs; *p; p++) {
		res = PQexec(sc->conn, *p);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			snprintf(errstr, sizeof(errstr) - 1, "spq: create error: %s",
					PQresultErrorMessage(res));
			syslog(LOG_INFO, errstr);
		}
		PQclear(res);
	}

	release_conn(&_spq, sc);
	return true;
}

bool
spq_f_chunkRename(char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *chunk_new, guid_t *revision_new)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_f_chunkRename(c->conn, username, rootdir, file, chunk,
				chunk_new, revision_new);
		release_conn(&_spq, c);
	}
	return r;
}

bool
spq_f_chunkNew(char *username, char *hash, char *path,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file,
		uint32_t offset, uint32_t origin_len)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_f_chunkNew(c->conn, username, hash, path,
				rootdir, revision, chunk, file, offset, origin_len);
		release_conn(&_spq, c);
	}
	return r;
}

uint64_t
spq_f_chunkFile(char *username,
		guid_t *rootdir, guid_t *file, guid_t *revision,
		guid_t *parent_revision, guid_t *dir,
		char *enc_filename, uint64_t deviceid, uint8_t *pkey, size_t pkey_len)
{
	uint64_t r = 0u;
	struct spq *c;
	size_t pkeyhex_sz = pkey_len * 2 + 1;
	char *pkeyhex = calloc(1, pkeyhex_sz);
	if (pkeyhex) {
		bin2hex((uint8_t*)pkey, pkey_len, pkeyhex, pkeyhex_sz);
		if ((c = acquire_conn(&_spq)) != NULL) {
			r = _spq_f_chunkFile(c->conn, username, rootdir, file, revision,
					parent_revision, dir,
					enc_filename, deviceid, pkeyhex);
			release_conn(&_spq, c);
		}
		free(pkeyhex);
	}
	return r;
}

bool
spq_f_getChunkPath(char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		char *path, size_t path_len, size_t *offset, size_t *origin)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_f_getChunkPath(c->conn, username, rootdir, file, chunk,
				path, path_len, offset, origin);
		release_conn(&_spq, c);
	}
	return r;
}

static inline bool
_spq_f_logDirPush(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *directory, char *path)
{
	PGresult *res;
	ExecStatusType pqs;
	char errstr[1024];
	const char *tb = "INSERT INTO directory_log "
		"( username, rootdir_guid, directory_guid, path ) "
		"VALUES ($1, $2, $3, $4);";
	const int format[5] = {0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _dir_guid[GUID_MAX + 1];

	char *val[4];
	int length[4];

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(directory, _dir_guid, sizeof(_dir_guid));
	length[3] = path ? strlen(path) : 0;

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _dir_guid;
	val[3] = path;

	res = PQexecParams(pgc, tb, 4, NULL,
			(const char *const*)val, length, format, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_EMPTY_QUERY) {
		snprintf(errstr, sizeof(errstr), "spq: logDirPush exec error: %s",
					PQresultErrorMessage(res));
				syslog(LOG_INFO, errstr);
				PQclear(res);
				return false;
	}
	PQclear(res);
	return true;
}

uint64_t
spq_f_logDirPush(char *username, guid_t *rootdir, guid_t *directory, char *path)
{
	uint64_t r = 0;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_f_logDirPush(c->conn, username, rootdir, directory, path);
		release_conn(&_spq, c);
	}
	return r;
}

bool
_spq_f_getFileMeta(PGconn *pgc, char *username, guid_t *rootdir, guid_t *file,
		guid_t *revision, struct spq_FileMeta *fmeta)
{
	PGresult *res;
	ExecStatusType pqs;
	const char *tb =
	"SELECT "
	"	revision_guid, "
	"	directory_guid, "
	"	(SELECT COUNT(*) "
	"		FROM file_records "
	"		WHERE "
	"			file_records.rootdir_guid = file_keys.rootdir_guid AND "
	"			file_records.file_guid = file_keys.file_guid AND "
	"			file_records.revision_guid = file_keys.revision_guid) "
	"	AS chunks, "
	"	parent_revision_guid, "
	"	enc_filename, "
	"	public_key "
	"FROM file_keys "
	"WHERE "
	"	username = $1 AND "
	"	rootdir_guid = $2 AND "
	"	file_guid = $3 AND "
	"	(($4::UUID IS NOT NULL AND revision_guid = $4) OR TRUE) "
	"	ORDER BY time DESC "
	"LIMIT 1;";

	const int fmt[4] = {0, 0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _revision[GUID_MAX + 1];

	char *val[4];
	int len[4];

	len[0] = strlen(username);
	len[1] = guid2string(rootdir, _rootdir, sizeof(_rootdir));
	len[2] = guid2string(file, _file, sizeof(_file));
	len[3] = guid2string(revision, _revision, sizeof(_revision));

	val[0] = username;
	val[1] = _rootdir;
	val[2] = _file;
	val[3] = len[3] ? _revision : NULL;

	res = PQexecParams(pgc, tb, 4, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK && pqs != PGRES_EMPTY_QUERY) {
		char errstr[1024];
		snprintf(errstr, sizeof(errstr), "spq: getFileMeta exec error: %s",
					PQresultErrorMessage(res));
				syslog(LOG_INFO, errstr);
				PQclear(res);
				return false;
	}

	if (PQntuples(res) <= 0) {
		fmeta->empty = true;
		return true;
	}

	/* складирование результатов */
	fmeta->res = res;
	/* revision guid */
	fmeta->rev = PQgetvalue(res, 0, 0);
	fmeta->dir = PQgetvalue(res, 0, 1);
	if (PQgetlength(res, 0, 2) > 0) {
		fmeta->chunks = (uint32_t)strtoul(PQgetvalue(res, 0, 2), NULL, 10);
	} else {
		fmeta->chunks = 0u;
	}
	fmeta->parent_rev = PQgetvalue(res, 0, 3);
	fmeta->enc_filename = PQgetvalue(res, 0, 4);
	{
		int _len;
		if ((_len = PQgetlength(res, 0, 5)) > 0) {
			fmeta->key_len =
				hex2bin(PQgetvalue(res, 0, 5), _len, fmeta->key, PUBKEY_MAX);
		} else {
			memset(fmeta->key, 0u, PUBKEY_MAX);
			fmeta->key_len = 0u;
		}
	}

	return true;
}

bool
spq_f_getFileMeta(char *username, guid_t *rootdir, guid_t *file,
		guid_t *revision, struct spq_FileMeta *fmeta)
{
	bool retval = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		if (!(retval = _spq_f_getFileMeta(c->conn,
						username, rootdir, file, revision, fmeta))
				|| fmeta->empty) {
			memset(fmeta, 0u, sizeof(struct spq_FileMeta));
			fmeta->empty = true;
			release_conn(&_spq, c);
		} else {
			fmeta->p = c;
		}
	}
	return retval;
}

void
spq_f_getFileMeta_free(struct spq_FileMeta *fmeta)
{
	if (fmeta->res) {
		PQclear(fmeta->res);
	}
	if (fmeta->p) {
		release_conn(&_spq, fmeta->p);
	}
	memset(fmeta, 0u, sizeof(struct spq_FileMeta));
}

#include "complex/getRevisions.c"
#include "complex/getChunks.c"
#include "complex/logDirFile.c"

