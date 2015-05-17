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
	unsigned active;

	struct {
		struct spq *sc;
	} acquire;

	struct spq *first;
} _spq;

static inline bool
_spq_f_getChunkPath(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		char *path, size_t path_len, size_t *offset, size_t *origin)
{
	PGresult *res;
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
		xsyslog(LOG_INFO, "getChunkPath exec error: %s",
			PQresultErrorMessage(res));
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
			spq->active++;
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
	spq->active--;
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
		/* выбор активного соеденения */
		if (!spq->acquire.sc) {
			for (sc = spq->first; sc; sc = sc->next) {
				if (sc->mark_active || PQstatus(sc->conn) != CONNECTION_OK)
					continue;
				spq->acquire.sc = sc;
			}
		}
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
						xsyslog(LOG_INFO, "con[%p] error: %s",
								(void*)sc, errmsg);
					}
					PQfinish(sc->conn);
				}
				sc->conn = PQconnectdb(spq->pgstring);
				PQsetErrorVerbosity(sc->conn, PQERRORS_TERSE);
			} else if (sc->conn && pgstatus == CONNECTION_OK && sc->errhash) {
				/* сообщаем что успешно подключились и подчищаем хеш */
				sc->errhash = 0u;
				xsyslog(LOG_INFO, "con[%p] connected", (void*)sc);
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
				xsyslog(LOG_INFO, "con[%p] destroy", (void*)sc_p);
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
			break;
		}
		/* создание новых структур для пула */
		while (spq_c < spq->pool) {
			sc = calloc(1, sizeof(struct spq));
			if (sc) {
				xsyslog(LOG_INFO, "con[%p] new connection", (void*)sc);
				/* назначем какое-нибудь безумное значение
				 * что бы получить красивенье "... connected" в логе
				 */
				sc->errhash = (uint32_t)-1;
				sc->next = spq->first;
				if (sc->next)
					sc->next->prev = sc;
				spq->first = sc;
			} else {
				snprintf(errstr, sizeof(errstr) - 1, "new connection: %s",
						strerror(errno));
			}
			spq_c++;
		}
		/* проверка всяких состояний,
		 */
		clock_gettime(CLOCK_REALTIME, &ts);
		if (_spq.end) {
			ts.tv_nsec += 3000000000;
		} else {
			ts.tv_sec += 1u;
		}
		/* TODO: выполнять проверку до timedwait и после */
		pthread_cond_timedwait(&spq->cond, &spq->mutex, &ts);
		if (spq->end) {
			spq->pool = 0u;
		}
		pthread_mutex_unlock(&spq->mutex);
	}

	xsyslog(LOG_INFO, "manager exit (pool=%u, end=%s, active=%u)",
			_spq.pool, _spq.end ? "yes" : "no", _spq.active);
	return NULL;
}

void
spq_open(unsigned pool, char *pgstring)
{
	size_t pgstring_len;
	if (_spq.inited)
		return;
	if (!pgstring || !*pgstring) {
		xsyslog(LOG_WARNING, "no connection (pgstring=%s, pool=%u)",
				pgstring, pool);
		return;
	}
	pthread_cond_init(&_spq.cond, NULL);
	pthread_mutex_init(&_spq.mutex, NULL);
	pthread_mutex_lock(&_spq.mutex);
	if (pthread_create(&_spq.mgm, NULL,
				(void*(*)(void*))_thread_mgm, (void*)&_spq)) {
		xsyslog(LOG_INFO, "manager thread started: %p",
				(void*)_spq.mgm);
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
	xsyslog(LOG_INFO, "resize pool: %u -> %u", _spq.pool, pool);
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
	xsyslog(LOG_INFO, "wait manager exit, active = %u", _spq.active);
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
	const char *const tb = "SELECT fepserver_installed();";
	struct spq *sc;
	PGresult *res;
	ExecStatusType pqs;
	sc = acquire_conn(&_spq);
	if (!sc)
		return false;

	res = PQexec(sc->conn, tb);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		xsyslog(LOG_ERR, "postgresql: %s", PQresultErrorMessage(res));
		xsyslog(LOG_ERR, "please inject sql/struct.sql into db");
		release_conn(&_spq, sc);
		return false;
	} else {
		char *version = PQgetvalue(res, 0, 0);
#ifdef SQLSTRUCTVER
		xsyslog(LOG_INFO, "db struct version: %s, excepted version: %s",
				version, S(SQLSTRUCTVER));
		if (strcmp(version, S(SQLSTRUCTVER))) {
			xsyslog(LOG_ERR, "expected and db version differ (%s != %s). "
					"Please, update database from sql/struct.sql file",
					S(SQLSTRUCTVER), version);
			release_conn(&_spq, sc);
			return false;
		}
#else
		xsyslog(LOG_INFO, "db struct version: %s", version);
#endif
	}
	PQclear(res);

	release_conn(&_spq, sc);
	return true;
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

static inline uint64_t
_spq_f_logFilePush(PGconn *pgc, char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *directory, char *filename)
{
	/* FIXME: хуита */
	PGresult *res;
	ExecStatusType pqs;
	const char *tb = "UPDATE file_keys "
		"SET "
		"	time = now(), "
		"	checkpoint = trunc(extract(epoch from now())), "
		"	directory_guid = "
		"		CASE "
		"			WHEN $4::UUID IS NULL THEN directory_guid "
		"			ELSE $4::UUID "
		"		END, "
		"	enc_filename = "
		"		CASE "
		"			WHEN $5::varchar IS NULL THEN enc_filename "
		"			ELSE $5::varchar "
		"		END, "
		"	deviceid = $6 "
		"WHERE "
		"	username = $1 AND "
		"	rootdir_guid = $2 AND "
		"	file_guid = $3 "
		"RETURNING checkpoint;";
	const int fmt[6] = {0, 0, 0, 0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _dir[GUID_MAX + 1];
	char _deviceid[sizeof(uint64_t) * 8 + 1];

	char *val[6];
	int len[6];

	uint64_t checkpoint = 0u;

	len[0] = strlen(username);
	len[1] = guid2string(rootdir, _rootdir, sizeof(_rootdir));
	len[2] = guid2string(file, _file, sizeof(_file));
	len[3] = guid2string(directory, _dir, sizeof(_dir));
	len[4] = filename ? strlen(filename) : 0u;
	len[5] = snprintf(_deviceid, sizeof(_deviceid), "%"PRIu64, device_id);

	val[0] = username;
	val[1] = _rootdir;
	val[2] = _file;
	val[3] = len[3] ? _dir : NULL;
	val[4] = filename;
	val[5] = _deviceid;

	res = PQexecParams(pgc, tb, 6, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "logFilePush exec error: %s",
				PQresultErrorMessage(res));
	} else if (PQntuples(res) > 0 && PQgetlength(res, 0, 0)) {
		checkpoint = strtoul(PQgetvalue(res, 0, 0), NULL, 10);
	}
	PQclear(res);
	return checkpoint;
}

uint64_t
spq_f_logFilePush(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *directory, char *filename)
{
	uint64_t r = 0u;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_f_logFilePush(c->conn, username, device_id,
				rootdir, file, directory, filename);
		release_conn(&_spq, c);
	}
	return r;
}

static inline uint64_t
_spq_f_logDirPush(PGconn *pgc, char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *directory, char *path)
{
	PGresult *res;
	ExecStatusType pqs;
	const char *tb = "INSERT INTO directory_log "
		"( username, rootdir_guid, directory_guid, path, deviceid) "
		"VALUES ($1, $2, $3, $4, $5) "
		"RETURNING trunc(extract(epoch from time));";
	const int format[5] = {0, 0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _dir_guid[GUID_MAX + 1];
	char _deviceid[sizeof(uint64_t) * 8 + 1];

	char *val[5];
	int length[5];

	uint64_t checkpoint = 0u;

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(directory, _dir_guid, sizeof(_dir_guid));
	length[3] = path ? strlen(path) : 0;
	length[4] = snprintf(_deviceid, sizeof(_deviceid), "%"PRIu64, device_id);

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _dir_guid;
	val[3] = path;
	val[4] = _deviceid;

	res = PQexecParams(pgc, tb, 5, NULL,
			(const char *const*)val, length, format, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "logDirPush exec error: %s",
				PQresultErrorMessage(res));
	} else if (PQgetlength(res, 0, 0)) {
		checkpoint = strtoul(PQgetvalue(res, 0, 0), NULL, 10);
	}
	PQclear(res);
	return checkpoint;
}

uint64_t
spq_f_logDirPush(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *directory, char *path)
{
	uint64_t r = 0;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_f_logDirPush(c->conn, username, device_id,
				rootdir, directory, path);
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
		xsyslog(LOG_INFO, "getFileMeta exec error: %s",
			PQresultErrorMessage(res));
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

bool
_spq_insert_chunk(PGconn *pgc,
		guid_t *rootdir, guid_t *file, guid_t *revision, guid_t *chunk,
		char *chunk_hash, uint32_t chunk_size, uint32_t chunk_offset,
		char *address)
{
	PGresult *res;
	const char *tb = "SELECT insert_chunk"
		"("
		"	$1::UUID, "
		"	$2::UUID, "
		"	$3::UUID, "
		"	$4::UUID, "
		"	$5::character varying, "
		"	$6::integer, "
		"	$7::integer, "
		"	$8::text "
		");";
	const int fmt[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _revision[GUID_MAX + 1];
	char _chunk[GUID_MAX + 1];
	char _size[32];
	char _offset[32];

	char *val[8];
	int len[8];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = guid2string(file, PSIZE(_file));
	len[2] = guid2string(revision, PSIZE(_revision));
	len[3] = guid2string(chunk, PSIZE(_chunk));
	len[4] = strlen(chunk_hash);
	len[5] = snprintf(_size, sizeof(_size), "%"PRIu32, chunk_size);
	len[6] = snprintf(_offset, sizeof(_offset), "%"PRIu32, chunk_offset);
	len[7] = strlen(address);

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = _revision;
	val[3] = _chunk;
	val[4] = chunk_hash;
	val[5] = _size;
	val[6] = _offset;
	val[7] = address;

	res = PQexecParams(pgc, tb, 8, NULL, (const char *const*)val, len, fmt, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "exec insert_chunk error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		return false;
	}

	if (PQgetlength(res, 0, 0) != 0) {
		xsyslog(LOG_INFO, "exec insert_chunk error: %s",
				PQgetvalue(res, 0, 0));
		PQclear(res);
		return false;
	}

	PQclear(res);
	return true;
}

bool
spq_insert_chunk(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *revision, guid_t *chunk,
		char *chunk_hash, uint32_t chunk_size, uint32_t chunk_offset,
		char *address)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = spq_begin_life(c->conn, username, device_id) &&
			_spq_insert_chunk(c->conn, rootdir, file, revision, chunk,
				chunk_hash, chunk_size, chunk_offset, address);
		release_conn(&_spq, c);
	}
	return r;
}

bool
_spq_link_chunk(PGconn *pgc,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *new_chunk, guid_t *new_revision)
{
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] = "SELECT link_chunk"
		"("
		"	$1::UUID,"
		"	$2::UUID,"
		"	$3::UUID,"
		"	$4::UUID,"
		"	$5::UUID"
		");";
	const int fmt[5] = {0, 0, 0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _chunk[GUID_MAX + 1];
	char _new_chunk[GUID_MAX + 1];
	char _new_revision[GUID_MAX + 1];

	char *val[5];
	int len[5];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = guid2string(file, PSIZE(_file));
	len[2] = guid2string(chunk, PSIZE(_chunk));
	len[3] = guid2string(new_chunk, PSIZE(_new_chunk));
	len[4] = guid2string(new_revision, PSIZE(_new_revision));

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = _chunk;
	val[3] = _new_chunk;
	val[4] = _new_revision;

	res = PQexecParams(pgc, tb, 5, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "exec link_chunk error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		return false;
	}

	if (PQgetlength(res, 0, 0) > 0) {
		xsyslog(LOG_INFO, "exec link_chunk error: %s",
				PQgetvalue(res, 0, 0));
		PQclear(res);
		return false;
	}

	PQclear(res);
	return true;
}

bool
spq_link_chunk(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *new_chunk, guid_t *new_revision)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = spq_begin_life(c->conn, username, device_id) &&
			_spq_link_chunk(c->conn, rootdir, file, chunk,
				new_chunk, new_revision);
		release_conn(&_spq, c);
	}
	return r;
}

uint64_t
_spq_insert_revision(PGconn *pgc,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, guid_t *parent_revision,
		char *filename, char *pubkey,
		guid_t *dir,
		unsigned chunks)
{
	uint64_t result;
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] = "SELECT insert_revision"
		"("
		"	$1::UUID,"
		"	$2::UUID,"
		"	$3::UUID,"
		"	$4::UUID,"
		"	$5::character varying,"
		"	$6::character varying,"
		"	$7::UUID,"
		"	$8::integer"
		");";
	const int fmt[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _revision[GUID_MAX + 1];
	char _parent_revision[GUID_MAX + 1];
	char _dir[GUID_MAX + 1];
	char _chunks[32];

	const char *_m = NULL;
	char *val[8];
	int len[8];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = guid2string(file, PSIZE(_file));
	len[2] = guid2string(revision, PSIZE(_revision));
	len[3] = guid2string(parent_revision, PSIZE(_parent_revision));
	len[4] = strlen(filename);
	len[5] = strlen(pubkey);
	len[6] = guid2string(dir, PSIZE(_dir));
	len[7] = snprintf(_chunks, sizeof(_chunks), "%u", chunks);

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = _revision;
	val[3] = _parent_revision;
	val[4] = filename;
	val[5] = pubkey;
	val[6] = _dir;
	val[7] = _chunks;

	res = PQexecParams(pgc, tb, 8, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);

	if (pqs != PGRES_TUPLES_OK)
		_m = PQresultErrorMessage(res);
	else if (PQgetlength(res, 0, 0))
		_m = PQgetvalue(res, 0, 0);

	if (_m) {
		xsyslog(LOG_INFO, "exec insert_revision error: %s", _m);
		PQclear(res);
		return 0;
	}
	result = strtoul(PQgetvalue(res, 0, 1), NULL, 10);
	PQclear(res);
	return result;
}

uint64_t
spq_insert_revision(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, guid_t *parent_revision,
		char *filename, char *pubkey,
		guid_t *dir,
		unsigned chunks)
{
	uint64_t r = 0lu;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		if (spq_begin_life(c->conn, username, device_id)) {
			r = _spq_insert_revision(c->conn, rootdir, file,
					revision, parent_revision, filename, pubkey, dir, chunks);
		}
		release_conn(&_spq, c);
	}
	return r;
}

bool
spq_begin_life(PGconn *pgc, char *username, uint64_t device_id)
{
	PGresult *res;
	const char tb[] = "SELECT begin_life($1::character varying, $2::bigint);";
	const int fmt[2] = {0, 0};

	char _device_id[16];

	char *val[2];
	int len[2];

	len[0] = strlen(username);
	len[1] = snprintf(_device_id, sizeof(_device_id), "%"PRIu64, device_id);

	val[0] = username;
	val[1] = _device_id;

	res = PQexecParams(pgc, tb, 2, NULL, (const char *const*)val, len, fmt, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "exec begin_life error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		return false;
	}

	PQclear(res);
	return true;
}

static inline bool
_spq_check_user(PGconn *pgc, char *username, char *secret)
{
	bool r = false;
	PGresult *res;
	const char tb[] =
		"SELECT check_user($1::character varying, $2::character varying);";
	const int fmt[2] = {0, 0};
	char *val[2];
	int len[2];

	len[0] = strlen(username);
	len[1] = strlen(secret);

	val[0] = username;
	val[1] = secret;

	res = PQexecParams(pgc, tb, 2, NULL, (const char *const*)val, len, fmt, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "exec check_user error: %s",
				PQresultErrorMessage(res));
	} else if (PQgetlength(res, 0, 0)) {
		if (PQgetvalue(res, 0, 0)[0] == 't')
			r = true;
	}

	PQclear(res);
	return r;
}

bool
spq_check_user(char *username, char *secret)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_check_user(c->conn, username, secret);
		release_conn(&_spq, c);
	}
	return r;
}

#include "complex/getRevisions.c"
#include "complex/getChunks.c"
#include "complex/logDirFile.c"

