/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/simplepq.c
 */
#include "simplepq.h"
#include "snip.h"
#include <syslog.h>

#include <stdlib.h>

#include <errno.h>
#include <string.h>

#include <time.h>
#include <libpq-fe.h>
#include <pthread.h>

#if __linux__
# include <linux/limits.h>
#else
# include <limits.h>
#endif

#ifndef MIN
# define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

struct spq {
	PGconn *conn;

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

/* поиск и захват ближайшего доступного ресурса в пуле */
static struct spq*
acquire_conn(struct spq_root *spq)
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
			spq->acquire.sc = NULL;
		}
		/* TODO: mark_active = true */
		pthread_mutex_unlock(&spq->mutex);
	}
	return c;
}

/* возвращение захваченного ресурса в пул */
static void
release_conn(struct spq_root *spq, struct spq *sc)
{
	/* процедура выполняется параллельно */
	pthread_mutex_lock(&spq->mutex);
	sc->mark_active = false;
	pthread_mutex_unlock(&spq->mutex);
	return;
}

static void*
_thread_mgm(struct spq_root *spq)
{
	char errstr[1024];
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
					snprintf(errstr, sizeof(errstr) - 1, "spq: [%p] error: %s",
							(void*)sc, PQerrorMessage(sc->conn));
					syslog(LOG_INFO, errstr);
					PQfinish(sc->conn);
				}
				sc->conn = PQconnectdb(spq->pgstring);
				PQsetErrorVerbosity(sc->conn, PQERRORS_TERSE);
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
		ts.tv_nsec += 3000u;
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
	const char *tb_fr = "CREATE TABLE IF NOT EXISTS file_records "
		"("
		"	time timestamp with time zone NOT NULL DEFAULT now(), "
		"	username varchar(1024) NOT NULL, "
		"	chunk_hash varchar(1024) NOT NULL, "
		"	chunk_guid UUID NOT NULL, "
		"	rootdir_guid UUID NOT NULL, "
		"	revision_guid UUID NOT NULL, "
		"	parent_revision_guid UUID DEFAULT NULL, "
		"	chunk_path varchar(1024), "
		"	file_guid UUID, "
		"	filename varchar(1024) DEFAULT NULL"
		");";
	struct spq *sc;
	PGresult *res;
	sc = acquire_conn(&_spq);
	if (!sc)
		return false;
	res = PQexec(sc->conn, tb_fr);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		snprintf(errstr, sizeof(errstr) - 1, "spq: create error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
	}

	release_conn(&_spq, sc);
	return true;
}

bool
spq_f_chunkNew(char *username, char *hash, char *path,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file)
{
	bool r;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_f_chunkNew(c->conn, username, hash, path,
				rootdir, revision, chunk, file);
		release_conn(&_spq, c);
	}
	return r;
}

bool
spq_f_chunkFile(char *username,
		guid_t *rootdir, guid_t *revision, guid_t *file,
		char *filename, guid_t *parent_revision)
{
	bool r;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_f_chunkFile(c->conn, username, rootdir, revision, file,
				filename, parent_revision);
		release_conn(&_spq, c);
	}
	return r;
}
