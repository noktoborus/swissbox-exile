/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/include/mgm.c
 */

struct spq {
	PGconn *conn;

	/* хеш строки подключения
	 * нужен при переподключении к другому серверу
	 */
	uint32_t pgstring_hash;

	struct timeval lc; /* последняя проверка статуса */
	uint32_t errhash;
	bool mark_active;

#if DEEPDEBUG
	const char *acquired_by;
	unsigned acquires;
#endif

	struct spq *next;
	struct spq *prev;
};

struct spq_options {
	char *pgstring;
	bool log_failed_queries;
	unsigned pool;
};

static struct spq_root {
	struct ev_loop *loop;

	struct ev_async exit;
	struct ev_async update;
	struct ev_timer timer;
	struct ev_timer ping;

	pthread_t mgm;

	bool inited;
	/* структура для
	 * обновления конфигурации
	 * сначала значения изменяются в этих полях
	 * после чего дёргается _spq.update
	 * и конфигурация переносится в рабочую структуру
	 */
	struct spq_options options_in;

	/* рабочая структура конфигурации */
	struct spq_options options;

	/* хеш подключения, должен изменяться каждый раз,
	 * как приходит обновление конфигурации
	 */
	uint32_t pgstring_hash;

	struct {
		struct spq *sc;
	} acquire;

	struct spq *first;
} _spq;

#if DEEPDEBUG
static void
spq_ac() {
#if 0
	unsigned c = 1u;
	struct spq *sc;
	xsyslog(LOG_USER, "stats: (pool=%u, end=%s, active=%u)\n",
			_spq.pool, _spq.end ? "yes" : "no", _spq.active);
	for (sc = _spq.first; sc; sc = sc->next, c++) {
		xsyslog(LOG_USER,
				"n#%02u: active: %s, acquired: %s (%u), status: %d @ %p\n",
				c,
				sc->mark_active ? "yes" : "no",
				sc->acquired_by,
				sc->acquires,
				PQstatus(sc->conn),
				(void*)sc);
	}
#endif
}

#endif

/* поиск и захват ближайшего доступного ресурса в пуле */
static struct spq*
_acquire_conn(struct spq_root *spq)
{
	/* TODO: */
#if 0
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
#endif
	return NULL;
}

/* возвращение захваченного ресурса в пул */
static void
_release_conn(struct spq_root *spq, struct spq *sc)
{
	/* TODO: */
#if 0
	/* процедура выполняется параллельно */
	pthread_mutex_lock(&spq->mutex);
	sc->mark_active = false;
	spq->active--;
	pthread_mutex_unlock(&spq->mutex);
	return;
#endif
}

#if DEEPDEBUG
static inline struct spq*
__acquire_conn(struct spq_root *spq, const char *funcname)
{
	struct spq *c;
	if ((c = _acquire_conn(spq))) {
		xsyslog(LOG_DEBUG, "acquire %p in %s", (void*)c, funcname);
		c->acquired_by = funcname;
		c->acquires++;
	}
	return c;
}

static inline void
__release_conn(struct spq_root *spq, struct spq *sc, const char *funcname)
{
	xsyslog(LOG_DEBUG, "release %p in %s", (void*)sc, funcname);
	sc->acquired_by = NULL;
	_release_conn(spq, sc);
	return;
}

# define acquire_conn(x) __acquire_conn(x, __func__)
# define release_conn(x, y) __release_conn(x, y, __func__)
#else
# define acquire_conn(x) _acquire_conn(x)
# define release_conn(x, y) _release_conn(x, y)
#endif

static void
_free_spq(struct spq_root *spq, struct spq *sc)
{
	/* принудительное освобождение узла */
	if (sc->conn != NULL) {
		PQfinish(sc->conn);
		sc->conn = NULL;
	}

	if (sc->next)
		sc->next->prev = sc->prev;
	if (sc->prev)
		sc->prev->next = sc->next;
	if (spq->first == sc)
		spq->first = (sc->next ? sc->next : sc->prev);

	xsyslog(LOG_INFO, "spq con[%p] close", (void*)sc);
	free(sc);
}

static void*
_thread_mgm(struct spq_root *spq)
{
	ev_run(spq->loop, 0);
	return NULL;
}

static void
spq_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	ConnStatusType pgstat;
	struct spq_root *spq = ev_userdata(loop);
	struct spq *sc;
	struct spq *sp;
	size_t sc_c = 0u; /* счётчик подключений */
	/* обход списка подключений */
	for (sp = NULL, sc = spq->first, sc_c = 0u;
			sc_c < spq->options.pool;
			sc_c++, sp = sc, sc = sc->next) {
		/* аллокация новой структуры */
		if (sc == NULL) {
			sc = calloc(1, sizeof(struct spq));
			if (sc) {
				xsyslog(LOG_INFO, "spq con[%p] new connection", (void*)sc);
				sc->errhash = (uint32_t)-1;
				sc->prev = sp;
				if (sp) {
					sp->next = sc;
				} else {
					spq->first = sc;
				}
			} else {
				xsyslog(LOG_INFO, "spq new connection error: %s",
						strerror(errno));
			}
		}
		if (sc->mark_active)
			continue;

		/* проверка на актуальность подключения */
		if (sc->pgstring_hash != spq->pgstring_hash) {
			PQfinish(sc->conn);
			sc->conn = NULL;
		}

		/* переподключения */
		if (sc->conn != NULL) {
			pgstat = PQstatus(sc->conn);
			if (pgstat != CONNECTION_OK) {
				uint32_t _erh;
				char *_erm;
				/* получение ошибки, печать */
				_erm = PQerrorMessage(sc->conn);
				_erh = hash_pjw(_erm, strlen(_erm));
				if (_erh != sc->errhash) {
					sc->errhash = _erh;
					xsyslog(LOG_INFO, "spq con[%p] error: %s", (void*)sc, _erm);
				}
				PQfinish(sc->conn);
				sc->conn = NULL;
			} else {
				continue;
			}
		}

		/* подключение */
		sc->pgstring_hash = hash_pjw(PSLEN(spq->options.pgstring));
		sc->conn = PQconnectdb(spq->options.pgstring);
		PQsetErrorVerbosity(sc->conn, PQERRORS_TERSE);
	}

	/* отсекание лишних подключений */
	for (; sc; sc = sp) {
		sp = sc->next;

		/* не трогаем активные подключения */
		if (sc->mark_active)
			continue;

		_free_spq(spq, sc);
	}
	return;
}

static void
spq_ping_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	/* TODO: пинг подключений */
}

static void
spq_exit_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	struct spq_root *spq = ev_userdata(loop);
	xsyslog(LOG_INFO, "spq manager: break loop at signal");
	ev_break(loop, EVBREAK_ALL);
	/* запуск процедуры таймера */
	spq_timer_cb(loop, &spq->timer, 0);
}

static void
spq_update_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	struct spq_root *spq = ev_userdata(loop);
	xsyslog(LOG_INFO, "spq manager: update configuration");
	/* TODO */
}

/* должно вызываться после старта треда */
static void
_spq_clear(struct spq_root *spq)
{
	if (!spq->mgm) {
		return;
	}

	/* отчистка всякого мусора, в частности, опций */
	if (spq->options.pgstring == spq->options_in.pgstring) {
		if (spq->options.pgstring) {
			free(spq->options.pgstring);
		}
	} else {
		if (spq->options.pgstring) {
			free(spq->options.pgstring);
		}
		if (spq->options_in.pgstring) {
			free(spq->options_in.pgstring);
		}
	}

	memset(&spq->options, 0u, sizeof(struct spq_options));
	memset(&spq->options_in, 0u, sizeof(struct spq_options));
}

void
spq_open(unsigned pool, char *pgstring)
{
	if (_spq.inited)
		return;

	if (!pgstring || !*pgstring) {
		xsyslog(LOG_WARNING,
				"spq manger: error: no connection (pgstring=%s, pool=%u)",
				pgstring, pool);
		return;
	}

	/* копирование настроек */
	_spq.loop = ev_loop_new(EVFLAG_AUTO);
	if (!_spq.loop) {
		xsyslog(LOG_ERR,
				"spq manager: loop error: ev_loop_new() failed, errno: %s",
				strerror(errno));
		return;
	}

	_spq.options.pool = pool;
	if ((_spq.options.pgstring = strdup(pgstring)) == NULL) {
		xsyslog(LOG_ERR,
				"spq manager: memory error: strdup(pgstring) failed: errno %s",
				strerror(errno));
		_spq.pgstring_hash = hash_pjw(pgstring, strlen(pgstring));
		return;
	}

	memcpy(&_spq.options_in, &_spq.options, sizeof(struct spq_options));

	_spq.inited = true;
	/* создание нового потока */
	if (pthread_create(&_spq.mgm, NULL,
				(void*(*)(void*))_thread_mgm, (void*)&_spq)) {
		xsyslog(LOG_INFO, "manager thread started: %p", (void*)_spq.mgm);

		/* инициализация сигналов */
		ev_async_init(&_spq.exit, spq_exit_cb);
		ev_async_init(&_spq.update, spq_update_cb);
		ev_timer_init(&_spq.timer, spq_timer_cb, .5, .10);
		ev_timer_init(&_spq.ping, spq_ping_cb, .35, 30);

		ev_set_userdata(_spq.loop, &_spq);

		ev_async_start(_spq.loop, &_spq.exit);
		ev_async_start(_spq.loop, &_spq.update);
		ev_timer_start(_spq.loop, &_spq.timer);
		ev_timer_start(_spq.loop, &_spq.ping);
		/* запустились */
	} else {
		_spq.inited = false;
		_spq_clear(&_spq);
		xsyslog(LOG_ERR,
				"spq mananger: thread error: not started: %s",
				strerror(errno));
	}
}

void
spq_resize(unsigned pool)
{
	if (pool == _spq.options_in.pool)
		return;
	xsyslog(LOG_INFO, "spq: resize pool: %u -> %u", _spq.options_in.pool, pool);
	_spq.options_in.pool = pool;
	ev_async_send(_spq.loop, &_spq.update);
}

void
spq_set_log_failed_queries(bool enable)
{
	if (enable == _spq.options_in.log_failed_queries)
		return;
	xsyslog(LOG_INFO,
			"spq: set log_failed_queries to %s", enable ? "true" : "false");
	_spq.options_in.log_failed_queries = enable;
	ev_async_send(_spq.loop, &_spq.update);
}

void
spq_close()
{
	void *n = NULL;
	if (!_spq.inited)
		return;

	ev_async_send(_spq.loop, &_spq.exit);
	xsyslog(LOG_INFO, "spq manager: wait exit...");
	pthread_join(_spq.mgm, &n);

	_spq.inited = false;

	/* деинициализация цикла */
	ev_async_stop(_spq.loop, &_spq.exit);
	ev_async_stop(_spq.loop, &_spq.update);
	ev_timer_stop(_spq.loop, &_spq.timer);
}

void
_spq_log_expand(const char *query,
		size_t vals,
		const char *const val[], int len[])
{
	size_t s = strlen(query);
	size_t offset = 0u;
	uint32_t hash = hash_pjw(query, s);
	char values[4096] = {0};

	if (s <= 1) {
		xsyslog(LOG_DEBUG, "spq error: zero-length query");
		return;
	}

	if (vals) {
		for (s = 0u; s < vals; s++) {
			if (val[s]) {
				offset += snprintf(values + offset, sizeof(values) - offset,
						" '%s',", val[s]);
			} else {
				offset += snprintf(values + offset, sizeof(values) - offset,
						" NULL,");
			}
		}
		values[offset - 1] = '\0';


		if (query[s - 1] != ';') {
			xsyslog(LOG_DEBUG,
					"QUERY >>>\nPREPARE q_%"PRIx32" AS %s;\nEXECUTE q_%"PRIx32"(%s);",
					hash, query, hash, values);
		} else {
			xsyslog(LOG_DEBUG,
					"QUERY >>>\nPREPARE q_%"PRIx32" AS %s\nEXECUTE q_%"PRIx32"(%s);",
					hash, query, hash, values);
		}
	} else {
		/* влом генерировать строки и прочее, скопировать код проще */
		if (query[s - 1] != ';') {
			xsyslog(LOG_DEBUG,"QUERY >>>\n%s", query);
		} else {
			xsyslog(LOG_DEBUG, "QUERY >>>\n%s", query);
		}
	}

}
