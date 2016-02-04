/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/include/mgm.c
 */

struct spq {
	/* сигнал для освобождения структуры */
	struct ev_async release;

	PGconn *conn;

	/* хеш строки подключения
	 * нужен при переподключении к другому серверу
	 */
	uint32_t pgstring_hash;

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

	/* срабатывает при выходе из ev_loop */
	struct ev_cleanup sig_cleanup;
	/* захват подключения */
	struct ev_async sig_acquire;
	/* сообщение о необходимости сброса всех подключений */
	struct ev_async sig_int;
	/* сообщение о необходимости выхода */
	struct ev_async exit;
	/* обновление конфигурации */
	struct ev_async update;
	/* уборка */
	struct ev_timer timer;
	/* пинг подключений */
	struct ev_timer ping;

	pthread_t mgm;
	pthread_mutex_t mgm_lock;

	bool inited;

	/* блокировка опций для пущей безопасности */
	pthread_mutex_t options_lock;
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
		pthread_mutex_t lock;
		pthread_cond_t cond;
		/* ожидает ли кто-нибудь подключения
		 * будем считать что wait атомарный
		 */
		bool wait;
		size_t wait_count;
	} acquire;

	unsigned active;

	struct spq *first;
} _spq;

#if DEEPDEBUG
static void
spq_ac() {
	unsigned c = 1u;
	struct spq *sc;
	xsyslog(LOG_USER,
			"stats: (pool=%u, active=%u, wait=%s, wait_count=%"PRIuPTR")\n",
			_spq.options.pool, _spq.active,
			_spq.acquire.wait ? "yes" : "no", _spq.acquire.wait_count);

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
}

#endif

/* поиск и захват ближайшего доступного ресурса в пуле */
static struct spq*
_acquire_conn(struct spq_root *spq)
{
	struct spq *sc = NULL;
	/* отправка сообщения о готовности захватить ресурс */
	ev_async_send(spq->loop, &spq->sig_acquire);
	/* ожидание ответа */
	pthread_mutex_lock(&spq->acquire.lock);
	/* инкриментация счётчика ожидания */
	if (++spq->acquire.wait_count)
		spq->acquire.wait = true;

	/*
	 * захват подключения происходит в
	 * spq_release_cb, spq_acquire_cb, spq_timer_cb
	 */
	/* FIXME: use pthread_cond_timedwait() */
	if (!pthread_cond_wait(&spq->acquire.cond, &spq->acquire.lock)) {
		/* сигнал пришёл, загребаем указатель */
		if ((sc = spq->acquire.sc) != NULL) {
			sc->mark_active = true;
			spq->acquire.sc = NULL;
		}
	}

	if (!--spq->acquire.wait_count)
		spq->acquire.wait = false;

	pthread_mutex_unlock(&spq->acquire.lock);
	return sc;
}

/* возвращение захваченного ресурса в пул */
static void
_release_conn(struct spq_root *spq, struct spq *sc)
{
	/* всё что нужно сделать здесь -- свиснуть в событие */
	ev_async_send(spq->loop, &sc->release);
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
	} else {
		xsyslog(LOG_DEBUG, "acquire fail in %s", funcname);
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

	ev_async_stop(spq->loop, &sc->release);

	xsyslog(LOG_INFO,
			"spq con[%p] close, active = %s",
			(void*)sc, (sc->mark_active ? "yes" : "no"));
	free(sc);
}

static void*
_thread_mgm(struct spq_root *spq)
{
#if __USE_GNU
	pthread_setname_np(pthread_self(), "SimplePQ");
#endif
	/* синхронизация запуска */
	pthread_mutex_lock(&spq->mgm_lock);
	pthread_mutex_unlock(&spq->mgm_lock);
	pthread_mutex_destroy(&spq->mgm_lock);

	ev_run(spq->loop, 0);
	return NULL;
}

static void
spq_acquire_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	struct spq_root *spq = ev_userdata(loop);
	struct spq *sc = NULL;

	pthread_mutex_lock(&spq->acquire.lock);
	if (!spq->acquire.sc) {
		/* поиск свободного подключения */
		for (sc = spq->first; sc; sc = sc->next) {
			if (!sc->mark_active && sc->conn) {
				spq->active++;
				spq->acquire.sc = sc;
				break;
			}
		}
	}
	/* установка флага */
	if (!spq->acquire.sc) {
		spq->acquire.wait = true;
	} else {
		/*
		 * сигнал отправляется только в случае успешного захвата
		 */
		pthread_cond_signal(&spq->acquire.cond);
	}

	pthread_mutex_unlock(&spq->acquire.lock);
}

static void
spq_release_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	struct spq_root *spq = ev_userdata(loop);
	struct spq *sc = (void*)w;

	/* проверка состояния и захват */
	if (PQstatus(sc->conn) != CONNECTION_OK) {
		PQfinish(sc->conn);
		sc->conn = NULL;
	} if (spq->acquire.wait) {
		/* захват подключения */
		pthread_mutex_lock(&spq->acquire.lock);
		spq->acquire.sc = sc;

		pthread_cond_signal(&spq->acquire.cond);
		if (!sc->mark_active) {
			sc->mark_active = true;
			xsyslog(LOG_WARNING,
					"spq con[%p] error: unexpected free connection", (void*)sc);
			spq->active++;
		}

		pthread_mutex_unlock(&spq->acquire.lock);
	} else {
		if (sc->mark_active) {
			sc->mark_active = false;
			spq->active--;
		} else {
			xsyslog(LOG_WARNING,
					"spq con[%p] error: unexpected release message", (void*)sc);
		}
	}
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

				ev_async_init(&sc->release, spq_release_cb);
				ev_async_start(spq->loop, &sc->release);
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

		/* новое подключение */
		sc->pgstring_hash = hash_pjw(PSLEN(spq->options.pgstring));
		if (!(sc->conn = PQconnectdb(spq->options.pgstring))) {
			xsyslog(LOG_INFO,
					"spq con[%p] new connection error: %s",
					(void*)sc, strerror(errno));
		} else {
			PQsetErrorVerbosity(sc->conn, PQERRORS_TERSE);
			/* проверяем, есть ли кто у нас на ожидании и выполняем захват */
			if (spq->acquire.wait) {
				pthread_mutex_lock(&spq->acquire.lock);
				spq->acquire.sc = sc;
				spq->active++;
				pthread_cond_signal(&spq->acquire.cond);
				pthread_mutex_unlock(&spq->acquire.lock);
			}
		}
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
spq_int_cb(struct ev_loop *loop, ev_cleanup *w, int revents)
{
	struct spq_root *spq = ev_userdata(loop);
	struct spq *sc = NULL;
	struct spq *sp = NULL;
	xsyslog(LOG_INFO, "spq mgm: interrupt");
	/* сопсно всё прерывание заключается в принудительном удалением ссылок */
	for (sc = spq->first; sc; sc = sp) {
		sp = sc->next;
		_free_spq(spq, sc);
	}
}

static void
spq_cleanup_cb(struct ev_loop *loop, ev_cleanup *w, int revents)
{
	struct spq_root *spq = ev_userdata(loop);
	struct spq *sc = NULL;
	struct spq *sp = NULL;
	xsyslog(LOG_INFO, "spq mgm: cleanup");

	/* отчистка списка подключений */
	for (sc = spq->first; sc; sc = sp) {
		sp = sc->next;
		_free_spq(spq, sc);
	}


	ev_cleanup_stop(loop, w);
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
	/* проверка на изменения и применение конфигурации */

	pthread_mutex_lock(&spq->options_lock);

	if (spq->options_in.pgstring &&
			spq->options_in.pgstring != spq->options.pgstring) {
		/* проверки по указателя должно хватить */
		free(spq->options.pgstring);
		/* перенос значения и чистка указателя */
		spq->options.pgstring = spq->options_in.pgstring;
		spq->options_in.pgstring = NULL;
		/* обновление хеша */
		spq->pgstring_hash = hash_pjw(PSLEN(spq->options.pgstring));
		xsyslog(LOG_INFO,
				"spq manager: new pgstring: %s", spq->options.pgstring);
	}

	if (spq->options_in.log_failed_queries != spq->options.log_failed_queries) {
		spq->options.log_failed_queries = spq->options_in.log_failed_queries;
		xsyslog(LOG_INFO,
				"spq manager: log_failed_queries set to %s",
				spq->options.log_failed_queries ? "enabled" : "disabled");
	}

	if (spq->options_in.pool != spq->options.pool) {
		spq->options.pool = spq->options_in.pool;
		xsyslog(LOG_INFO,
					"spq manager: pool size set to %u",
					spq->options.pool);
	}
	pthread_mutex_unlock(&spq->options_lock);
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

	/* синхронизация запуска */
	pthread_mutex_init(&_spq.mgm_lock, NULL);
	pthread_mutex_lock(&_spq.mgm_lock);
	/* создание нового потока */
	if (!pthread_create(&_spq.mgm, NULL,
				(void*(*)(void*))_thread_mgm, (void*)&_spq)) {
		xsyslog(LOG_INFO, "manager thread started: %p", (void*)_spq.mgm);

		/* инициализация сигналов */
		ev_async_init(&_spq.sig_int, spq_int_cb);
		ev_async_init(&_spq.sig_acquire, spq_acquire_cb);
		ev_async_init(&_spq.exit, spq_exit_cb);
		ev_async_init(&_spq.update, spq_update_cb);
		ev_timer_init(&_spq.timer, spq_timer_cb, 0., 5.);
		ev_timer_init(&_spq.ping, spq_ping_cb, 35., 30.);
		ev_cleanup_init(&_spq.sig_cleanup, spq_cleanup_cb);

		ev_set_userdata(_spq.loop, &_spq);

		ev_async_start(_spq.loop, &_spq.sig_int);
		ev_async_start(_spq.loop, &_spq.sig_acquire);
		ev_async_start(_spq.loop, &_spq.exit);
		ev_async_start(_spq.loop, &_spq.update);
		ev_timer_start(_spq.loop, &_spq.timer);
		ev_timer_start(_spq.loop, &_spq.ping);
		ev_cleanup_start(_spq.loop, &_spq.sig_cleanup);

		pthread_mutex_init(&_spq.options_lock, NULL);
		pthread_mutex_init(&_spq.acquire.lock, NULL);
		pthread_cond_init(&_spq.acquire.cond, NULL);

		pthread_mutex_unlock(&_spq.mgm_lock);
		/* запустились */
	} else {
		pthread_mutex_destroy(&_spq.mgm_lock);
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
	pthread_mutex_lock(&_spq.options_lock);

	if (pool == _spq.options_in.pool)
		return;
	xsyslog(LOG_INFO, "spq: resize pool: %u -> %u", _spq.options_in.pool, pool);
	_spq.options_in.pool = pool;
	ev_async_send(_spq.loop, &_spq.update);

	pthread_mutex_unlock(&_spq.options_lock);
}

void
spq_set_log_failed_queries(bool enable)
{
	pthread_mutex_lock(&_spq.options_lock);

	if (enable == _spq.options_in.log_failed_queries)
		return;
	xsyslog(LOG_INFO,
			"spq: set log_failed_queries to %s", enable ? "true" : "false");
	_spq.options_in.log_failed_queries = enable;
	ev_async_send(_spq.loop, &_spq.update);

	pthread_mutex_unlock(&_spq.options_lock);
}

void
spq_set_address(char *pgstring)
{
	pthread_mutex_lock(&_spq.options_lock);

	if (_spq.options_in.pgstring) {
		free(_spq.options_in.pgstring);
	}
	/* копирование, потому что хрен знает что нам передали */
	_spq.options_in.pgstring = strdup(pgstring);

	pthread_mutex_unlock(&_spq.options_lock);
}

void
spq_interrupt()
{
	if (!_spq.inited)
		return;
	ev_async_send(_spq.loop, &_spq.sig_int);
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

	pthread_cond_broadcast(&_spq.acquire.cond);

	_spq.inited = false;

	/* деинициализация цикла */
	ev_async_stop(_spq.loop, &_spq.sig_int);
	ev_async_stop(_spq.loop, &_spq.sig_acquire);
	ev_async_stop(_spq.loop, &_spq.exit);
	ev_async_stop(_spq.loop, &_spq.update);
	ev_timer_stop(_spq.loop, &_spq.timer);

	pthread_mutex_destroy(&_spq.options_lock);
	pthread_mutex_destroy(&_spq.acquire.lock);
	pthread_cond_destroy(&_spq.acquire.cond);

	_spq_clear(&_spq);

	ev_loop_destroy(_spq.loop);
	memset(&_spq, 0, sizeof(_spq));
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

