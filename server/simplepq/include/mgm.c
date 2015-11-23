/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/include/mgm.c
 */

struct spq {
	PGconn *conn;

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

#if DEEPDEBUG
static void
spq_ac() {
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

}

#endif

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
		/* *** */
		/* выполнение переподключений и прочего */
		for (sc = spq->first; sc; sc = (sc ? sc->next : NULL)) {
			/* счётчик подключений в пуле, для учёта размера пула */
			spq_c++;
			/* если подключение "захвачено", то пропускаем его */
			if (sc->mark_active)
				continue;
			pgstatus = PQstatus(sc->conn);
			/* переподключение статусу подключения
			 */
			if (pgstatus != CONNECTION_OK && spq_c <= spq->pool) {
				if (sc->conn != NULL) {
					uint32_t _erh;
					char *_erm;
					/* получение ошибки, печать */
					_erm = PQerrorMessage(sc->conn);
					_erh = hash_pjw(_erm, strlen(_erm));
					if (_erh != sc->errhash) {
						sc->errhash = _erh;
						xsyslog(LOG_INFO, "con[%p] error: %s", (void*)sc, _erm);
					}
					PQfinish(sc->conn);
				}
				sc->conn = PQconnectdb(spq->pgstring);
				PQsetErrorVerbosity(sc->conn, PQERRORS_TERSE);
			} else if (sc->conn && pgstatus == CONNECTION_OK && sc->errhash) {
				/* индикация о случившимся подключении */
				sc->errhash = 0u;
				xsyslog(LOG_INFO, "con[%p] connected", (void*)sc);
			} else if (spq_c > spq->pool) {
				/* удаление лишних структур */
				struct spq *_sc = sc;
				PQfinish(sc->conn);
				/* вычленение из списка */
				if (spq->first == _sc)
					spq->first = sc->next;
				if (_sc->prev)
					_sc->prev->next = _sc->next;
				if (_sc->next)
					_sc->next->prev = _sc->prev;
				/* обновление ссылки */
				if (!(sc = sc->prev))
					sc = spq->first;
				xsyslog(LOG_INFO, "con[%p] destroy", (void*)_sc);
				free(_sc);
			} else if (tvc.tv_sec - sc->lc.tv_sec > 30) {
				/*
				 * регулярная провека соедненения с бд
				 */
				PQclear(PQexec(sc->conn, "SELECT 1;"));
				memcpy(&sc->lc.tv_sec, &tvc.tv_sec, sizeof(struct timeval));
			} else {
				/* если никаких операций над подключением не выполнялись,
				 * то можно пометить его как возможным для захвата
				 */
				spq->acquire.sc = sc;
			}
		}
		/* выход из бесконечного цикла если нет ни одного подключения */
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
	pthread_mutex_lock(&_spq.mutex);
	_spq.pool = pool;
	pthread_mutex_unlock(&_spq.mutex);
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


