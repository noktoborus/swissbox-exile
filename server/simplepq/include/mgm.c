/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/include/mgm.c
 */
static struct spq _root;

static void
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


static const char const *
pqstatus2string(ConnStatusType t) {
	switch (t) {
	case CONNECTION_OK:
		return "CONNECTION_OK";
	case CONNECTION_BAD:
		return "CONNECTION_BAD";
	case CONNECTION_STARTED:
		return "CONNECTION_STARTED";
	case CONNECTION_MADE:
		return "CONNECTION_MADE";
	case CONNECTION_AWAITING_RESPONSE:
		return "CONNECTION_AWAITING_RESPONSE";
	case CONNECTION_AUTH_OK:
		return "CONNECTION_AUTH_OK";
	case CONNECTION_SETENV:
		return "CONNECTION_SETENV";
	case CONNECTION_SSL_STARTUP:
		return "CONNECTION_SSL_STARTUP";
	case CONNECTION_NEEDED:
		return "CONNECTION_NEEDED";
	default:
		return "~unknown~";
	}
}

void
spq_open(char *pgstring)
{
	xsyslog(LOG_INFO, "spq: init");

	if (!pgstring) {
		xsyslog(LOG_ERR, "spq: error: pgstring not setted");
		return;
	}

	pthread_mutex_init(&_root.lock, NULL);
	_root.inited = true;
	_root.pgstring = strdup(pgstring);
}

static inline void _key_unlink(struct spq_key *key)
{
	/* вынимаем из списка */
	if (key->key) {
		key->key->keyp = key->keyp;
	}
	if (key->keyp) {
		key->keyp->key = key->key;
	}
	if (_root.key == key) {
		_root.key = key->key;
	}
	_root.count--;
}

void
spq_interrupt()
{
	struct spq_key *key;

	xsyslog(LOG_INFO, "spq: interrupt");
	pthread_mutex_lock(&_root.lock);
	/* пройтись по всем подключениям и сломать их */
	for (key = _root.key; key; key = key->key) {
		if (key->c) {
			xsyslog(LOG_INFO,
					"spq: key[%p]: interrupt (in_action: %s)",
					(void*)key, key->in_action ? "yes" : "no");
			PQfinish(key->c);
			key->c = NULL;
		}
	}
	pthread_mutex_unlock(&_root.lock);
}

void
spq_close()
{
	struct spq_key *key;
	struct spq_key *keyn;

	xsyslog(LOG_INFO, "spq: destroy");

	if (!_root.inited) {
		xsyslog(LOG_ERR, "spq: error: not inited");
		return;
	}

	pthread_mutex_lock(&_root.lock);

	if (_root.pgstring)
		free(_root.pgstring);
	/* внаглую всё отключаем */
	for (key = _root.key; key; key = keyn) {
		keyn = key->key;

		if (key->in_action) {
			/* выводим дополнительное сообщение, что бы точно не пропустить
			 * то, что программист накосячил с порядком операций
			 */
			xsyslog(LOG_WARNING,
					"spq: key[%p] destroy error: in_action=yes", (void*)key);
		}
		if (key->c) {
			PQfinish(key->c);
			key->c = NULL;
		}
		xsyslog(LOG_INFO,
				"spq: key[%p] destroy "
				"(active: %s, uses: %"PRIuPTR", state: %s)",
				(void*)key,
				key->in_action ? "yes" : "no",
				key->uses,
				pqstatus2string(PQstatus(key->c)));
		_key_unlink(key);
		free(key);
	}

	_root.inited = false;
	pthread_mutex_unlock(&_root.lock);
	pthread_mutex_destroy(&_root.lock);
}

void
spq_set_log_failed_queries(bool enable)
{
	if (!_root.inited) {
		xsyslog(LOG_ERR, "spq: error: not inited");
		return;
	}
	pthread_mutex_lock(&_root.lock);
	xsyslog(LOG_INFO,
			"spq: set log_failed_queries = %s", enable ? "yes" : "no");
	_root.log_failed_queries = enable;
	pthread_mutex_unlock(&_root.lock);
}

void
spq_set_address(char *pgstring)
{
	if (!_root.inited) {
		xsyslog(LOG_ERR, "spq: error: not inited");
		return;
	}
	pthread_mutex_lock(&_root.lock);
	xsyslog(LOG_INFO,
			"spq: set address = %s", pgstring);
	if (!_root.pgstring) {
		free(_root.pgstring);
		_root.pgstring = strdup(pgstring);
		_root.pgstring_hash = hash_pjw(pgstring, strlen(pgstring));
	}
	pthread_mutex_unlock(&_root.lock);
}

static bool inline
spq_begin_life(PGconn *pgc, const char *username, uint64_t device_id)
{
	PGresult *res;
	const char tb[] = "SELECT begin_life($1::character varying, $2::bigint);";
	const int fmt[2] = {0, 0};

	char _device_id[16];

	char *val[2];
	int len[2];

	len[0] = strlen(username);
	len[1] = snprintf(_device_id, sizeof(_device_id), "%"PRIu64, device_id);

	val[0] = (char*)username;
	val[1] = _device_id;

	res = PQexecParams(pgc, tb, 2, NULL, (const char *const*)val, len, fmt, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "exec begin_life error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return false;
	}

	PQclear(res);
	return true;
}

struct spq_key *
spq_vote(const char *username, uint64_t device_id)
{
	/* random key */
	struct spq_key *key = NULL;
	if (!_root.inited) {
		xsyslog(LOG_ERR, "spq: error: not inited");
		return NULL;
	}

	pthread_mutex_lock(&_root.lock);
	/* 1. поиск свободного подключения */
	for (key = _root.key; key; key = key->key) {
		if (!key->in_action) {
			/* метим как захваченные и выходим */
			key->in_action = true;
			_root.active++;
			xsyslog(LOG_INFO,
					"spq: key[%p] acquire "
					"(active: %"PRIuPTR", count: %"PRIuPTR", uses: %"PRIuPTR")",
					(void*)key, _root.active, _root.count, key->uses);
			break;
		}
	}
	/* держать всё время корень захваченным бессмысленно, потому отпускаем */
	pthread_mutex_unlock(&_root.lock);

	/* 2. создание нового узла, если готового нет */
	if (!key) {
		key = calloc(1, sizeof(*key));
		if (!key) {
			xsyslog(LOG_WARNING,
					"spq error: calloc(%lu) -> %s",
					(unsigned long)sizeof(*key), strerror(errno));
			return NULL;
		}
		/* вписывание в список */
		xsyslog(LOG_INFO,
				"spq: key[%p]: new (active: %"PRIuPTR", count: %"PRIuPTR")",
				(void*)key, _root.active, _root.count);
		key->in_action = true;
		_root.active++;
		pthread_mutex_lock(&_root.lock);
		if ((key->key = _root.key) != NULL) {
			_root.key->keyp = key;
		}
		_root.key = key;
		_root.count++;
		pthread_mutex_unlock(&_root.lock);
	}

	/* 3. проверка состояния */
	if (key->c) {
		ConnStatusType _pqst = CONNECTION_BAD;
		if (PQstatus(key->c) != CONNECTION_OK) {
			xsyslog(LOG_INFO,
					"spq: key[%p]: reconnect (status: %s, message: %s)",
				   (void*)key, pqstatus2string(_pqst),
				   PQerrorMessage(key->c));
			PQfinish(key->c);
			key->c = NULL;
		}
	}

	/* 4. подключение */
	if (!key->c) {
		/* для подключения нужна строка */
		char *_pg = NULL;
		pthread_mutex_lock(&_root.lock);
		_pg = strdup(_root.pgstring);
		pthread_mutex_unlock(&_root.lock);
		if (!_pg) {
			xsyslog(LOG_WARNING, "spq: key[%p]: memory error: strdup() -> %s",
					(void*)key, strerror(errno));
			goto error;
		}
		if ((key->c = PQconnectdb(_pg)) == NULL) {
			xsyslog(LOG_INFO, "spq: key[%p]: memory error: PQconnectdb() -> %s",
					(void*)key, strerror(errno));
			goto error;
		}
		xsyslog(LOG_INFO, "spq: key[%p]: connecting", (void*)key);
		key->pgstring_hash = hash_pjw(_pg, strlen(_pg));
		free(_pg);
	}

	/* 5. проверка состояния
	 * не уверен, но при синхронном (блокирующемся) подключении
	 * состояние может быть только OK или BAD
	 */
	if (PQstatus(key->c) == CONNECTION_BAD) {
		xsyslog(LOG_INFO, "spq: key[%p]: connection error: %s",
				(void*)key, PQerrorMessage(key->c));
		goto error;
	}
	/* 6. выполнение стартового запроса */
	if (username) {
		if (!spq_begin_life(key->c, username, device_id)) {
			xsyslog(LOG_WARNING, "spq: key[%p]: bootstrap error", (void*)key);
			goto error;
		}
	} else {
		 /* TODO: добавить хоть какой-то чекер, хоть PQexec(key->c, "") */
	}

	/* 7. возврат */
	key->uses++;
	return key;

	error:
	/* выход с ошибкой */
	pthread_mutex_lock(&_root.lock);
	/* сброс флага обязательно нужно выполнять в тред-безопасной зоне */
	key->in_action = false;
	_root.active--;
	pthread_mutex_unlock(&_root.lock);

	return NULL;
}

void
spq_devote(struct spq_key *key)
{
	if (!_root.inited) {
		xsyslog(LOG_ERR, "spq: error: not inited");
		return;
	}

	if (!key->in_action) {
		xsyslog(LOG_WARNING,
				"spq: key[%p] devote, but not in action",
				(void*)key);
		return;
	}
	/* TODO: нужно заканчивать жизнь временным таблицам (begin_life/end_life) */
	pthread_mutex_lock(&_root.lock);
	key->in_action = false;
	_root.active--;
	xsyslog(LOG_INFO,
			"spq: key[%p] release "
			"(active: %"PRIuPTR", count: %"PRIuPTR", uses: %"PRIuPTR")",
			(void*)key, _root.active, _root.count, key->uses);
	pthread_mutex_unlock(&_root.lock);
	/* освобождать структуру не нужно, может ещё пригодится */
}

