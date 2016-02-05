/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/getDevices.c
 */

static inline PGresult*
spq_getDevices_exec(PGconn *pgc,
		const char *username, uint64_t device_id,
		struct spq_hint *hint)
{
	PGresult *res;
	ExecStatusType pqs;
	const char *tb = "SELECT * FROM device_list($1::varchar, $2::bigint);";

	int _l;
	char *_v;

	char *val[2];
	int len[2];

	char _device_id[32];

	const int fmt[] = {0, 0};

	len[0] = strlen(username);
	len[1] = snprintf(_device_id, sizeof(_device_id), "%"PRIu64, device_id);

	val[0] = (char*)username;
	val[1] = _device_id;

	res = PQexecParams(pgc, tb, 2, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		_v = PQresultErrorMessage(res);
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "spq: getDevices exec error: %s", _v);
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return NULL;
	} else if (PQntuples(res) > 0 && (_l = PQgetlength(res, 0, 0)) != 0) {
		_v = PQgetvalue(res, 0, 0);
		spq_feed_hint(_v, _l, hint);
		PQclear(res);
		return NULL;
	}

	return res;
}

bool
spq_getDevices_it(struct getDevices *state)
{
	char *val;

	if (state->row >= state->max)
		return false;

	if (PQgetlength((PGresult*)state->res, state->row, 1) != 0) {
		val = PQgetvalue((PGresult*)state->res, state->row, 1);
		state->last_auth_time = val;
	}

	if (PQgetlength((PGresult*)state->res, state->row, 2) != 0) {
		val = PQgetvalue((PGresult*)state->res, state->row, 2);
		state->device_id = strtoull(val, NULL, 10);
	}

	state->row++;
	return true;
}

void
spq_getDevices_free(struct getDevices *state)
{
	if (state->p) {
		spq_devote((struct spq_key*)state->p);
	}
	if (state->res) {
		PQclear(state->res);
	}
	memset(state, 0u, sizeof(struct getDevices));
}

bool
spq_getDevices(const char *username, uint64_t device_id,
		struct getDevices *state,
		struct spq_hint *hint)
{
	struct spq_key *c;
	PGresult *res;

	if (!state->p && (state->p = spq_vote(NULL, 0u)) == NULL) {
		xsyslog(LOG_WARNING, "spq: vote getDevices error");
		return false;
	}
	c = (struct spq_key*)state->p;

	/* если ресурса нет -- делаем запрос */
	if (!state->res && (state->res = spq_getDevices_exec(c->c,
					username, device_id, hint)) == NULL) {
		spq_devote(c);
		memset(state, 0u, sizeof(*state));
		return false;
	}
	res = (PGresult*)state->res;

	/* инициализация значений */
	state->max = (unsigned)PQntuples(res);
	state->row = 0u;

	return true;
}

