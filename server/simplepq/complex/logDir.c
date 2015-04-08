/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/logDir.c
 */

static inline PGresult*
_spq_f_logDir_exec(PGconn *pgc, char *username, uint64_t checkpoint,
		uint64_t deviceid)
{
	PGresult *res;
	ExecStatusType pqs;
	char errstr[1024];
	const char *tb = "SELECT"
		"	trunc(extract(epoch from time)),"
		"	rootdir_guid,"
		"	directory_guid,"
		"	path "
		"FROM directory_log WHERE "
		"username = $1 AND time > to_timestamp($2) AND deviceid != $3 "
		"ORDER BY time ASC;";
	const int format[3] = {0, 0, 0};

	char _unixtime[sizeof(uint64_t) * 8 + 1];
	char _deviceid[sizeof(uint64_t) * 8 + 1];

	char *val[2];
	int length[2];

	length[0] = strlen(username);
	length[1] = snprintf(_unixtime, sizeof(_unixtime), "%"PRIu64, checkpoint);
	length[2] = snprintf(_deviceid, sizeof(_deviceid), "%"PRIu64, deviceid);

	val[0] = username;
	val[1] = _unixtime;
	val[2] = _deviceid;

	res = PQexecParams(pgc, tb, 3, NULL,
			(const char *const*)val, length, format, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: logDir exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return NULL;
	}

	return res;
}

bool
spq_f_logDir(char *username, uint64_t checkpoint, uint64_t deviceid,
		struct getLogDir *state)
{
	struct spq *c;
	if (!state->p && (state->p = acquire_conn(&_spq)) == NULL) {
		return false;
	}
	c = (struct spq*)state->p;

	if (!state->res && (state->res = _spq_f_logDir_exec(c->conn,
					username, deviceid, checkpoint)) == NULL) {
		release_conn(&_spq, c);
		memset(state, 0u, sizeof(struct getLogDir));
		return false;
	}

	state->max = (unsigned)PQntuples((PGresult*)state->res);
	state->row = 0u;

	return true;
}

bool
spq_f_logDir_it(struct getLogDir *state)
{
	size_t len;
	char *val;
	if (state->row >= state->max)
		return false;

	/* checkpoint */
	if((len = PQgetlength(state->res, state->row, 0)) != 0u) {
		val = PQgetvalue(state->res, state->row, 0);
		state->checkpoint = strtoul(val, NULL, 10);
	} else {
		state->checkpoint = 0u;
	}

	/* rootdir_guid */
	if ((len = PQgetlength(state->res, state->row, 1)) != 0u) {
		val = PQgetvalue(state->res, state->row, 1);
		string2guid(val, len, &state->rootdir);
	} else {
		string2guid(NULL, 0, &state->rootdir);
	}

	/* directory_guid */
	if ((len = PQgetlength(state->res, state->row, 2)) != 0u) {
		val = PQgetvalue(state->res, state->row, 2);
		string2guid(val, len, &state->directory);
	} else {
		string2guid(NULL, 0, &state->directory);
	}

	/* path */
	if ((len = PQgetlength(state->res, state->row, 3)) != 0u) {
		val = PQgetvalue(state->res, state->row, 3);
		memcpy(state->path, val, MIN(len, PATH_MAX));
	} else {
		*state->path = '\0';
	}

	state->row++;
	return true;
}

void
spq_f_logDir_free(struct getLogDir *state)
{
	if (state->p)
		release_conn(&_spq, state->p);
	if (state->res)
		PQclear(state->res);
	memset(state, 0u, sizeof(struct getLogDir));
}


