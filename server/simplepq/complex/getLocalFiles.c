/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/getLocalFiles.c
 */

void
spq_getLocalFiles_free(struct getLocalFiles *state)
{
	if (state->p) {
		release_conn(&_spq, state->p);
	}
	if (state->res) {
		PQclear(state->res);
	}
	memset(state, 0u, sizeof(struct getLocalFiles));
}

bool
spq_getLocalFiles_it(struct getLocalFiles *state)
{
	char *val;

	if (state->row >= state->max)
		return false;

	/* 0 = file id (bigint) */
	val = PQgetvalue((PGresult*)state->res, state->row, 0);
	state->file_id = strtoul(val, NULL, 10);

	/* 1 = file address (text) */
	state->path = PQgetvalue((PGresult*)state->res, state->row, 1);

	/* 2 = file owner (varchar) */
	state->owner = PQgetvalue((PGresult*)state->res, state->row, 2);

	state->row++;
	return true;
}

static inline PGresult*
_s_exec(PGconn *pgc, struct spq_hint *hint)
{
	PGresult *res;
	ExecStatusType pqs;
	const char *tb = "SELECT "
			"file_chunk.location_group, "
			"file_chunk.address, "
			"\"user\".username "
		"FROM file_chunk, file, rootdir, \"user\" "
		"WHERE "
			"file_chunk.driver IS NULL AND "
			"file.id = file_chunk.file_id AND "
			"rootdir.id = file.rootdir_id AND "
			"\"user\".id = rootdir.user_id "
			"GROUP BY "
				"file_chunk.location_group, "
				"file_chunk.address, "
				"\"user\".username "
			"ORDER BY file_chunk.location_group;";

	res = PQexec(pgc, tb);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		char errstr[1024];
		snprintf(errstr, sizeof(errstr), "spq: getLocalFiles exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return NULL;
	}
	return res;
}

bool
spq_getLocalFiles(struct getLocalFiles *state, struct spq_hint *hint)
{
	struct spq *c;
	PGresult *res;

	/* инициализация,
	 * смысла отдавать на каждой итерации подключение pg
	 * т.к. пока не будут загребены все результаты,
	 * выполнить новый запрос не получится(?)
	 */
	if (!state->p && (state->p = acquire_conn(&_spq)) == NULL) {
		return false;
	}
	c = (struct spq*)state->p;

	/* если ресурса нет -- делаем запрос */
	if (!state->res && (state->res = _s_exec(c->conn, hint)) == NULL) {
		release_conn(&_spq, c);
		memset(state, 0u, sizeof(struct getLocalFiles));
		return false;
	}
	res = (PGresult*)state->res;

	/* инициализация значений */
	state->max = (unsigned)PQntuples(res);
	state->row = 0u;

	return true;
}

