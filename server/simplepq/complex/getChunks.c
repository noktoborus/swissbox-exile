/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/getChunks.c
 */

static inline PGresult*
_spq_f_getChunks_exec(PGconn *pgc,
		char *username, guid_t *rootdir, guid_t *file, guid_t *revision)
{
	PGresult *res;
	ExecStatusType pqs;
	char errstr[1024];
	const char *tbq = "SELECT chunk_hash, chunk_guid FROM file_records WHERE "
		"username = $1 AND "
		"rootdir_guid = $2 AND "
		"file_guid = $3 AND "
		"revision_guid = $4;";
	const int format[4] = {0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _revision_guid[GUID_MAX + 1];

	char *val[4];
	int length[4];

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = guid2string(revision, _revision_guid, sizeof(_revision_guid));

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = _revision_guid;

	res = PQexecParams(pgc, tbq, 4, NULL,
			(const char *const*)val, length, format, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: getChunks exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return NULL;
	}
	return res;
}

void
spq_f_getChunks_free(struct getChunks *state)
{
	if (state->p) {
		release_conn(&_spq, state->p);
	}
	if (state->res) {
		PQclear(state->res);
	}
	memset(state, 0u, sizeof(struct getChunks));
}

bool
spq_f_getChunks_it(struct getChunks *state)
{
	size_t len;
	char *val;

	if (state->row >= state->max)
		return false;

	/* получении записи, возврат значений */
	/* 0 = hash */
	len = strlen((val = PQgetvalue((PGresult*)state->res, state->row, 0)));
	memcpy(state->hash, val , MIN(len, HASHHEX_MAX));
	/* 1 = guid */
	len = strlen((val = PQgetvalue((PGresult*)state->res, state->row, 1)));
	string2guid(val, len, &state->chunk);

	state->row++;
	return true;
}

bool
spq_f_getChunks(char *username,
		guid_t *rootdir, guid_t *file, guid_t *revision,
		struct getChunks *state)
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
	if (!state->res && (state->res = _spq_f_getChunks_exec(c->conn, username,
				rootdir, file, revision)) == NULL) {
		release_conn(&_spq, c);
		memset(state, 0u, sizeof(struct getChunks));
		return false;
	}
	res = (PGresult*)state->res;

	/* инициализация значений */
	state->max = (unsigned)PQntuples(res);
	state->row = 0u;

	return true;
}

