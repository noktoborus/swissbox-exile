/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/getChunks.c
 */

static inline PGresult*
_spq_getChunks_exec(PGconn *pgc,
		guid_t *rootdir, guid_t *file, guid_t *revision)
{
	PGresult *res;
	ExecStatusType pqs;
	char errstr[1024];
	const char *tb = "SELECT * FROM chunk_list($1::UUID, $2::UUID, $3::UUID);";
	const int fmt[3] = {0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _revision_guid[GUID_MAX + 1];

	char *val[3];
	int len[3];

	len[0] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	len[1] = guid2string(file, _file_guid, sizeof(_file_guid));
	len[2] = guid2string(revision, _revision_guid, sizeof(_revision_guid));

	val[0] = _rootdir_guid;
	val[1] = _file_guid;
	val[2] = _revision_guid;

	res = PQexecParams(pgc, tb, 3, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: getChunks exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return NULL;
	}
	return res;
}

void
spq_getChunks_free(struct getChunks *state)
{
	if (state->res) {
		PQclear(state->res);
	}
	memset(state, 0u, sizeof(struct getChunks));
}

bool
spq_getChunks_it(struct getChunks *state)
{
	size_t len;
	char *val;

	if (state->row >= state->max)
		return false;

	/* получении записи, возврат значений */
	/* 0 = guid */
	len = strlen((val = PQgetvalue((PGresult*)state->res, state->row, 0)));
	string2guid(val, len, &state->chunk);
	/* 1 = hash */
	len = strlen((val = PQgetvalue((PGresult*)state->res, state->row, 1)));
	memcpy(state->hash, val , MIN(len, HASHHEX_MAX));

	state->row++;
	return true;
}

bool
spq_getChunks(struct spq_key *k,
		guid_t *rootdir, guid_t *file, guid_t *revision,
		struct getChunks *state)
{
	PGresult *res;

	/* если ресурса нет -- делаем запрос */
	if (!state->res && (state->res = _spq_getChunks_exec(k->c,
				rootdir, file, revision)) == NULL) {
		memset(state, 0u, sizeof(struct getChunks));
		return false;
	}
	res = (PGresult*)state->res;

	/* инициализация значений */
	state->max = (unsigned)PQntuples(res);
	state->row = 0u;

	return true;
}

