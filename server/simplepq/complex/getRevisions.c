/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/getRevisions.c
 */

static inline PGresult*
_spq_f_getRevisions_exec(PGconn *pgc,
		char *username, guid_t *rootdir, guid_t *file, unsigned depth)
{
	PGresult *res;
	ExecStatusType pqs;
	char errstr[1024];
	/* TODO: запрос делает какую-то ерунду
	 * нужно строить список по parent_revision_guid
	 */
	const char *tbq = "SELECT revision_guid, parent_revision_guid "
		"FROM file_keys WHERE "
		"username = $1 AND "
		"rootdir_guid = $2 AND "
		"file_guid = $3 "
		"GROUP BY time,revision_guid,parent_revision_guid "
		"ORDER BY time DESC "
		"LIMIT $4;";
	const int format[4] = {0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];

	char *val[4];
	int length[4];

	char ndepth[16];
	snprintf(ndepth, sizeof(ndepth), "%"PRIu32, depth);

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = strlen(ndepth);

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = ndepth;

	res = PQexecParams(pgc, tbq, 4, NULL,
			(const char *const*)val, length, format, 0);

	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: getRevisions exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return NULL;
	}
	return res;
}

bool
spq_f_getRevisions(char *username, guid_t *rootdir, guid_t *file,
		unsigned depth, struct getRevisions *state)
{
	struct spq *c;

	if (!state->p && (state->p = acquire_conn(&_spq)) == NULL) {
		return false;
	}
	c = (struct spq*)state->p;

	if (!state->res && (state->res = _spq_f_getRevisions_exec(c->conn,
					username, rootdir, file, depth)) == NULL) {
		release_conn(&_spq, c);
		memset(state, 0u, sizeof(struct getRevisions));
		return false;
	}

	state->max = (unsigned)PQntuples((PGresult*)state->res);
	state->row = 0u;

	return true;
}

bool
spq_f_getRevisions_it(struct getRevisions *state)
{
	size_t len;
	char *val;
	if (state->row >= state->max)
		return false;

	/* revision_guid */
	len = strlen((val = PQgetvalue((PGresult*)state->res, state->row, 0)));
	string2guid(val, len, &state->revision);

	/* parent_revision_guid */
	if ((len = PQgetlength((PGresult*)state->res, state->row, 1)) != 0u) {
		string2guid(PQgetvalue((PGresult*)state->res, state->row, 1), len,
				&state->parent);
	} else if (state->parent.not_null) {
		string2guid(NULL, 0, &state->parent);
	}

	state->row++;
	return true;
}

void
spq_f_getRevisions_free(struct getRevisions *state)
{
	if (state->p)
		release_conn(&_spq, state->p);
	if (state->res)
		PQclear(state->res);
	memset(state, 0u, sizeof(struct getRevisions));
}

