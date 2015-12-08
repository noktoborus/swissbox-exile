/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/getRevisions.c
 */

static inline PGresult*
_spq_getRevisions_exec(PGconn *pgc,
		guid_t *rootdir, guid_t *file, unsigned depth)
{
	PGresult *res;
	ExecStatusType pqs;
	char errstr[1024];
	/* TODO: запрос делает какую-то ерунду
	 * нужно строить список по parent_revision_guid
	 */
	const char *tbq = "SELECT * FROM revision_list"
		"("
		"	$1::UUID,"
		"	$2::UUID,"
		"	$3::integer"
		")";
	const int fmt[3] = {0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];

	char *val[3];
	int len[3];

	char ndepth[16];

	len[0] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	len[1] = guid2string(file, _file_guid, sizeof(_file_guid));
	len[2] = snprintf(ndepth, sizeof(ndepth), "%"PRIu32, depth);

	val[0] = _rootdir_guid;
	val[1] = _file_guid;
	val[2] = ndepth;

	res = PQexecParams(pgc, tbq, 3, NULL, (const char *const*)val, len, fmt, 0);

	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: getRevisions exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		Q_LOGX(tbq, sizeof(len) / sizeof(*len), val, len);
		return NULL;
	}
	return res;
}

bool
spq_getRevisions(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		unsigned depth, struct getRevisions *state)
{
	struct spq *c;

	if (!state->p && (state->p = acquire_conn(&_spq)) == NULL) {
		return false;
	}
	c = (struct spq*)state->p;

	if (!state->res && (!spq_begin_life(c->conn, username, device_id) ||
			(state->res = _spq_getRevisions_exec(c->conn,
				rootdir, file, depth)) == NULL)) {
		release_conn(&_spq, c);
		memset(state, 0u, sizeof(struct getRevisions));
		return false;
	}

	state->max = (unsigned)PQntuples((PGresult*)state->res);
	state->row = 0u;

	return true;
}

bool
spq_getRevisions_it(struct getRevisions *state)
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
spq_getRevisions_free(struct getRevisions *state)
{
	if (state->p)
		release_conn(&_spq, state->p);
	if (state->res)
		PQclear(state->res);
	memset(state, 0u, sizeof(struct getRevisions));
}

