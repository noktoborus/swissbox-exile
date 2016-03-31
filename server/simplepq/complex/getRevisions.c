/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/getRevisions.c
 */

static inline PGresult*
_spq_getRevisions_exec(PGconn *pgc,
		guid_t *rootdir, guid_t *file, unsigned depth)
{
	/* TODO: код устарел, реализовать полностью spq_hint */
	PGresult *res;
	ExecStatusType pqs;
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

	char *m = NULL;

	len[0] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	len[1] = guid2string(file, _file_guid, sizeof(_file_guid));
	len[2] = snprintf(ndepth, sizeof(ndepth), "%"PRIu32, depth);

	val[0] = _rootdir_guid;
	val[1] = _file_guid;
	val[2] = ndepth;

	res = PQexecParams(pgc, tbq, 3, NULL, (const char *const*)val, len, fmt, 0);

	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_TUPLES_OK) {
		m = PQresultErrorMessage(res);
		xsyslog(LOG_INFO, "spq: getRevisions exec error: %s", m);
		/*spq_hint_feed(NULL, 0, hint);*/
		PQclear(res);
		Q_LOGX(tbq, sizeof(len) / sizeof(*len), val, len);
		return NULL;
	}
	return res;
}

bool
spq_getRevisions(struct spq_key *k,
		guid_t *rootdir, guid_t *file,
		unsigned depth, struct getRevisions *state)
{
	if (!state->res && (state->res = _spq_getRevisions_exec(k->c,
				rootdir, file, depth)) == NULL) {
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
	if (state->res)
		PQclear(state->res);
	memset(state, 0u, sizeof(struct getRevisions));
}

