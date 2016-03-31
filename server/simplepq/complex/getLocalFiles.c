/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/getLocalFiles.c
 */

void
spq_getLocalFiles_free(struct getLocalFiles *state)
{
	if (state->p) {
		spq_devote((struct spq_key*)state->p);
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
	/* TODO: wtf? */
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
		char *_m = PQresultErrorMessage(res);
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "spq: getLocalFiles exec error: %s", _m);
		PQclear(res);
		Q_LOG(tb);
		return NULL;
	}
	return res;
}

bool
spq_getLocalFiles(struct getLocalFiles *state, struct spq_hint *hint)
{
	struct spq_key *c;
	PGresult *res;

	/* TODO: хуита */
	if (!state->p && (state->p = spq_vote(NULL, 0u)) == NULL) {
		xsyslog(LOG_WARNING, "spq: vote getLocalFiles error");
		return false;
	}
	c = (struct spq_key*)state->p;

	/* если ресурса нет -- делаем запрос */
	if (!state->res && (state->res = _s_exec(c->c, hint)) == NULL) {
		spq_devote(c);
		memset(state, 0u, sizeof(struct getLocalFiles));
		return false;
	}
	res = (PGresult*)state->res;

	/* инициализация значений */
	state->max = (unsigned)PQntuples(res);
	state->row = 0u;

	return true;
}

