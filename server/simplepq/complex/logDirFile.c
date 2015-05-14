/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/logDirFile.c
 */

static inline PGresult*
_spq_f_logDirFile_exec(PGconn *pgc, guid_t *rootdir, uint64_t checkpoint)
{
	PGresult *res;
	ExecStatusType pqs;
	char *tb =
	"SELECT * FROM log_list($1::UUID, $2::bigint);";
	const int fmt[2] = {0, 0};

	char _rootdir[GUID_MAX + 1];
	char _checkpoint[32] = {0};

	char *val[2];
	int len[2];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = snprintf(_checkpoint, sizeof(_checkpoint), "%"PRIu64, checkpoint);

	val[0] = len[0] ? _rootdir : NULL;
	val[1] = _checkpoint;

	res = PQexecParams(pgc, tb, 3, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_TUPLES_OK) {
		char errstr[1024];
		snprintf(errstr, sizeof(errstr), "spq: logDirFile exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return NULL;
	}

	return res;
}


bool
spq_f_logDirFile(char *username, guid_t *rootdir, uint64_t checkpoint, uint64_t deviceid,
		struct logDirFile *state)
{
	struct spq *c;
	if (!state->p && (state->p = acquire_conn(&_spq)) == NULL) {
		return false;
	}
	c = (struct spq*)state->p;

	if (!spq_begin_life(c->conn, username, deviceid)) {
		release_conn(&_spq, c);
		return false;
	}

	if (!state->res && (state->res = _spq_f_logDirFile_exec(c->conn,
					rootdir, checkpoint)) == NULL) {
		release_conn(&_spq, c);
		memset(state, 0u, sizeof(struct logDirFile));
		return false;
	}

	state->max = (unsigned)PQntuples((PGresult*)state->res);
	state->row = 0u;

	return true;
}

bool
spq_f_logDirFile_it(struct logDirFile *state)
{
	size_t len;
	char *val;
	if (state->row >= state->max)
		return false;

	/* columns:
	 * 0. type ("f" or "d" or "r")
	 * 1. checkpoint (f and d)
	 * 2. rootdir_guid (f and d)
	 * 3. file_guid (f only)
	 * 4. revision_guid (f only)
	 * 5. directory_guid (f and d)
	 * 6. parent_revision_guid (f only)
	 * 7. enc_filename (f and d) (for d raw path)
	 * 8. public_key (f only)
	 * 9. count chunks (f only)
	 */

	state->type = PQgetvalue(state->res, state->row, 0)[0];

	/* checkpoint */
	if((len = PQgetlength(state->res, state->row, 1)) != 0u) {
		val = PQgetvalue(state->res, state->row, 1);
		state->checkpoint = strtoul(val, NULL, 10);
	} else {
		state->checkpoint = 0u;
	}

	/* rootdir_guid */
	if ((len = PQgetlength(state->res, state->row, 2)) != 0u) {
		val = PQgetvalue(state->res, state->row, 2);
		string2guid(val, len, &state->rootdir);
	} else {
		string2guid(NULL, 0, &state->rootdir);
	}

	/* path */
	if ((len = PQgetlength(state->res, state->row, 7)) != 0u) {
		val = PQgetvalue(state->res, state->row, 7);
		memcpy(state->path, val, MIN(len, PATH_MAX));
	} else {
		*state->path = '\0';
	}

	/* у всех видов сообщений есть directory_guid, кроме rootdir */
	if (state->type != 'r') {
		/* directory_guid */
		if ((len = PQgetlength(state->res, state->row, 5)) != 0u) {
			val = PQgetvalue(state->res, state->row, 5);
			string2guid(val, len, &state->directory);
		} else {
			string2guid(NULL, 0, &state->directory);
		}
	}

	if (state->type == 'f') {
		/* нужно впихнуть данные по файлу */

		/* file_guid */
		if ((len = PQgetlength(state->res, state->row, 3)) != 0u) {
			val = PQgetvalue(state->res, state->row, 3);
			string2guid(val, len, &state->file);
		} else {
			string2guid(NULL, 0u, &state->file);
		}

		/* revision guid */
		if ((len = PQgetlength(state->res, state->row, 4)) != 0u) {
			val = PQgetvalue(state->res, state->row, 4);
			string2guid(val, len, &state->revision);
		} else {
			string2guid(NULL, 0u, &state->revision);
		}

		/* parent revision guid */
		if ((len = PQgetlength(state->res, state->row, 6)) != 0u) {
			val = PQgetvalue(state->res, state->row, 6);
			string2guid(val, len, &state->parent);
		} else {
			string2guid(NULL, 0u, &state->parent);
		}

		/* public key */
		if ((len = PQgetlength(state->res, state->row, 8)) != 0u) {
			val = PQgetvalue(state->res, state->row, 8);
			state->key_len = hex2bin(val, len, state->key, PUBKEY_MAX);
		} else {
			memset(state->key, 0u, PUBKEY_MAX);
		}

		/* chunks */
		if (PQgetlength(state->res, state->row, 9)) {
			val = PQgetvalue(state->res, state->row, 9);
			state->chunks = (size_t)strtoul(val, NULL, 10);
		} else {
			state->chunks = 0u;
		}
	}

	state->row++;
	return true;
}

void
spq_f_logDirFile_free(struct logDirFile *state)
{
	if (state->p)
		release_conn(&_spq, state->p);
	if (state->res)
		PQclear(state->res);
	memset(state, 0u, sizeof(struct logDirFile));
}

