/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/logDir.c
 */

static inline bool
_spq_f_logDir_exec(PGconn *pgc, char *username, uint64_t checkpoint)
{
	PGresult *res;
	ExecStatusType pgs;
	char errstr[1024];
	const char *tb = "SELECT time, rootdir_guid, directory_guid, path "
		"FROM directory_log WHERE "
		"username = $1 AND time > $2;";
	const int format[2] = {0, 0};

	char _unixtime[sizeof(uint64_t) * 8 + 1];

	char *val[2];
	int length[2];

	length[0] = strlen(username);
	length[1] = snprintf(_unixtime, sizeof(_unixtime), "%"PRIu64, checkpoint);

	val[0] = username;
	val[1] = _unixtime;

	res = PQexecParams(pgc, tb, 2, NULL,
			(const char *const*)val, length, format, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_COMMAND_OK && pqs != PGRES_TUPLES_OK) {
		snprintf(errstr, sizeof(errstr), "spq: logDir exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return NULL;
	}

	return false;
}

bool
spq_f_logDir(char *username, uint64_t checkpoint)
{
	return false;
}

bool
spq_f_logDir_it(struct getLogDir *state)
{
	return false;
}

void
spq_f_logDir_free(struct getLogDir *state)
{
}


