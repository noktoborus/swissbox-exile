/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/include/base.c
 */

bool
spq_create_tables()
{
	const char *const tb = "SELECT fepserver_installed();";
	struct spq_key *k;
	PGresult *res;
	ExecStatusType pqs;
	k = spq_vote(NULL, 0u);
	if (!k) {
		xsyslog(LOG_ERR, "spq: acquire connection for check failed");
		return false;
	}

	res = PQexec(k->c, tb);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		xsyslog(LOG_ERR, "postgresql: %s", PQresultErrorMessage(res));
		xsyslog(LOG_ERR, "please inject sql/struct.sql into db");
		spq_devote(k);
		PQclear(res);
		Q_LOG(tb);
		return false;
	} else {
		char *version = PQgetvalue(res, 0, 0);
#ifdef SQLSTRUCTVER
		xsyslog(LOG_INFO, "db struct version: %s, excepted version: %s",
				version, S(SQLSTRUCTVER));
		if (strcmp(version, S(SQLSTRUCTVER))) {
			xsyslog(LOG_ERR, "expected and db version differ (%s != %s). "
					"Please, update database from sql/struct.sql file",
					S(SQLSTRUCTVER), version);
			spq_devote(k);
			PQclear(res);
			return false;
		}
#else
		xsyslog(LOG_INFO, "db struct version: %s", version);
#endif
	}
	PQclear(res);

	spq_devote(k);
	return true;
}

bool
spq_initial_user(struct spq_InitialUser *iu,
		struct spq_hint *hint)
{
	PGresult *res;
	const char tb[] = "SELECT * FROM initial_user();";
	struct spq_key *k = spq_vote(NULL, 0u);

	char *m;
	int ml;

	if (!k) {
		xsyslog(LOG_WARNING, "spq: vote initial_user error");
		return false;
	}

	res = PQexec(k->c, tb);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "exec initial_user error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		Q_LOG(tb);
		spq_devote(k);
		return false;
	}

	/* r_error */
	if ((ml = PQgetlength(res, 0, 0)) != 0) {
		m = PQgetvalue(res, 0, 0);
		spq_feed_hint(m, ml, hint);
		xsyslog(LOG_INFO, "exec initial_user warning: %s", m);
	}

	/* r_mark */
	if ((ml = PQgetlength(res, 0, 1)) != 0) {
		m = PQgetvalue(res, 0, 1);
		string2guid(m, ml, &iu->mark);
	} else {
		string2guid(NULL, 0u, &iu->mark);
	}

	PQclear(res);
	spq_devote(k);
	return true;
}

bool
spq_check_user(char *username, char *secret, uint64_t device_id,
		struct spq_UserInfo *user, struct spq_hint *hint)
{
	PGresult *res;
	struct spq_key *k = spq_vote(NULL, 0u);
	const char tb[] =
		"SELECT trunc(extract(epoch from r_registered)), * "
		"FROM check_user("
		"	$1::character varying,"
		"	$2::character varying,"
		"	$3::bigint);";
	const int fmt[3] = {0, 0};
	char *val[3];
	int len[3];

	char *rval;
	int rlen;

	char _device_id[32];

	if (!k) {
		xsyslog(LOG_WARNING, "spq: vote check_user error");
		return false;
	}

	len[0] = strlen(username);
	len[1] = strlen(secret);
	len[2] = snprintf(_device_id, sizeof(_device_id), "%"PRIu64, device_id);

	val[0] = username;
	val[1] = secret;
	val[2] = _device_id;

	res = PQexecParams(k->c, tb, 3, NULL, (const char *const*)val, len, fmt, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "exec check_user error: %s",
				PQresultErrorMessage(res));
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		PQclear(res);
		spq_devote(k);
		return false;
	} else if ((rlen = PQgetlength(res, 0, 1)) != 0) {
		/* парсинг варнинга */
		rval = PQgetvalue(res, 0, 1);
		spq_feed_hint(rval, (size_t)rlen, hint);
		xsyslog(LOG_DEBUG, "exec check_user warning: %s", rval);
	}

	/* обработка других полей */
	/* r_autorized, boolean */
	if ((rlen = PQgetlength(res, 0, 2)) != 0)
		user->authorized = (PQgetvalue(res, 0, 2)[0] == 't');

	/* r_devices, integer */
	if ((rlen = PQgetlength(res, 0, 4)) != 0) {
		rval = PQgetvalue(res, 0, 4);
		user->devices = strtoul(rval, NULL, 10);
	}

	/* r_last_device, bigint */
	if ((rlen = PQgetlength(res, 0, 5)) != 0) {
		rval = PQgetvalue(res, 0, 5);
		user->last_device = strtoull(rval, NULL, 10);
	}

	/* r_next_server, text */
	if ((rlen = PQgetlength(res, 0, 8)) != 0) {
		rval = PQgetvalue(res, 0, 8);
		strncpy(user->next_server, rval, PATH_MAX);
		user->next_server[PATH_MAX] = '\0';
	}

	/* trunc(r_registered), bigint */
	if ((rlen = PQgetlength(res, 0, 0)) != 0) {
		rval = PQgetvalue(res, 0, 0);
		user->registered = strtoull(rval, NULL, 0);
	}

	PQclear(res);
	spq_devote(k);
	return true;
}

bool
spq_add_user(char *username, char *secret, struct spq_hint *hint)
{
	PGresult *res;
	struct spq_key *k = spq_vote(NULL, 0u);
	const char tb[] =
		"INSERT INTO \"user\"(username, secret)"
		"VALUES ($1::character varying, $2::character varying)";

	const int fmt[2] = {0, 0};
	char *val[2];
	int len[2];

	if (!k) {
		xsyslog(LOG_WARNING, "spq: vote add_user error");
		return false;
	}

	len[0] = strlen(username);
	len[1] = strlen(secret);

	val[0] = username;
	val[1] = secret;

	/* TODO: убрать ересь
	 * порядок должен быть наведён в spq_devote()
	 */
	PQclear(PQexec(k->c, "DROP TABLE IF EXISTS _life_;"));
	res = PQexecParams(k->c, tb, 2, NULL, (const char *const*)val, len, fmt, 0);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "exec add_user error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		spq_devote(k);
		return false;
	}

	PQclear(res);
	spq_devote(k);
	return true;
}

