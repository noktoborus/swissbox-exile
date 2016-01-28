/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/complex/store.c
 */

bool
_spq_store_save(PGconn *pgc,
		bool share, uint32_t offset, uint32_t length,
		uint8_t *data, uint32_t data_len,
		struct spq_hint *hint)
{
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] = "SELECT * FROM store_save("
		"$1::bytea, $2::boolean, $3::integer, $4::integer"
		")";

	char *val[4];
	int len[4];

	char _offset[12];
	char _length[12];

	int _l = 0;
	char *_m = NULL;

	len[0] = data_len;
	len[1] = share ? 4 : 5;
	len[2] = snprintf(_offset, sizeof(_offset), "%"PRIu32, length);
	len[3] = snprintf(_length, sizeof(_length), "%"PRIu32, length);

	val[0] = (char*)data;
	val[1] = share ? "true" : "false";
	val[2] = _offset;
	val[3] = _length;

	res = PQexecParams(pgc, tb, 4, NULL, (const char *const*)val, len, NULL, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK && pqs != PGRES_EMPTY_QUERY) {
		_m = PQresultErrorMessage(res);
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "exec store_save error: %s", _m);
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return false;
	} else if ((_l = PQgetlength(res, 0, 0)) > 0u) {
		_m = PQgetvalue(res, 0, 0);
		spq_feed_hint(_m, _l, hint);
		xsyslog(LOG_INFO, "exec store_save warning: %s", _m);
	}

	return true;
}

bool spq_store_save(char *username, uint64_t device_id,
		bool share, uint32_t offset, uint32_t length,
		uint8_t *data, uint32_t data_len,
		struct spq_hint *hint)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = _spq_store_save(c->conn,
				share, offset, length, data, data_len, hint);
		release_conn(&_spq, c);
	}
	return r;
}

void *
_spq_store_load(PGconn *pgc,
		bool share, uint32_t offset, uint32_t length,
		struct spq_StoreData *sd,
		struct spq_hint *hint)
{
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] = "SELECT * FROM store_load("
		"$1::boolean, $2::integer, $3::integer"
		")";

	char *val[3];
	int len[3];

	char _offset[12];
	char _length[12];

	int _l = 0;
	char *_m = NULL;

	len[1] = share ? 4 : 5;
	len[2] = snprintf(_offset, sizeof(_offset), "%"PRIu32, length);
	len[3] = snprintf(_length, sizeof(_length), "%"PRIu32, length);

	val[1] = share ? "true" : "false";
	val[2] = _offset;
	val[3] = _length;

	res = PQexecParams(pgc, tb, 3, NULL, (const char *const*)val, len, NULL, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK && pqs != PGRES_EMPTY_QUERY) {
		_m = PQresultErrorMessage(res);
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "exec store_load error: %s", _m);
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return NULL;
	} else if ((_l = PQgetlength(res, 0, 0)) > 0u) {
		_m = PQgetvalue(res, 0, 0);
		spq_feed_hint(_m, _l, hint);
		xsyslog(LOG_INFO, "exec store_load warning: %s", _m);
	}
	/* получение значений */

	sd->store_len = PQgetlength(res, 0, 1);
	sd->store = (uint8_t*)PQgetvalue(res, 0, 1);
	if (PQgetlength(res, 0, 2)) {
		sd->length = (uint32_t)strtoul(PQgetvalue(res, 0, 2), NULL, 10);
	}

	return res;
}

bool
spq_store_load(char *username, uint64_t device_id,
		bool share, uint32_t offset, uint32_t length,
		struct spq_StoreData *sd,
		struct spq_hint *hint)
{
	struct spq *c;

	if (!sd->p && (sd->p = acquire_conn(&_spq)) == NULL) {
		return false;
	}
	c = (struct spq*)sd->p;

	/* если ресурса нет -- делаем запрос */
	if (!sd->res && (!spq_begin_life(c->conn, username, device_id) ||
			(sd->res = _spq_store_load(c->conn,
				share, offset, length, sd, hint)) == NULL)) {
		release_conn(&_spq, c);
		memset(sd, 0u, sizeof(*sd));
		return false;
	}

	return true;
}

void spq_store_load_free(struct spq_StoreData *sd)
{
	if (sd->p) {
		release_conn(&_spq, sd->p);
	}
	if (sd->res) {
		PQclear(sd->res);
	}
	memset(sd, 0u, sizeof(*sd));
}

