/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/simplepq.c
 */
#include "simplepq.h"
#include "junk/xsyslog.h"

#include <inttypes.h>
#include <stdlib.h>

#include <errno.h>
#include <string.h>

#include <time.h>
#include <pthread.h>
#include <sys/time.h>

#ifndef MIN
# define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

/* предпологается что везде одинаковые переменные */
#define Q_LOG(q) \
	{ if (_root.log_failed_queries) _spq_log_expand(q, 0, NULL, NULL); }
#define Q_LOGX(q, n, val, len) \
	{ if (_root.log_failed_queries) \
		_spq_log_expand(q, n, (const char *const*)val, len); }

bool spq_feed_hint(const char *msg, size_t msglen, struct spq_hint *hint);

#include "include/mgm.c"
#include "include/base.c"

bool
_spq_getChunkInfo(PGconn *pgc,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		struct getChunkInfo *o, struct spq_hint *hint)
{
	PGresult *res;
	ExecStatusType pqs;
	const char *tb = "SELECT * FROM chunk_info($1::UUID, $2::UUID, $3::UUID)";

	const int fmt[3] = {0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _chunk[GUID_MAX + 1];

	char *val[3];
	int len[3];

	char *_m = NULL;
	int _l = 0;

	len[0] = guid2string(rootdir, _rootdir, sizeof(_rootdir));
	len[1] = guid2string(file, _file, sizeof(_file));
	len[2] = guid2string(chunk, _chunk, sizeof(_chunk));

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = _chunk;

	res = PQexecParams(pgc, tb, 3, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);

	if (pqs != PGRES_TUPLES_OK && pqs != PGRES_EMPTY_QUERY) {
		_m = PQresultErrorMessage(res);
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "exec getChunkInfo error: %s", _m);
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return false;
	} else if ((_l = PQgetlength(res, 0, 0)) > 0u) {
		_m = PQgetvalue(res, 0, 0);
		spq_feed_hint(_m, _l, hint);
		xsyslog(LOG_INFO, "exec getChunkInfo warning: %s", _m);
	}

	/* заполнение полей */
	if ((_l = PQgetlength(res, 0, 1)) > 0) {
		o->address = strdup(PQgetvalue(res, 0, 1));
	}

	if ((_l = PQgetlength(res, 0, 2)) > 0) {
		o->driver = strdup(PQgetvalue(res, 0, 2));
	}

	if ((_l = PQgetlength(res, 0, 3)) > 0) {
		o->size = strtoul(PQgetvalue(res, 0, 3), NULL, 10);
	}

	if ((_l = PQgetlength(res, 0, 4)) > 0) {
		o->offset = strtoul(PQgetvalue(res, 0, 4), NULL, 10);
	}

	if ((_l = PQgetlength(res, 0, 5)) > 0) {
		o->group = strtoull(PQgetvalue(res, 0, 5), NULL, 10);
	}


	PQclear(res);
	return true;
}

bool
spq_getChunkInfo(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		struct getChunkInfo *o, struct spq_hint *hint)
{
	bool r = false;
	struct spq *c;
	memset(o, 0, sizeof(*o));
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = spq_begin_life(c->conn, username, device_id) &&
			_spq_getChunkInfo(c->conn, rootdir, file, chunk, o, hint);
		release_conn(&_spq, c);
	}
	return r;
}

bool
spq_getChunkInfo_free(struct getChunkInfo *o)
{
	if (o->address)
		free(o->address);
	if (o->driver)
		free(o->driver);
	memset(o, 0, sizeof(*o));
	return true;
}

bool
_spq_getFileMeta(PGconn *pgc, guid_t *rootdir, guid_t *file,
		guid_t *revision, bool uncompleted,
		struct spq_FileMeta *fmeta, struct spq_hint *hint)
{
	PGresult *res;
	ExecStatusType pqs;
	const char *tb =
		"SELECT * FROM file_get($1::UUID, $2::UUID, $3::UUID, $4::boolean);";

	const int fmt[4] = {0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _revision[GUID_MAX + 1];

	char *val[4];
	int len[4];

	len[0] = guid2string(rootdir, _rootdir, sizeof(_rootdir));
	len[1] = guid2string(file, _file, sizeof(_file));
	len[2] = guid2string(revision, _revision, sizeof(_revision));
	len[3] = uncompleted ? 4 : 5;

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = len[2] ? _revision : NULL;
	val[3] = uncompleted ? "TRUE" : "FALSE";

	res = PQexecParams(pgc, tb, 4, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK && pqs != PGRES_EMPTY_QUERY) {
		xsyslog(LOG_INFO, "getFileMeta exec error: %s",
			PQresultErrorMessage(res));
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return false;
	}

	if (PQgetlength(res, 0, 0)) {
		char *_value = PQgetvalue(res, 0, 0);
		xsyslog(LOG_INFO, "getFileMeta exec warning: %s", _value);
		if (hint) {
			strncpy(hint->message, _value, SPQ_ERROR_LEN);
		}
		PQclear(res);
		return false;
	}

	if (PQntuples(res) <= 0) {
		fmeta->empty = true;
		return true;
	}

	/* складирование результатов */
	fmeta->res = res;
	/* revision guid */
	fmeta->rev = PQgetvalue(res, 0, 1);
	fmeta->dir = PQgetvalue(res, 0, 3);
	if (PQgetlength(res, 0, 6) > 0) {
		fmeta->chunks = (uint32_t)strtoul(PQgetvalue(res, 0, 6), NULL, 10);
	} else {
		fmeta->chunks = 0u;
	}
	if (PQgetlength(res, 0, 7) > 0) {
		fmeta->stored_chunks =
			(uint32_t)strtoul(PQgetvalue(res, 0, 7), NULL, 10);
	} else {
		fmeta->stored_chunks = 0u;
	}
	fmeta->parent_rev = PQgetvalue(res, 0, 2);
	fmeta->enc_filename = PQgetvalue(res, 0, 4);
	{
		int _len;
		if ((_len = PQgetlength(res, 0, 5)) > 0) {
			fmeta->key_len =
				hex2bin(PQgetvalue(res, 0, 5), _len, fmeta->key, PUBKEY_MAX);
		} else {
			memset(fmeta->key, 0u, PUBKEY_MAX);
			fmeta->key_len = 0u;
		}
	}

	return true;
}

bool
spq_getFileMeta(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, bool uncompleted,
		struct spq_FileMeta *fmeta, struct spq_hint *hint)
{
	bool retval = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		if (!spq_begin_life(c->conn, username, device_id) ||
				!(retval = _spq_getFileMeta(c->conn,
						rootdir, file, revision, uncompleted, fmeta, hint))
				|| fmeta->empty) {
			memset(fmeta, 0u, sizeof(struct spq_FileMeta));
			fmeta->empty = true;
			release_conn(&_spq, c);
		} else {
			fmeta->p = c;
		}
	}
	return retval;
}

void
spq_getFileMeta_free(struct spq_FileMeta *fmeta)
{
	if (fmeta->res) {
		PQclear(fmeta->res);
	}
	if (fmeta->p) {
		release_conn(&_spq, fmeta->p);
	}
	memset(fmeta, 0u, sizeof(struct spq_FileMeta));
}

bool
_spq_insert_chunk(PGconn *pgc,
		guid_t *rootdir, guid_t *file, guid_t *revision, guid_t *chunk,
		char *chunk_hash, uint32_t chunk_size, uint32_t chunk_offset,
		char *address,
		bool *complete,
		struct spq_hint *hint)
{
	PGresult *res;
	const char *tb = "SELECT * FROM insert_chunk"
		"("
		"	$1::UUID, "
		"	$2::UUID, "
		"	$3::UUID, "
		"	$4::UUID, "
		"	$5::character varying, "
		"	$6::integer, "
		"	$7::integer, "
		"	$8::text "
		");";

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _revision[GUID_MAX + 1];
	char _chunk[GUID_MAX + 1];
	char _size[32];
	char _offset[32];

	char *val[8];
	int len[8];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = guid2string(file, PSIZE(_file));
	len[2] = guid2string(revision, PSIZE(_revision));
	len[3] = guid2string(chunk, PSIZE(_chunk));
	len[4] = strlen(chunk_hash);
	len[5] = snprintf(_size, sizeof(_size), "%"PRIu32, chunk_size);
	len[6] = snprintf(_offset, sizeof(_offset), "%"PRIu32, chunk_offset);
	len[7] = strlen(address);

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = _revision;
	val[3] = _chunk;
	val[4] = chunk_hash;
	val[5] = _size;
	val[6] = _offset;
	val[7] = address;

	res = PQexecParams(pgc, tb, 8, NULL, (const char *const*)val, len, NULL, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "exec insert_chunk error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return false;
	}

	/* отдавать сообщение дальше в программу стоит
	 * только в случае контролируемого r_error,
	 * а не случайного EXCEPTION
	 */
	if (PQgetlength(res, 0, 0) != 0) {
		char *_error = PQgetvalue(res, 0, 0);
		xsyslog(LOG_INFO, "exec insert_chunk warning: %s", _error);
		if (hint) {
			strncpy(hint->message, _error, SPQ_ERROR_LEN);
		}
		PQclear(res);
		return false;
	}

	if (complete) {
		if (PQgetlength(res, 0, 1) != 0) {
			*complete = (PQgetvalue(res, 0, 1)[0] == 't');
			xsyslog(LOG_INFO, "EQI %s\n", PQgetvalue(res, 0, 1));
		} else *complete = false;
	}

	PQclear(res);
	return true;
}

bool
spq_insert_chunk(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *revision, guid_t *chunk,
		char *chunk_hash, uint32_t chunk_size, uint32_t chunk_offset,
		char *address,
		bool *complete,
		struct spq_hint *hint)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = spq_begin_life(c->conn, username, device_id) &&
			_spq_insert_chunk(c->conn, rootdir, file, revision, chunk,
				chunk_hash, chunk_size, chunk_offset, address, complete, hint);
		release_conn(&_spq, c);
	}
	return r;
}

bool
_spq_link_chunk(PGconn *pgc,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *new_chunk, guid_t *new_revision,
		bool *complete,
		struct spq_hint *hint)
{
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] = "SELECT * FROM link_chunk"
		"("
		"	$1::UUID,"
		"	$2::UUID,"
		"	$3::UUID,"
		"	$4::UUID,"
		"	$5::UUID"
		");";
	const int fmt[5] = {0, 0, 0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _chunk[GUID_MAX + 1];
	char _new_chunk[GUID_MAX + 1];
	char _new_revision[GUID_MAX + 1];

	char *val[5];
	int len[5];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = guid2string(file, PSIZE(_file));
	len[2] = guid2string(chunk, PSIZE(_chunk));
	len[3] = guid2string(new_chunk, PSIZE(_new_chunk));
	len[4] = guid2string(new_revision, PSIZE(_new_revision));

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = _chunk;
	val[3] = _new_chunk;
	val[4] = _new_revision;

	res = PQexecParams(pgc, tb, 5, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "exec link_chunk error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return false;
	}

	if (PQgetlength(res, 0, 0) > 0) {
		xsyslog(LOG_INFO, "exec link_chunk error: %s",
				PQgetvalue(res, 0, 0));
		PQclear(res);
		return false;
	}

	if (complete) {
		if (PQgetlength(res, 0, 1) != 0) {
			*complete = (PQgetvalue(res, 0, 1)[0] == 't');
		} else *complete = false;
	}

	PQclear(res);
	return true;
}

bool
spq_link_chunk(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *new_chunk, guid_t *new_revision,
		bool *complete,
		struct spq_hint *hint)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = spq_begin_life(c->conn, username, device_id) &&
			_spq_link_chunk(c->conn, rootdir, file, chunk,
				new_chunk, new_revision, complete, hint);
		release_conn(&_spq, c);
	}
	return r;
}

bool
_spq_get_quota(PGconn *pgc, guid_t *rootdir, struct spq_QuotaInfo *qi,
		struct spq_hint *hint)
{
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] = "SELECT * FROM check_quota($1::UUID);";
	const int fmt[1] = {0};

	char *m;
	int ml;

	char _rootdir[GUID_MAX + 1];

	char *val[1];
	int len[1];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));

	val[0] = _rootdir;

	res = PQexecParams(pgc, tb, 1, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);
	if (pqs != PGRES_TUPLES_OK) {
		m = PQresultErrorMessage(res);
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "exec check_quota error: %s", m);
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return false;
	} else if ((ml = PQgetlength(res, 0, 0)) > 0) {
		m = PQgetvalue(res, 0, 0);
		spq_feed_hint(m, ml, hint);
		xsyslog(LOG_INFO, "exec check_quota warning: %s", m);
	}

	if ((ml = PQgetlength(res, 0, 1)) > 0) {
		qi->quota = strtoull(PQgetvalue(res, 0, 1), NULL, 10);
	}

	if ((ml = PQgetlength(res, 0, 2)) > 0) {
		qi->used = strtoull(PQgetvalue(res, 0, 2), NULL, 10);
	}

	PQclear(res);
	return false;
}

bool
spq_get_quota(char *username, uint64_t device_id,
		guid_t *rootdir, struct spq_QuotaInfo *qi, struct spq_hint *hint)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = spq_begin_life(c->conn, username, device_id) &&
			_spq_get_quota(c->conn, rootdir, qi, hint);
		release_conn(&_spq, c);
	}
	return r;
}

uint64_t
_spq_directory_create(PGconn *pgc, guid_t *rootdir,
		guid_t *new_directory, char *new_dirname,
		struct spq_hint *hint)
{
	uint64_t result = 0lu;
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] =
		"SELECT * FROM directory_create($1::UUID, $2::UUID, $3::text);";
	const int fmt[3] = {0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _directory[GUID_MAX + 1];

	const char *_m = NULL;
	char *val[3];
	int len[3];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = guid2string(new_directory, PSIZE(_directory));
	len[2] = new_dirname ? strlen(new_dirname) : 0;

	val[0] = _rootdir;
	val[1] = _directory;
	val[2] = new_dirname;

	res = PQexecParams(pgc, tb, 3, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);

	if (pqs != PGRES_TUPLES_OK) {
		_m = PQresultErrorMessage(res);
		xsyslog(LOG_INFO, "exec directory_create error: %s", _m);
		PQclear(res);
		return 0lu;
	}

	{
		unsigned r_len;
		if ((r_len = PQgetlength(res, 0, 0))) {
			_m = PQgetvalue(res, 0, 0);
			if (_m && hint) {
				if (r_len > 2u && _m[1] == ':') {
					switch (_m[0]) {
					case '2':
						hint->level = SPQ_WARN;
						break;
					case '3':
						hint->level = SPQ_NOTICE;
						break;
					default:
						hint->level = SPQ_ERR;
					}
					if (_m[0] == '3')
						hint->level = SPQ_NOTICE;
					r_len = 2u;
				} else {
					r_len = 0u;
				}
				strncpy(hint->message, &_m[r_len], SPQ_ERROR_LEN);
			}
			if (_m)
				xsyslog(LOG_INFO, "exec directory_create warning: %s", _m);
		}

		if (PQgetlength(res, 0, 1)) {
			result = strtoul(PQgetvalue(res, 0, 1), NULL, 10);
		}
	}

	PQclear(res);
	return result;
}

uint64_t
spq_directory_create(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *new_directory, char *new_dirname,
		struct spq_hint *hint)
{
	uint64_t r = 0lu;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		if (spq_begin_life(c->conn, username, device_id)) {
			r = _spq_directory_create(c->conn, rootdir,
					new_directory, new_dirname, hint);
		}
		release_conn(&_spq, c);
	}
	return r;
}

uint64_t
_spq_update_file(PGconn *pgc, guid_t *rootdir, guid_t *file,
		guid_t *new_directory, char *new_filename,
		struct spq_hint *hint)
{
	uint64_t result;
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] =
		"SELECT * FROM update_file "
		"("
		"	$1::UUID,"
		"	$2::UUID,"
		"	$3::UUID,"
		"	$4::character varying"
		");";
	const int fmt[4] = {0, 0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _directory[GUID_MAX + 1];

	const char *_m = NULL;
	char *val[4];
	int len[4];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = guid2string(file, PSIZE(_file));
	len[2] = guid2string(new_directory, PSIZE(_directory));
	len[3] = new_filename ? strlen(new_filename) : 0u;

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = len[2] ? _directory : NULL;
	val[3] = len[3] ? new_filename : NULL;

	res = PQexecParams(pgc, tb, 4, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);

	if (pqs != PGRES_TUPLES_OK) {
		_m = PQresultErrorMessage(res);
		xsyslog(LOG_INFO, "exec update_file error: %s", _m);
	} else if (PQgetlength(res, 0, 0)) {
		_m = PQgetvalue(res, 0, 0);
		if (_m && hint)
			strncpy(hint->message, _m, SPQ_ERROR_LEN);
		xsyslog(LOG_INFO, "exec update_file warning: %s", _m);
	}

	if (_m) {
		PQclear(res);
		return 0lu;
	}

	result = strtoul(PQgetvalue(res, 0, 1), NULL, 10);
	PQclear(res);

	return result;
}

uint64_t
spq_update_file(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		guid_t *new_directory, char *new_filename,
		struct spq_hint *hint)
{
	uint64_t r = 0lu;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		if(spq_begin_life(c->conn, username, device_id))
			r = _spq_update_file(c->conn, rootdir, file,
					new_directory, new_filename, hint);
		release_conn(&_spq, c);
	}
	return r;
}

bool
spq_feed_hint(const char *msg, size_t msglen, struct spq_hint *hint)
{
	size_t e;
	if (!hint)
		return false;

	if (!msg || !msglen) {
		hint->level = SPQ_ERR;
		return true;
	}

	if (msglen >= 2u && msg[1] == ':') {
		switch(msg[0]) {
		case '2':
			hint->level = SPQ_WARN;
			break;
		case '3':
			hint->level = SPQ_NOTICE;
			break;
		default:
			hint->level = SPQ_ERR;
			break;
		}
		e = MIN(SPQ_ERROR_LEN, msglen - 2);
		strncpy(hint->message, &msg[2], e);
		hint->message[e] = '\0';
	} else {
		hint->level = SPQ_ERR;
		e = MIN(SPQ_ERROR_LEN, msglen);
		strncpy(hint->message, msg, e);
		hint->message[e] = '\0';
	}
	return true;
}

uint64_t
_spq_insert_revision(PGconn *pgc,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, guid_t *parent_revision,
		char *filename, char *pubkey,
		guid_t *dir,
		unsigned chunks,
		bool prepare,
		bool *complete,
		struct spq_hint *hint)
{
	uint64_t result;
	PGresult *res;
	ExecStatusType pqs;
	const char tb[] = "SELECT * FROM insert_revision"
		"("
		"	$1::UUID,"
		"	$2::UUID,"
		"	$3::UUID,"
		"	$4::UUID,"
		"	$5::character varying,"
		"	$6::character varying,"
		"	$7::UUID,"
		"	$8::integer,"
		"	$9::boolean"
		");";
	const int fmt[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	char _rootdir[GUID_MAX + 1];
	char _file[GUID_MAX + 1];
	char _revision[GUID_MAX + 1];
	char _parent_revision[GUID_MAX + 1];
	char _dir[GUID_MAX + 1];
	char _chunks[32];

	const char *_m = NULL;
	size_t _mlen = 0u;

	char *val[9];
	int len[9];

	len[0] = guid2string(rootdir, PSIZE(_rootdir));
	len[1] = guid2string(file, PSIZE(_file));
	len[2] = guid2string(revision, PSIZE(_revision));
	len[3] = guid2string(parent_revision, PSIZE(_parent_revision));
	len[4] = strlen(filename);
	len[5] = pubkey ? strlen(pubkey) : 0;
	len[6] = guid2string(dir, PSIZE(_dir));
	len[7] = snprintf(_chunks, sizeof(_chunks), "%u", chunks);
	len[8] = prepare ? 4 : 5;

	val[0] = _rootdir;
	val[1] = _file;
	val[2] = _revision;
	val[3] = len[3] ? _parent_revision : NULL;
	val[4] = filename;
	val[5] = pubkey;
	val[6] = _dir;
	val[7] = _chunks;
	val[8] = prepare ? "TRUE" : "FALSE";

	res = PQexecParams(pgc, tb, 9, NULL, (const char *const*)val, len, fmt, 0);
	pqs = PQresultStatus(res);

	if (pqs != PGRES_TUPLES_OK) {
		_m = PQresultErrorMessage(res);
		spq_feed_hint(NULL, 0u, hint);
		xsyslog(LOG_INFO, "exec insert_revision error: %s", _m);
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return 0;
	} else if ((_mlen = PQgetlength(res, 0, 0)) > 0u) {
		_m = PQgetvalue(res, 0, 0);
		spq_feed_hint(_m, _mlen, hint);
		xsyslog(LOG_INFO, "exec insert_revision warning: %s", hint->message);
	}

	result = strtoul(PQgetvalue(res, 0, 1), NULL, 10);

	if (complete) {
		if (PQgetlength(res, 0, 2) != 0) {
			*complete = (PQgetvalue(res, 0, 2)[0] == 't');
		} else *complete = false;
	}

	PQclear(res);
	return result;
}

uint64_t
spq_insert_revision(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, guid_t *parent_revision,
		char *filename, char *pubkey,
		guid_t *dir,
		unsigned chunks,
		bool prepare,
		bool *complete,
		struct spq_hint *hint)
{
	uint64_t r = 0lu;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		if (spq_begin_life(c->conn, username, device_id)) {
			r = _spq_insert_revision(c->conn, rootdir, file,
					revision, parent_revision, filename, pubkey, dir, chunks,
					prepare, complete, hint);
		}
		release_conn(&_spq, c);
	}
	return r;
}

bool
_spq_chunk_prepare(PGconn *pg,
		guid_t *rootdir,
		char *chunk_hash, uint32_t chunk_size,
		struct getChunkInfo *o,
		struct spq_hint *hint)
{
	PGresult *res;
	const char tb[] =
		"SELECT * FROM chunk_prepare($1::UUID, $2::varchar, $3::integer)";

	char *val[3];
	int len[3];

	char _rootdir[GUID_MAX + 1];
	char _chunk_size[12];

	char *_m = NULL;
	int _l = 0;

	len[0] = guid2string(rootdir, _rootdir, sizeof(_rootdir));
	len[1] = strlen(chunk_hash);
	len[2] = snprintf(_chunk_size, sizeof(_chunk_size), "%"PRIu32, chunk_size);

	val[0] = _rootdir;
	val[1] = chunk_hash;
	val[2] = _chunk_size;

	res = PQexecParams(pg, tb, 3, NULL, (const char *const*)val, len, NULL, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		xsyslog(LOG_INFO, "exec chunk_prepare error: %s",
				PQresultErrorMessage(res));
		PQclear(res);
		Q_LOGX(tb, sizeof(len) / sizeof(*len), val, len);
		return false;
	} else if ((_l = PQgetlength(res, 0, 0)) > 0u) {
		_m = PQgetvalue(res, 0, 0);
		spq_feed_hint(_m, _l, hint);
		xsyslog(LOG_INFO, "exec chunk_prepare warning: %s", _m);
	}


	if ((_l = PQgetlength(res, 0, 1)) > 0) {
		o->address = strdup(PQgetvalue(res, 0, 1));
	}

	if ((_l = PQgetlength(res, 0, 2)) > 0) {
		o->driver = strdup(PQgetvalue(res, 0, 2));
	}

	o->size = chunk_size;

	if ((_l = PQgetlength(res, 0, 3)) > 0) {
		o->group = strtoull(PQgetvalue(res, 0, 3), NULL, 10);
	}

	PQclear(res);

	return true;
}

bool
spq_chunk_prepare(char *username, uint64_t device_id,
		guid_t *rootdir,
		char *chunk_hash, uint32_t chunk_size,
		struct getChunkInfo *o,
		struct spq_hint *hint)
{
	bool r = false;
	struct spq *c;
	if ((c = acquire_conn(&_spq)) != NULL) {
		r = spq_begin_life(c->conn, username, device_id) &&
			_spq_chunk_prepare(c->conn, rootdir,
				chunk_hash, chunk_size, o, hint);
		release_conn(&_spq, c);
	}
	return r;
}

#include "complex/getRevisions.c"
#include "complex/getChunks.c"
#include "complex/logDirFile.c"
#include "complex/getLocalFiles.c"
#include "complex/getDevices.c"
#include "complex/store.c"

