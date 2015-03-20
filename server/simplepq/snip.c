/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/snip.c
 */
#include "snip.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <syslog.h>

bool
_spq_f_getChunkPath(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		char *path, size_t path_len)
{
	PGresult *res;
	char errstr[1024];
	const char *tb = "SELECT path FROM file_records WHERE"
		"username = $1, rootdir_guid = $2, file_guid = $2, chunk_guid = $3";
	const int format[4] = {0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _chunk_guid[GUID_MAX + 1];

	char *val[4];
	int length[4];

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = guid2string(chunk, _chunk_guid, sizeof(_chunk_guid));

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = _chunk_guid;

	res = PQexecParams(pgc, tb, 4, NULL,
			(const char *const*)val, length, format, 0);

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		snprintf(errstr, sizeof(errstr), "spq: getChunkPath exec error: %s",
			PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return false;
	}

	PQclear(res);
	return true;
}


bool
_spq_f_chunkNew(PGconn *pgc, char *username, char *hash, char *path,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file,
		uint32_t offset, uint32_t origin_len)
{
	PGresult *res;
	char errstr[1024];
	const char *tb = "INSERT INTO file_records"
		"("
		"	username, "
		"	rootdir_guid, "
		"	file_guid,"
		"	revision_guid, "
		"	chunk_guid, "
		"	chunk_hash, "
		"	chunk_path, "
		"	\"offset\","
		"	origin"
		") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);";
	const int format[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _revision_guid[GUID_MAX + 1];
	char _chunk_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _offset[16];
	char _origin[16];

	char *val[9];
	int length[9];

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = guid2string(revision, _revision_guid, sizeof(_revision_guid));
	length[4] = guid2string(chunk, _chunk_guid, sizeof(_chunk_guid));
	length[5] = strlen(hash);
	length[6] = strlen(path);
	length[7] = snprintf(_offset, sizeof(_offset), "%"PRIu32, offset);
	length[8] = snprintf(_origin, sizeof(_origin),"%"PRIu32, origin_len);

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = _revision_guid;
	val[4] = _chunk_guid;
	val[5] = hash;
	val[6] = path;
	val[7] = _offset;
	val[8] = _origin;

	res = PQexecParams(pgc, tb, 9, NULL,
			(const char *const*)val, length, format, 0);

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		snprintf(errstr, sizeof(errstr), "spq: chunkNew exec error: %s",
			PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return false;
	}

	PQclear(res);
	return true;
}


bool
_spq_f_chunkFile(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *revision, guid_t *file,
		guid_t *parent_revision,
		char *enc_filename, char *hash_filename, char *pkey)
{
	PGresult *res;
	char errstr[1024];
	const char tb[] = "INSERT INTO file_keys"
		"("
		"	username,"
		"	rootdir_guid,"
		"	file_guid,"
		"	revision_guid,"
		"	parent_revision_guid,"
		"	enc_filename,"
		"	hash_filename,"
		"	public_key"
		") VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
	const int format[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	char _s_rootdir[GUID_MAX + 1];
	char _s_file[GUID_MAX + 1];
	char _s_revision[GUID_MAX + 1];
	char _s_parent[GUID_MAX + 1];

	char *val[8];
	int length[8];

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _s_rootdir, sizeof(_s_rootdir));
	length[2] = guid2string(file, _s_file, sizeof(_s_file));
	length[3] = guid2string(revision, _s_revision, sizeof(_s_revision));
	length[4] = guid2string(parent_revision, _s_parent, sizeof(_s_parent));
	length[5] = strlen(enc_filename);
	length[6] = strlen(hash_filename);
	length[7] = strlen(pkey);

	val[0] = username;
	val[1] = _s_rootdir;
	val[2] = _s_file;
	val[3] = _s_revision;
	val[4] = _s_parent;
	val[5] = enc_filename;
	val[6] = hash_filename;
	val[7] = pkey;

	res = PQexecParams(pgc, tb, 8, NULL,
			(const char *const*)val, length, format, 0);

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		snprintf(errstr, sizeof(errstr), "spq: chunkFile exec error: %s",
			PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return false;
	}
	PQclear(res);
	return true;
}

PGresult*
_spq_f_getChunks_exec(PGconn *pgc,
		char *username, guid_t *rootdir, guid_t *file, guid_t *revision)
{
	PGresult *res;
	char errstr[1024];
	const char *tbq = "SELECT chunk_hash, chunk_guid FROM file_records WHERE "
		"username = $1, "
		"rootdir_guid = $2, file_guid = $3, revision_guid = $4";
	const int format[4] = {0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _revision_guid[GUID_MAX + 1];

	char *val[4];
	int length[4];

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = guid2string(revision, _revision_guid, sizeof(_revision_guid));

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = _revision_guid;

	res = PQexecParams(pgc, tbq, 4, NULL,
			(const char *const*)val, length, format, 0);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		snprintf(errstr, sizeof(errstr), "spq: getChunks exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return NULL;
	}
	return res;
}

PGresult*
_spq_f_getRevisions_exec(PGconn *pgc,
		char *username, guid_t *rootdir, guid_t *file, unsigned depth)
{
	PGresult *res;
	char errstr[1024];
	const char *tbq = "SELECT revision_guid FROM file_records WHERE "
		"username = $1, "
		"rootdir_guid = $2, "
		"file_guid = $3 "
		"ORDER BY time DESC LIMIT $4";
	const int format[5] = {0, 0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];

	char *val[5];
	int length[5];

	uint32_t ndepth = htons((uint32_t)depth);

	length[0] = strlen(username);
	length[1] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[2] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[3] = sizeof(uint32_t);

	val[0] = username;
	val[1] = _rootdir_guid;
	val[2] = _file_guid;
	val[3] = (char*)&ndepth;

	res = PQexecParams(pgc, tbq, 5, NULL,
			(const char *const*)val, length, format, 0);

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		snprintf(errstr, sizeof(errstr), "spq: getChunks exec error: %s",
				PQresultErrorMessage(res));
		syslog(LOG_INFO, errstr);
		PQclear(res);
		return NULL;
	}
	return res;
}

