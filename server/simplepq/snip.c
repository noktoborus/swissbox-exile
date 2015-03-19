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
		"	chunk_hash, "
		"	chunk_path, "
		"	rootdir_guid, "
		"	revision_guid, "
		"	chunk_guid, "
		"	file_guid,"
		"	offset,"
		"	origin,"
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
	length[1] = strlen(hash);
	length[2] = strlen(path);
	length[3] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[4] = guid2string(revision, _revision_guid, sizeof(_revision_guid));
	length[5] = guid2string(chunk, _chunk_guid, sizeof(_chunk_guid));
	length[6] = guid2string(file, _file_guid, sizeof(_file_guid));
	length[7] = snprintf(_offset, sizeof(_offset), "%"PRIu32, offset);
	length[8] = snprintf(_origin, sizeof(_origin),"%"PRIu32, origin_len);

	val[0] = username;
	val[1] = hash;
	val[2] = path;
	val[3] = _rootdir_guid;
	val[4] = _revision_guid;
	val[5] = _chunk_guid;
	val[6] = _file_guid;
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
		char *filename, guid_t *parent_revision)
{
	PGresult *res;
	char errstr[1024];
	const char *tb = "UPDATE file_records SET "
		"	parent_revision = $1, filename = $2 "
		" WHERE "
		"	username = $3, "
		"	rootdir_guid = $4, "
		"	revision_guid = $5, "
		"	file_guid = $6";
	const int format[6] = {0, 0, 0, 0, 0, 0};

	char _parent_revision_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];
	char _rootdir_guid[GUID_MAX + 1];
	char _revision_guid[GUID_MAX + 1];

	char *val[6];
	int length[6];

	length[0] = guid2string(parent_revision,
			_parent_revision_guid, sizeof(_parent_revision_guid));
	length[1] = strlen(filename);
	length[2] = strlen(username);
	length[3] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[4] = guid2string(revision, _revision_guid, sizeof(_revision_guid));
	length[5] = guid2string(file, _file_guid, sizeof(_file_guid));

	val[0] = length[0] ? val[0] : NULL;
	val[1] = filename;
	val[2] = username;
	val[3] = _rootdir_guid;
	val[4] = _revision_guid;
	val[5] = _file_guid;

	res = PQexecParams(pgc, tb, 6, NULL,
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

