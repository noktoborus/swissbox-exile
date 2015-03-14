/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/snip.c
 */
#include "snip.h"

#include <stdio.h>
#include <string.h>

bool
_spq_f_chunkNew(PGconn *pgc, char *username, char *hash,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file)
{
	PGresult *res;
	const char *tb = "INSERT INTO fail_records"
		"("
		"	username, "
		"	chunk_hash, "
		"	rootdir_guid, "
		"	revision_guid, "
		"	chunk_guid, "
		"	file_guid"
		") VALUES ($1, $2, $3, $4, $5, $6);";
	const int format[6] = {0, 0, 0, 0, 0, 0};

	char _rootdir_guid[GUID_MAX + 1];
	char _revision_guid[GUID_MAX + 1];
	char _chunk_guid[GUID_MAX + 1];
	char _file_guid[GUID_MAX + 1];

	char _hash_hex[] = " ";
	char *val[6];
	int length[6];

	length[0] = strlen(username);
	length[1] = 1;
	length[2] = guid2string(rootdir, _rootdir_guid, sizeof(_rootdir_guid));
	length[3] = guid2string(revision, _revision_guid, sizeof(_revision_guid));
	length[4] = guid2string(chunk, _chunk_guid, sizeof(_chunk_guid));
	length[5] = guid2string(file, _file_guid, sizeof(_file_guid));

	val[0] = username;
	val[1] = _hash_hex;
	val[2] = _rootdir_guid;
	val[3] = _revision_guid;
	val[4] = _chunk_guid;
	val[5] = _file_guid;

	res = PQexecParams(pgc, tb, 6, NULL,
			(const char *const*)val, length, format, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		/* TODO */
	}

	PQclear(res);
	return true;
}


