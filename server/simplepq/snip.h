/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/snip.h
 */
#ifndef _SIMPLEPQ_SNIP_1426357506_H_
#define _SIMPLEPQ_SNIP_1426357506_H_
#include "junk/guid.h"
#include "simplepq.h"

#include <stdbool.h>
#include <libpq-fe.h>


/*
 * получение адреса чанка
 * результат копируется в *path, не более path_len и терминируется нулём
 *
 * поиск по полям:
 * 	username
 * 	rootdir_guid
 * 	file_guid
 * 	chunk_guid
 *
 */
bool
_spq_f_getChunkPath(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		char *path, size_t path_len);

/*
 * внесение информации по загруженному чанку
 * записываемые поля:
 *  time
 *  username
 *  hash
 *  rootdir_guid
 *  revision_guid
 *  chunk_guid
 *  file_guid
 *  file_offset
 *  origin_len
 */
bool _spq_f_chunkNew(PGconn *pgc, char *username, char *hash, char *path,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file,
		uint32_t offset, uint32_t origin_len);

/*
 * внесение информации в БД для чанков по сообщению FileUpdate
 * обновление полей:
 * 	parent_revision_guid
 *	filename
 * поиск по полям:
 * 	username
 * 	rootdir_guid
 * 	file_guid
 * 	revision_guid
 */
bool _spq_f_chunkFile(PGconn *pgc, char *username,
		guid_t *rootdir, guid_t *revision, guid_t *file,
		char *filename, guid_t *parent_revision);

#endif /* _SIMPLEPQ_SNIP_1426357506_H_ */

