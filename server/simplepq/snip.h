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
 * внесение информации по загруженному чанку
 * записываемые поля:
 *  time
 *  username
 *  hash
 *  rootdir_guid
 *  revision_guid
 *  chunk_guid
 *  file_guid
 */
bool _spq_f_chunkNew(PGconn *pgc, char *username, char *hash,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file);



#endif /* _SIMPLEPQ_SNIP_1426357506_H_ */

