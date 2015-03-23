/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/simplepq.h
 */
#ifndef _SIMPLEPQ_SIMPLEPQ_1426075906_H_
#define _SIMPLEPQ_SIMPLEPQ_1426075906_H_
/*
 * менеджмент подключения к pgsql,
 * ерунда для простого выполнения запросов
 */
#include "junk/guid.h"
#include "junk/utils.h"
#include <stdbool.h>

/* открытие подключений к бд, pool -- количество подключений */
void spq_open(unsigned pool, char *pgstring);
void spq_resize(unsigned pool);
void spq_close();


bool spq_create_tables();

bool spq_f_chunkNew(char *username, char *hash, char *path,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file,
		uint32_t offset, uint32_t origin_len);

bool
spq_f_chunkFile(char *username,
		guid_t *rootdir, guid_t *file, guid_t *revision,
		guid_t *parent_revision,
		char *enc_filename, char *hash_filename, char *pkey, size_t pkey_len);

bool spq_f_getChunkPath(char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		char *path, size_t path_len);

/* получение списка ревизий */

struct getRevisions {
	void *p;
	void *res;

	guid_t parent;
	guid_t revision;

	unsigned row;
	unsigned max;
};
/* запрос ревизий
 * чтение полей:
 *	revision_guid
 * 	parent_revision_guid
 *
 * поиск по полям:
 * 	time
 * 	username
 * 	parent_revision_guid
 * 	rootdir_guid
 * 	file_guid
 */
bool spq_f_getRevisions(char *username, guid_t *rootdir, guid_t *file,
		unsigned depth, struct getRevisions *state);
/* итерация результата */
bool spq_f_getRevisions_it(struct getRevisions *state);
/* отчистка результатов spq_f_getRevisions */
void spq_f_getRevisions_free(struct getRevisions *state);

/* получение списка чанков (итератор по списку) */

struct getChunks {
	void *p; /* захваченная структура */
	void *res; /* ресурс постгреса */

	/* значение текущей строки, гуид чанка и его хеш */
	guid_t chunk;
	char hash[HASHHEX_MAX + 1];

	unsigned row;
	unsigned max;
};

/* запрос чанков и построчное изъятие результата
 * чтение полей:
 * 	chunk_hash
 * 	chunk_guid
 *
 * поиск по полям:
 *  username
 * 	rootdir_guid
 *	file_guid
 *	revision_guid
 */
bool spq_f_getChunks(char *username,
		guid_t *rootdir, guid_t *file, guid_t *revision,
		struct getChunks *state);
/* прохождение по списку, возвращает false, если достигнут конец */
bool spq_f_getChunks_it(struct getChunks *state);
/* отчистка результатов getChunks */
void spq_f_getChunks_free(struct getChunks *state);

#endif /* _SIMPLEPQ_SIMPLEPQ_1426075906_H_ */

