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

bool spq_f_chunkRename(char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *chunk_new, guid_t *revision_new);

/* v3 */
bool spq_insert_chunk(char *username,
		guid_t *rootdir, guid_t *file, guid_t *revision, guid_t *chunk,
		char *chunk_hash, uint32_t chunk_size, uint32_t chunk_offset,
		char *address);

bool spq_link_chunk(char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *new_chunk, guid_t *new_revision);

bool spq_insert_revision(char *username,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, guid_t *parent_revision,
		char *filename, uint8_t *pubkey,
		guid_t *dir,
		unsigned chunks);

/* */

bool spq_f_chunkNew(char *username, char *hash, char *path,
		guid_t *rootdir, guid_t *revision, guid_t *chunk, guid_t *file,
		uint32_t offset, uint32_t origin_len);

uint64_t
spq_f_chunkFile(char *username,
		guid_t *rootdir, guid_t *file, guid_t *revision,
		guid_t *parent_revision, guid_t *dir,
		char *enc_filename, uint64_t deviceid, uint8_t *pkey, size_t pkey_len);

bool spq_f_getChunkPath(char *username,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		char *path, size_t path_len, size_t *offset, size_t *origin);

struct getLogFile {
	void *p;
	void *res;
};

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

/* лог директофайлов */
struct logDirFile {
	void *p;
	void *res;

	uint64_t checkpoint;
	guid_t rootdir;
	guid_t directory;
	char path[PATH_MAX]; /* raw path for "d", enc_filename for "f" */

	char type; /* "d" for directory or "f" for file */
	guid_t file;
	guid_t revision;
	guid_t parent;

	uint8_t key[PUBKEY_MAX];
	size_t key_len;

	size_t chunks;

	unsigned row;
	unsigned max;
};

bool
spq_f_logDirFile(char *username, uint64_t checkpoint, uint64_t deviceid,
		struct logDirFile *state);
bool
spq_f_logDirFile_it(struct logDirFile *state);
void
spq_f_logDirFile_free(struct logDirFile *state);

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

struct spq_FileMeta {
	bool empty;

	char *rev;
	char *dir;

	uint32_t chunks;

	char *parent_rev;
	char *enc_filename;

	uint8_t key[PUBKEY_MAX];
	uint32_t key_len;

	void *p;
	void *res;
};

/*
 * вызывается два раза -- первый раз для заполнения полей в fmeta,
 * второй раз для освобождения,
 * если в результате spq_FileMeta.empty == true, то второй вызов не требуется
 * аргумент *revision может быть == NULL, в таком случае возвращается
 * последняя ревизия
 */
bool spq_f_getFileMeta(char *username, guid_t *rootdir, guid_t *file,
		guid_t *revision, struct spq_FileMeta *fmeta);
void spq_f_getFileMeta_free(struct spq_FileMeta *fmeta);

/* запись в лог файлов */
uint64_t
spq_f_logFilePush(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *directory, char *filename);
/* запись в лог директорий */
uint64_t spq_f_logDirPush(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *directory, char *path);


#endif /* _SIMPLEPQ_SIMPLEPQ_1426075906_H_ */

