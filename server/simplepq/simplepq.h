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
#include <libpq-fe.h>

/* открытие подключений к бд, pool -- количество подключений */
void spq_open(unsigned pool, char *pgstring);
void spq_resize(unsigned pool);
void spq_close();

bool spq_create_tables();

/* v3 */
/* структура для возврата сообщений об ошибках
 * и прочей отладочной информации
 */
#define SPQ_ERROR_LEN 1024
struct spq_hint {
	char message[SPQ_ERROR_LEN + 1];
};

uint64_t
spq_update_file(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		guid_t *new_directory, char *new_filename,
		struct spq_hint *hint);

bool spq_insert_chunk(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *revision, guid_t *chunk,
		char *chunk_hash, uint32_t chunk_size, uint32_t chunk_offset,
		char *address,
		struct spq_hint *hint);

bool spq_link_chunk(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		guid_t *new_chunk, guid_t *new_revision,
		struct spq_hint *hint);

uint64_t spq_insert_revision(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, guid_t *parent_revision,
		char *filename, char *pubkey,
		guid_t *dir,
		unsigned chunks,
		struct spq_hint *hint);

uint64_t spq_directory_create(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *new_directory, char *new_dirname,
		struct spq_hint *hint);

/* */

bool spq_getChunkPath(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		char *path, size_t path_len, size_t *offset,
		struct spq_hint *hint);

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
bool spq_getRevisions(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		unsigned depth, struct getRevisions *state);
/* итерация результата */
bool spq_getRevisions_it(struct getRevisions *state);
/* отчистка результатов spq_f_getRevisions */
void spq_getRevisions_free(struct getRevisions *state);

/* лог директофайлов */
struct logDirFile {
	void *p;
	void *res;

	uint64_t checkpoint;
	guid_t rootdir;
	guid_t directory;
	char path[PATH_MAX + 1]; /* raw path for "d", enc_filename for "f" */

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
spq_f_logDirFile(char *username, guid_t *rootdir, uint64_t checkpoint,
		uint64_t deviceid, struct logDirFile *state);
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
bool spq_getChunks(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file, guid_t *revision,
		struct getChunks *state);
/* прохождение по списку, возвращает false, если достигнут конец */
bool spq_getChunks_it(struct getChunks *state);
/* отчистка результатов getChunks */
void spq_getChunks_free(struct getChunks *state);

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
bool spq_getFileMeta(char *username, uint64_t device_id,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, struct spq_FileMeta *fmeta,
		struct spq_hint *hint);
void spq_getFileMeta_free(struct spq_FileMeta *fmeta);

/* проверка наличия пользователя в бд */
bool spq_check_user(char *username, char *secret);

/* помогалки */
bool spq_begin_life(PGconn *pgc, char *username, uint64_t device_id);

#endif /* _SIMPLEPQ_SIMPLEPQ_1426075906_H_ */

