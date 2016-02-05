/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/simplepq.h
 */
#ifndef _SIMPLEPQ_SIMPLEPQ_1426075906_H_
#define _SIMPLEPQ_SIMPLEPQ_1426075906_H_
/*
 * менеджмент подключения к pgsql,
 * ерунда для простого выполнения запросов
 */
#include <ev.h>

#include "junk/guid.h"
#include "junk/utils.h"
#include <stdbool.h>
#include <libpq-fe.h>
#include <pthread.h>

struct spq_key {
	PGconn *c;

	bool in_action;
	size_t uses;

	uint32_t pgstring_hash;

	struct spq_key *key;
	struct spq_key *keyp;
};

struct spq {
	/* основная блокировка */
	pthread_mutex_t lock;

	uint32_t pgstring_hash;
	char *pgstring;
	bool log_failed_queries;


	size_t active;
	size_t count;

	struct spq_key *key;
};

/* открытие подключений к бд, pool -- количество подключений
 * потоко-небезопасная функция
 */
void spq_open(char *pgstring);
/* прерывание всех запросов */
void spq_interrupt();
/* закрытие менеджера подключений. Потоко-небезопасная функция */
void spq_close();

/* включение/выключение печать в лог запросов с ошибками */
void spq_set_log_failed_queries(bool enable);
/* изменения адреса подключения */
void spq_set_address(char *pgstring);

bool spq_create_tables();

/* запрос ключа */
struct spq_key *
spq_vote(const char *username, uint64_t device_id);

/* возврат отработанного ключа */
void
spq_devote(struct spq_key *key);

enum spq_level {
	SPQ_OK = 0,
	SPQ_ERR,
	SPQ_WARN,
	SPQ_NOTICE
};

/* v3 */
/* структура для возврата сообщений об ошибках
 * и прочей отладочной информации
 */
#define SPQ_ERROR_LEN 1024
struct spq_hint {
	char message[SPQ_ERROR_LEN + 1];
	enum spq_level level;
};

uint64_t
spq_update_file(struct spq_key *k,
		guid_t *rootdir, guid_t *file,
		guid_t *new_directory, char *new_filename,
		struct spq_hint *hint);

bool spq_insert_chunk(struct spq_key *k,
		guid_t *rootdir, guid_t *file, guid_t *revision, guid_t *chunk,
		char *chunk_hash, uint32_t chunk_size, uint32_t chunk_offset,
		char *address,
		/* output */
		bool *complete,
		struct spq_hint *hint);

uint64_t spq_insert_revision(struct spq_key *k,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, guid_t *parent_revision,
		char *filename, char *pubkey,
		guid_t *dir,
		unsigned chunks,
		bool prepare,
		/* output */
		bool *complete,
		struct spq_hint *hint);

uint64_t spq_directory_create(struct spq_key *k,
		guid_t *rootdir, guid_t *new_directory, char *new_dirname,
		struct spq_hint *hint);

/* */
/* информация о чанке: расположение, драйвер, размеры и группа */
struct getChunkInfo {
	char *address;
	char *driver;
	size_t size;
	size_t offset;
	uint64_t group; /* location_group в sql */
};

bool spq_getChunkInfo(struct spq_key *k,
		guid_t *rootdir, guid_t *file, guid_t *chunk,
		struct getChunkInfo *o, struct spq_hint *hint);

bool spq_getChunkInfo_free(struct getChunkInfo *o);

/* */

struct getLogFile {
	void *p;
	void *res;
};

/* список устройств */
struct getDevices {
	void *p;
	void *res;

	const char *last_auth_time;
	uint64_t device_id;

	unsigned row;
	unsigned max;
};

bool spq_getDevices_it(struct getDevices *state);
void spq_getDevices_free(struct getDevices *state);
bool spq_getDevices(const char *username, uint64_t device_id,
		struct getDevices *state, struct spq_hint *hint);

/* получение списка локальных файлов */

struct getLocalFiles {
	void *p;
	void *res;

	uint64_t file_id;

	char *path;
	char *owner;

	unsigned row;
	unsigned max;
};

bool spq_getLocalFiles_it(struct getLocalFiles *state);
void spq_getLocalFiles_free(struct getLocalFiles *state);
bool spq_getLocalFiles(struct getLocalFiles *state, struct spq_hint *hint);

/* получение списка ревизий */

struct getRevisions {
	void *p;
	void *res;

	guid_t parent;
	guid_t revision;

	unsigned row;
	unsigned max;
};
/* запрос ревизий */
bool spq_getRevisions(struct spq_key *k,
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
spq_f_logDirFile(struct spq_key *k, guid_t *rootdir, uint64_t checkpoint,
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

/* запрос чанков и построчное изъятие результата */
bool spq_getChunks(struct spq_key *k,
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
	uint32_t stored_chunks;

	char *parent_rev;
	char *enc_filename;

	uint8_t key[PUBKEY_MAX];
	uint32_t key_len;

	void *p;
	void *res;
};

/* TODO: ненужное говнище?
 * вызывается два раза -- первый раз для заполнения полей в fmeta,
 * второй раз для освобождения,
 * если в результате spq_FileMeta.empty == true, то второй вызов не требуется
 * аргумент *revision может быть == NULL, в таком случае возвращается
 * последняя ревизия
 */
bool spq_getFileMeta(struct spq_key *k,
		guid_t *rootdir, guid_t *file,
		guid_t *revision, bool uncompleted,
		struct spq_FileMeta *fmeta, struct spq_hint *hint);
void spq_getFileMeta_free(struct spq_FileMeta *fmeta);

bool spq_store_save(struct spq_key *k,
		bool share, uint32_t offset, uint32_t length,
		uint8_t *data, uint32_t data_len,
		struct spq_hint *hint);

struct spq_StoreData {
	bool empty;

	uint8_t *store;
	uint32_t store_len;

	uint32_t length;

	void *p;
	void *res;
};

bool spq_store_load(struct spq_key *k,
		bool share, uint32_t offset, uint32_t length,
		struct spq_StoreData *sd,
		struct spq_hint *hint);

void spq_store_load_free(struct spq_StoreData *sd);

/* проверка наличия пользователя в бд */
struct spq_UserInfo {
	/* авторизован ли пользователь или нужно обращаться к next_server */
	bool authorized;
	/* время регистрации, если пользователь был получен от next_server,
	 * то время последнего обновления
	 */
	time_t registered;

	/* счётчик зарегистрированных устройств пользователя */
	uint32_t devices;
	/* последнее устройство входа */
	uint64_t last_device;

	/* адрес следующего сервера для авторизации и прочего */
	char next_server[PATH_MAX + 1];
};


/*
 * получение информаци по чанку (чанкам? по их chunk_hash)
 *
 * getChunkInfo заполняется кроме поля group
 *  поля address и driver заполняются только при наличие чанка на сервере
 * освобождать структуру с помощью spq_getChunkInfo_free() требуется
 */
bool
spq_chunk_prepare(struct spq_key *k,
		guid_t *rootdir,
		char *chunk_hash, uint32_t chunk_size,
		struct getChunkInfo *o,
		struct spq_hint *hint);

struct spq_QuotaInfo {
	uint64_t used;
	uint64_t quota;
};

/* получение информации по квоте в указанной rootdir
 * в *qi результат запроса
 */
bool
spq_get_quota(struct spq_key *k,
		guid_t *rootdir, struct spq_QuotaInfo *qi, struct spq_hint *hint);

struct spq_InitialUser {
	guid_t mark;
};

/*
 * получение начальных значений для пользователя
 */
bool spq_initial_user(struct spq_InitialUser *iu, struct spq_hint *hint);
bool spq_check_user(char *username, char *secret, uint64_t device_id,
		struct spq_UserInfo *user, struct spq_hint *hint);

/* костыли */
bool spq_add_user(char *username, char *secret, struct spq_hint *hint);

#endif /* _SIMPLEPQ_SIMPLEPQ_1426075906_H_ */

