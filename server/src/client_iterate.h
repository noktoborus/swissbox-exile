/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.h
 */
#ifndef _SRC_CLIENT_ITERATE_1423393202_H_
#define _SRC_CLIENT_ITERATE_1423393202_H_
#include "main.h"
#include "list.h"
#include "junk/guid.h"
#include "junk/utils.h"
#include "fakedb/fakedb.h"
#include "simplepq/simplepq.h"

#include <stdint.h>
#include <polarssl/sha256.h>

#define BUFFER_ALLOC 1024
#define BUFFER_MAX 65536

enum cev_state
{
	CEV_FIRST = 0,
	CEV_AUTH,
	CEV_MORE
};


enum c_fdb_type {
	C_FILEUPDATE = 1,
};

struct fdb_head {
	enum c_fdb_type type;
};

struct fdb_fileUpdate {
	struct fdb_head head;
	Fep__FileUpdate msg;
	char rootdir_guid[GUID_MAX + 1];
	char file_guid[GUID_MAX + 1];
	char parent_revision_guid[GUID_MAX + 1];
	char revision_guid[GUID_MAX + 1];

	uint8_t *key;
	size_t key_len;
	char *hash_filename;
	char *enc_filename;
};

typedef enum _result_send {
	RESULT_CHUNKS = 1,
	RESULT_REVISIONS = 2,
	RESULT_LOGDIRFILE = 3,
} result_send_t;

struct result_send {
	void *res;
	/* id сессии (или C_NOSESSID) */
	uint64_t id;
	/* счётчик отосланных пакетов */
	uint32_t packets;
	/* тип результата */
	result_send_t type;

	union {
		struct getChunks c;
		struct getRevisions r;
		struct logDirFile df;
	} v;

	void (*free)(void*);

	struct result_send *next;
};

#define C_NOSESSID ((uint32_t)-1)
struct chunk_send {
	int fd;

	off_t sent;
	off_t size;

	uint32_t packets;
	uint32_t session_id;

	/* позиция чанка в файле и размер чанка */
	uint32_t file_offset;
	uint32_t chunk_size;

	struct chunk_send *next;
};

struct client_cum;

struct rootdir_g {
	uint32_t hash;
	guid_t rootdir;
	uint64_t checkpoint;
	uint64_t device_id;
};

#define C_NAMELEN 128
struct client {
	unsigned char *buffer;
	size_t blen;
	size_t bsz;

	char name[C_NAMELEN];

	struct client_cum *cum;
	uint64_t checkpoint;
	uint64_t device_id;

	struct {
		bool auth_ok; /* аунтифицировались */
		bool log_active; /* активация отправки FileUpdate/DirectoryUpdate*/
	} status;
	/* всякая хрень */
	bool timed;
	/*
	 * списки для фильтрации id сообщений
	 */
	struct listRoot mid; /* обычные сообщения (id) */
	struct listRoot sid; /* сообщения трансфера (session_id) */
	struct listRoot fid; /* метадата файлов (hash(file_guid)) */

	struct chunk_send *cout; /* список для файлов на отсылку */
	char *cout_buffer; /* буфер для отправки кусков чанков */
	size_t cout_bfsz;

	struct result_send *rout; /* список для ответов на всякие Query* */

	/* счётчик ошибок
	 * TODO: добавить в конфигурашку
	 */
	int count_error;

	struct sev_ctx *cev;

	/* header type and length */
	uint16_t h_type;
	uint32_t h_len;

	uint64_t genid;
	uint32_t gensid;
	enum cev_state state;

	struct fdbCursor *fdb;

	struct {
		struct rootdir_g *g;
		size_t c;
	} rootdir;

	struct {
		char *home;
		size_t send_buffer;
	} options;
};

bool client_load(struct client *c);
/* обработчик возвращает булёвое значение,
 * позитивное для продолжения работы и негативное для прерывания
 */
typedef bool(*handle_t)(struct client *, unsigned, void *);
typedef void*(*handle_unpack_t)(ProtobufCAllocator *, size_t, const uint8_t *);
typedef void(*handle_free_t)(void *, ProtobufCAllocator *);

typedef size_t(*fep_get_packed_size_t)(void*);
typedef size_t(*fep_pack_t)(void*, unsigned char*);

struct handle
{
	unsigned short type;
	char text[16];
	handle_t f;
	handle_unpack_t p;
	handle_free_t e;
	fep_get_packed_size_t f_sizeof;
	fep_pack_t f_pack;
};

const char *Fepstr(unsigned type);
#define HEADER_OFFSET 6
/* header:
 * |a|a|b|b|b|_|
 *  ^   ^__________ payload size
 *  |_________ packet type
 * _ - are reserved
 * all values in BE bytes order
 */

/* handle_header data */
#define HEADER_MORE 	0
#define HEADER_INVALID 	-1
#define HEADER_STOP 	-2

unsigned char *pack_header(unsigned type, size_t *len);
bool _send_message(struct sev_ctx *cev, unsigned type, void *msg, char *name);
#define send_message(cev, type, msg) \
	_send_message(cev, type, msg, #type)

uint64_t generate_id(struct client*);
uint32_t generate_sid(struct client*);

/*
 * Отсылает сообщение об ошибке
 * в качестве reamin указывается количество оставшихся попыток
 * если remain == -1, поле счётчика не формируется в сообщении
 */
bool send_error(struct client *c, uint64_t id, char *message, int remain);
/* то же что и send_error, но с отправкой в лог */
bool sendlog_error(struct client *c, uint64_t id, char *message, int remain);
#define C_OK_SIMPLE ((uint64_t)-1)
/* всё нормально
 * если checkpoint = C_OK_SIMPLE, отправляется сообщение ok,
 *  в ином случае сообщение OkUpdate
 */
bool send_ok(struct client *c, uint64_t id, uint64_t checkpoint, char *message);
/* всё нормально, только ждите */
bool send_pending(struct client *c, uint64_t id);

/* шлёт пинг, ждёт ответа, сообщает в лог о нём... */
bool send_ping(struct client *c);

/* обработка по id
 */

/* struct client *client
 * uint64_t id
 * unsigned int msg_type
 * void *msg
 * void *data
 */
typedef bool(*c_cb_t)(struct client*, uint64_t, unsigned int, void*, void*);

typedef struct wait_store
{
	void *data;
	c_cb_t cb;
} wait_store_t;

struct wait_xfer {
	int fd;
	char path[PATH_MAX + 1];
	uint32_t offset;
	uint64_t size; /* полный размер чанка */
	uint64_t filling; /* сколько данных было записано */
	struct wait_file *wf;

	guid_t chunk_guid;
	size_t hash_len; /* длина и сам хеш чанка */
	uint8_t hash[HASH_MAX];

	sha256_context sha256;
};

struct wait_file {
	unsigned chunks;
	unsigned chunks_ok;
	unsigned chunks_fail;

	unsigned ref; /* количество ссылок из wait_xfer */

	uint64_t msg_id;

	/* meta */
	uint64_t id;
	guid_t rootdir;
	guid_t file;
	guid_t revision;
	guid_t parent;
	guid_t dir;

	uint8_t key[PUBKEY_MAX];
	unsigned key_len;

	char enc_filename[PATH_MAX];
};

/* получение привязанных к id данных */
wait_store_t *touch_id(struct client *c, struct listRoot *list, uint64_t id);
/* аналогично touch_id, но после извлечения id вынимается из списка */
wait_store_t *query_id(struct client *c, struct listRoot *list, uint64_t id);
/* добавить новый элемент в список */
bool wait_id(struct client *c, struct listRoot *list, uint64_t id, wait_store_t *s);

/* упрощалки кода */
#define TYPICAL_HANDLE_F(struct_t, name, idl)\
	static bool \
	_handle_ ## name (struct client *c, unsigned type, struct_t *msg)\
	{\
		bool lval;\
		wait_store_t *s = query_id(c, idl, msg->id);\
		if (!s || !s->cb) {\
			if (s) free(s);\
			return sendlog_error(c, msg->id, "Unexpected " #name " message", -1);\
		}\
		lval = s->cb(c, msg->id, type, msg, s->data);\
		free(s);\
		return lval;\
	}

#define NOTIMP_HANDLE_F(struct_t, name)\
	static bool \
	_handle_ ##name(struct client *c, unsigned type, struct_t *msg)\
	{\
		xsyslog(LOG_WARNING, "client[%p] require " #name, (void*)c->cev);\
		return sendlog_error(c, 0, # name " not implement", -1);\
	}

#define TYPICAL_HANDLE_S(type, text, name) \
	{\
		type, \
		text, \
		(handle_t)_handle_ ##name,\
		(handle_unpack_t)fep__ ##name ##__unpack,\
		(handle_free_t)fep__ ##name ##__free_unpacked,\
		(fep_get_packed_size_t)fep__ ##name## __get_packed_size,\
		(fep_pack_t)fep__ ##name## __pack\
	}

#define RAW_P_HANDLE_S(type, text, name) \
	{\
		type, text, (handle_t)_handle_ ##name, \
		NULL, \
		NULL, \
		(fep_get_packed_size_t)fep__ ##name## __get_packed_size, \
		(fep_pack_t)fep__ ##name## __pack \
	}

#define RAW_HANDLE_S(type, text, name) \
	{type, text, (handle_t)_handle_ ##name, NULL, NULL, NULL, NULL}

#define INVALID_P_HANDLE_S(type, text, name) \
	{\
		type, text, (handle_t)_handle_invalid, \
		NULL, \
		NULL, \
		(fep_get_packed_size_t)fep__ ##name## __get_packed_size, \
		(fep_pack_t)fep__ ##name## __pack \
	}


#define INVALID_HANDLE_S(type, name) \
	{type, (handle_t)_handle_invalid, NULL, NULL, NULL, NULL}

#define MAKE_FHASH(rootdir, file) \
	( ((uint64_t)hash_pjw(rootdir, strlen(rootdir))) << 32 \
	 | ((uint64_t)hash_pjw(file, strlen(file))) )

void client_threads_prealloc();
void client_threads_bye();

#endif /* _SRC_CLIENT_ITERATE_1423393202_H_ */

