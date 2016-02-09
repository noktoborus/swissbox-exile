/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.h
 */
#ifndef _SRC_CLIENT_ITERATE_1423393202_H_
#define _SRC_CLIENT_ITERATE_1423393202_H_
#include "src/client/cum.h"
#include "main.h"
#include "list.h"
#include "junk/guid.h"
#include "junk/utils.h"
#include "simplepq/simplepq.h"
#include "squeue/squeue.h"
#include "fcac/fcac.h"

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

/* типы ресурсов, которые нужны для обработки пакета
 * обрабатываются битово
 */
enum handle_reqs_t {
	H_REQS_Z = 0,
	H_REQS_SQL = 1,
	H_REQS_FD = 2
};

typedef enum _result_send {
	RESULT_CHUNKS = 1,
	RESULT_REVISIONS = 2,
	RESULT_LOGDIRFILE = 3,
	RESULT_DEVICES = 4,
} result_send_t;

struct result_send {
	void *res;
	/* id сессии (или C_NOSESSID) */
	uint64_t id;
	/* счётчик отосланных пакетов */
	uint32_t packets;
	/* тип результата */
	result_send_t type;
	/* в какой рутдире произошёл запрос */
	guid_t rootdir;

	union {
		struct getChunks c;
		struct getRevisions r;
		struct logDirFile df;
		struct getDevices d;
	} v;

	void (*free)(void*);

	struct spq_key *sk;
	enum handle_reqs_t reqs;

	struct result_send *next;
};

#define C_NAMELEN 128
struct chat_store {
	size_t serial_from;
	uint64_t device_id_from;
	char name_from[C_NAMELEN + 1];

	bool unicast;
	uint64_t device_id_to;

/*
	bool outdoor;
	char name_to[C_NAMELEN + 1];
*/

	/* само собщение */
	size_t len;
	uint8_t buffer[1];
};

#define C_NOSESSID ((uint32_t)-1)
struct chunk_send {
	struct fcac_ptr p;

	off_t sent;
	off_t size;

	uint32_t packets;
	uint32_t session_id;

	/* позиция чанка в файле и размер чанка */
	uint32_t file_offset;
	uint32_t chunk_size;

	/* true если структуру нужно разобрать */
	bool corrupt;

	struct chunk_send *next;
};

/* подготовка к отправке чанка */
struct chunk_prepare {
	struct fcac_ptr *fp;

	/* отметка о последнее событие
	 * таком, как:
	 * 1. начало запроса
	 * 2. ответ драйвера
	 * 3. готовность к отправке
	 */
	time_t last;

	/* id пакета, на который нужно отправить ответ */
	uint64_t id;

	/* id сессии */
	uint64_t session_id;

	struct chunk_prepare *next;
};

#define C_ROOTDIR_ACTIVATE (uint64_t)-1
struct rootdir_g {
	uint32_t hash;
	guid_t rootdir;
	uint64_t checkpoint;
	uint64_t device_id;
	bool active; /* флаг необходимости отправки обновлений в этой рутдире */
};

struct client {
	unsigned char *buffer;
	size_t blen;
	size_t bsz;

	char name[C_NAMELEN];

	struct client_cum *cum;
	/* TODO: общий checkpoint для списка rootdir нужен
	 * но сейчас он вносит путаницу
	uint64_t checkpoint;
	*/
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

	/* отложенные входящие пакеты по причине достижения лимита обработки */
	struct listRoot msg_delayed;

	/* курсор по списку сообщений */
	struct squeue_cursor broadcast_c;
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

	/* всякие очереди для экономии ресурсов */

	struct {
		struct rootdir_g *g;
		size_t c;
	} rootdir;

	struct {
		char *home;
		size_t send_buffer;

		/* см. main.options */
		bool unique_device_id;

		long limit_global_sql_queries;
		long limit_global_fd_queries;
		long limit_local_sql_queries;
		long limit_local_fd_queries;
	} options;

	struct {
		long sql_queries_count;
		long fd_queries_count;
	} values;
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



struct h_reqs_store_t {
	unsigned type;
	enum handle_reqs_t reqs;
	size_t len;
	/*
	 * конечно это какое-то безумие паковать сообщение обратно
	 * в массив, что бы снова его распаковать, но всё же...
	 */
	uint8_t msg[1];
};

/*
 * захват и освобождение
 * счётчики "тупые", потому использовать их нужно аккуратно
 *
 */
/* захват и отпуск счётчика ресурсов
 * возвращает false в случае, если счётчик дальнейшая обработка пакета
 * нежелательна
 */
bool client_reqs_acquire(struct client *c, enum handle_reqs_t reqs);
void client_reqs_release(struct client *c, enum handle_reqs_t reqs);
/* освобождение всех глобальных ресурсов, захваченные клиентом */
void client_reqs_release_all(struct client *c);

/* поклажа сообщения в очередь обработки на потом
 * должно вызываться после неудачного client_reqs_acquire()
 */
bool client_reqs_queue(struct client *c, enum handle_reqs_t reqs,
		unsigned type, void *msg);

/* обработка сообщений в очереди (по одному за вызов)
 * в качестве reqs передаётся битовая маска свободных ресурсов
 *
 * false возвращается в случае, если не удалось вызвать хандлер сообщения
 * или хандлер вернул false
 *
 * во всех остальных случаях, включая пустую очередь, возвращается true
 *
 * если reqs == H_REQS_Z, то процедурка сама определяет какие ресурсы
 * доступны
 */
bool client_reqs_unqueue(struct client *c, enum handle_reqs_t reqs);

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
bool send_message(struct sev_ctx *cev, unsigned type, void *msg);

void free_message(unsigned type, void *msg);
bool pack_message(unsigned type, void *msg, uint8_t *out);
size_t sizeof_message(unsigned type, void *msg);
/* возвращает длину сообщения в буфере в случае удачи
 * HEADER_INVALID если какая-то хрень
 * HEADER_STOP если хандлер сообщения вернул false
 */
int exec_bufmsg(struct client *c, unsigned type, uint8_t *buf, size_t len);

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
/* запрос уже выполнен */
bool send_satisfied(struct client *c, uint64_t id);

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
	enum handle_reqs_t reqs;
	struct client *c;
} wait_store_t;

struct wait_xfer {
	struct fcac_ptr p;
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

	/* true, если при сборке чанков драйвер бд вернул completed */
	bool complete;

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
		xsyslog(LOG_WARNING,\
				"client[%"SEV_LOG"] require " #name, c->cev->serial);\
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

void client_threads_prealloc();
void client_threads_bye();

#endif /* _SRC_CLIENT_ITERATE_1423393202_H_ */

