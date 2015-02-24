/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.h
 */
#ifndef _SRC_CLIENT_ITERATE_1423393202_H_
#define _SRC_CLIENT_ITERATE_1423393202_H_
#include "main.h"

#define BUFFER_ALLOC 1024
#define BUFFER_MAX 65536

enum cev_state
{
	CEV_FIRST = 0,
	CEV_AUTH,
	CEV_MORE
};

typedef enum clien_idl {
	C_MID = 0,
	C_SID = 1
} client_idl_t;

#define C_NAMELEN 128
struct client {
	unsigned char *buffer;
	size_t blen;
	size_t bsz;

	char name[C_NAMELEN];

	/*
	 * списки для фильтрации id сообщений
	 */
	struct idlist *mid; /* обычные сообщения */
	struct idlist *scope_id; /* сообщения трансфера */

	/* счётчик ошибок
	 * TODO: добавить в конфигурашку
	 */
	int count_error;

	struct sev_ctx *cev;

	/* header type and length */
	unsigned short h_type;
	unsigned int h_len;

	uint64_t genid;
	enum cev_state state;

	struct {
		char *home;
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
	handle_t f;
	handle_unpack_t p;
	handle_free_t e;
	fep_get_packed_size_t f_sizeof;
	fep_pack_t f_pack;
};

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
bool _send_header(struct sev_ctx *cev, unsigned type, void *msg, char *name);
#define send_header(cev, type, msg) \
	_send_header(cev, type, msg, #type)

uint64_t generate_id(struct client*);

/*
 * Отсылает сообщение об ошибке
 * в качестве reamin указывается количество оставшихся попыток
 * если remain == -1, поле счётчика не формируется в сообщении
 */
bool send_error(struct client *c, uint64_t id, char *message, int remain);
/* то же что и send_error, но с отправкой в лог */
bool sendlog_error(struct client *c, uint64_t id, char *message, int remain);
/* всё нормально */
bool send_ok(struct client *c, uint64_t id);
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

struct wait_store *query_id(struct client *c, client_idl_t idl, uint64_t id);
bool wait_id(struct client *c, client_idl_t idl, uint64_t id, wait_store_t *s);

/* упрощалки кода */
#define TYPICAL_HANDLE_F(struct_t, name)\
	static bool \
	_handle_ ## name (struct client *c, unsigned type, struct_t *msg)\
	{\
		bool lval;\
		wait_store_t *s = query_id(c, C_MID, msg->id);\
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

#define TYPICAL_HANDLE_S(type, name) \
	{\
		type, \
		(handle_t)_handle_ ##name,\
		(handle_unpack_t)fep__ ##name ##__unpack,\
		(handle_free_t)fep__ ##name ##__free_unpacked,\
		(fep_get_packed_size_t)fep__ ##name## __get_packed_size,\
		(fep_pack_t)fep__ ##name## __pack\
	}

#define RAW_P_HANDLE_S(type, name) \
	{\
		type, (handle_t)_handle_ ##name, \
		NULL, \
		NULL, \
		(fep_get_packed_size_t)fep__ ##name## __get_packed_size, \
		(fep_pack_t)fep__ ##name## __pack \
	}

#define RAW_HANDLE_S(type, name) \
	{type, (handle_t)_handle_ ##name, NULL, NULL, NULL, NULL}

#define INVALID_P_HANDLE_S(type, name) \
	{\
		type, (handle_t)_handle_invalid, \
		NULL, \
		NULL, \
		(fep_get_packed_size_t)fep__ ##name## __get_packed_size, \
		(fep_pack_t)fep__ ##name## __pack \
	}


#define INVALID_HANDLE_S(type, name) \
	{type, (handle_t)_handle_invalid, NULL, NULL, NULL, NULL}

#endif /* _SRC_CLIENT_ITERATE_1423393202_H_ */

