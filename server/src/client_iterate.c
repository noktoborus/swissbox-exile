/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.c
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <inttypes.h>

#include "main.h"

#include "client_iterate.h"
#include "client_cb.h"

TYPICAL_HANDLE_F(Fep__Pong, pong)
TYPICAL_HANDLE_F(Fep__Auth, auth)
TYPICAL_HANDLE_F(Fep__Ok, ok)
TYPICAL_HANDLE_F(Fep__Error, error)
TYPICAL_HANDLE_F(Fep__Pending, pending)

/* простые сообщения */

bool
send_ping(struct client *c)
{
	return false;
}

bool
send_error(struct client *c, uint64_t id, char *message, int remain)
{
	bool lval = true;
	unsigned char *buf;
	size_t errlen;
	Fep__Error err = FEP__ERROR__INIT;

	err.id = id;
	err.message = message;
	if (remain > 0)
		err.remain = (unsigned)remain;
	errlen = fep__error__get_packed_size(&err);
	buf = pack_header(FEP__TYPE__tError, &errlen);
	CEV_ASSERT_MEM(c->cev, buf == NULL, return false);
	fep__error__pack(&err, &buf[HEADER_OFFSET]);
	CEV_ASSERT_SEND(c->cev, sev_send(c->cev, buf, errlen) == -1, lval = false);
	free(buf);
	return lval;
}

bool
send_ok(struct client *c, uint64_t id)
{
	bool lval = true;
	unsigned char *buf;
	size_t oklen;
	Fep__Ok ok = FEP__OK__INIT;

	ok.id = id;
	oklen = fep__ok__get_packed_size(&ok);
	buf = pack_header(FEP__TYPE__tOk, &oklen);
	CEV_ASSERT_MEM(c->cev, buf == NULL, return false);
	fep__ok__pack(&ok, &buf[HEADER_OFFSET]);
	CEV_ASSERT_SEND(c->cev, sev_send(c->cev, buf, oklen) == -1, lval = false);
	free(buf);
	return lval;
}

bool
send_pending(struct client *c, uint64_t id)
{
	bool lval = true;
	unsigned char *buf;
	size_t pendinglen;
	Fep__Pending pending = FEP__PENDING__INIT;

	pending.id = id;
	pendinglen = fep__pending__get_packed_size(&pending);
	buf = pack_header(FEP__TYPE__tOk, &pendinglen);
	CEV_ASSERT_MEM(c->cev, buf == NULL, return false);
	fep__pending__pack(&pending, &buf[HEADER_OFFSET]);
	CEV_ASSERT_SEND(c->cev, sev_send(c->cev, buf, pendinglen) == -1,
			lval = false);
	free(buf);
	return lval;
}

/*
 * Удаляет сообщение из очереди или добавляет сообщение в корень,
 * если корень пустой
 */
static inline struct idlist*
_struct_drop_or_root(struct idlist **root, struct idlist *target)
{
	if (!root)
		return NULL;
	if (target) {
		if (*root == target)
			*root = idlist_free(target);
		else if (!*root)
			*root = target;
		else
			return idlist_free(target);
	}
	return *root;
}

/*
 * стуктура, переданная в *drop будет извлечена из указанного списка
 */
static inline struct idlist*
_struct_id(struct client *c, client_idl_t idl, struct idlist *drop)
{
	switch (idl) {
		case C_MID:
			return _struct_drop_or_root(&c->mid, drop);
		case C_SID:
			return _struct_drop_or_root(&c->scope_id, drop);
		default:
			xsyslog(LOG_WARNING, "client[%p] unknown client_idl no: %d",
					(void*)c->cev, idl);
			return NULL;
	}
}

/* постановка id в очередь ожидания TODO */
bool
wait_id(struct client *c, client_idl_t idl, uint64_t id, wait_store_t *s)
{
	struct idlist *wid;

	/* ещё одна бесполезная проверка */
	if (!s || !s->cb) {
		xsyslog(LOG_DEBUG, "client[%p] wait_id() not receive wait_store or cb",
				(void*)c->cev);
		return false;
	}

	if (!(wid = _struct_id(c, idl, NULL))) {
		/* корень пустой */
		if (!(wid = idlist_alloc(id, wid)))
			return false;
		/* бесполезная проверка на вкручиваемость узла в корень */
		if (!(_struct_id(c, idl, wid))) {
			idlist_free(wid);
			return false;
		}
	} else if (!(wid = idlist_alloc(id, wid))) {
		/* корень не пустой и добавление нового фильтра не случилось */
		return false;
	}

	wid->data = (void*)s;

	return true;
}

/* поиск id из очереди
 * при нахождении соотствия в списке, фильтр вынимается из оного
 */
wait_store_t*
query_id(struct client *c, client_idl_t idl, uint64_t id)
{
	struct idlist *wid;
	wait_store_t *data;
	if (!(wid = _struct_id(c, idl, NULL)))
		return NULL;

	if (!(wid = idlist_find(id, wid, DANY)))
		return NULL;

	if (wid->data)
		data = (wait_store_t*)wid->data;

	/* удаление ненужной структуры */
	_struct_id(c, idl, wid);
	return data;
}

/* всякая ерунда */
bool
_handle_ping(struct client *c, unsigned type, Fep__Ping *ping)
{
	bool lval = true;
	unsigned char *buf;
	size_t ponglen;
	Fep__Pong pong = FEP__PONG__INIT;
	struct timeval tv;

	if (gettimeofday(&tv, NULL) == -1) {
		xsyslog(LOG_WARNING, "client[%p] gettimeofday() fail: %s",
				(void*)c->cev, strerror(errno));
	}
	pong.id = ping->id;
	pong.timestamp = tv.tv_sec;
	pong.usecs = tv.tv_usec;

	ponglen = fep__pong__get_packed_size(&pong);
	buf = pack_header(FEP__TYPE__tPong, &ponglen);
	CEV_ASSERT_MEM(c->cev, !buf, return false);
	fep__pong__pack(&pong, &buf[HEADER_OFFSET]);
	CEV_ASSERT_SEND(c->cev, sev_send(c->cev, buf, ponglen) == -1,
			lval = false);
	free(buf);
	return lval;
}

bool
_handle_invalid(struct client *c, unsigned type, void *msg)
{
	send_error(c, 0, "Unknown packet", c->count_error);
	if (c->count_error <= 0)
		return false;
	else
		return true;
}

static struct handle handle[] =
{
	{0u, _handle_invalid, NULL, NULL},
	TYPICAL_HANDLE_S(FEP__TYPE__tPing, ping),
	TYPICAL_HANDLE_S(FEP__TYPE__tPong, pong),
	RAW_HANDLE_S(FEP__TYPE__tError, error),
	RAW_HANDLE_S(FEP__TYPE__tOk, ok),
	RAW_HANDLE_S(FEP__TYPE__tPending, pending),
	INVALID_HANDLE_S(FEP__TYPE__tReqAuth),
	TYPICAL_HANDLE_S(FEP__TYPE__tAuth, auth),
};

/* return offset */
unsigned char *
pack_header(unsigned type, size_t *len)
{
	unsigned char *buf = (unsigned char*)calloc(1, *len + HEADER_OFFSET);
	uint16_t typeBE = htons(type);
	uint32_t lenBE = htonl(*len);
	/* FIXME: ??? */
	if (buf) {
		lenBE = lenBE >> 8;
		memcpy(buf, &typeBE, 2);
		memcpy(&buf[2], &lenBE, 3);
#if 0
		xsyslog(LOG_DEBUG, "header[type: %u, len: %lu]: %02x %02x %02x %02x %02x %02x",
				type, *len, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
#endif
		*len += HEADER_OFFSET;
	}
	return buf;
}

/*-1 invalid message
 * 0 ok
 * 1 need more
 *
 * return special value (HEADER_MORE, HEADER_INVALID) or bytes
 *
 */
int
handle_header(unsigned char *buf, size_t size, struct client *c)
{
	if (!c->h_type) {
		if (size < HEADER_OFFSET) {
			return HEADER_MORE;
		} else {
			memcpy(&c->h_type, buf, 2);
			memcpy(&c->h_len, &buf[2], 3);
			c->h_type = ntohs(c->h_type);
			c->h_len = ntohl(c->h_len << 8);
#if 0
			xsyslog(LOG_DEBUG, "client[%p] got header[type: %u, len: %u]: "
					"%02x %02x %02x %02x %02x %02x",
					(void*)c->cev, c->h_type, c->h_len,
					buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
#endif
			/* бесполезная проверка на длину пакета */
			if (c->h_len > 1 << 24) {
				xsyslog(LOG_WARNING, "client[%p] header[type: %u, len: %u]: "
						"length can't be great then %d",
						(void*)c->cev, c->h_type, c->h_len,
						1 << 24);
				c->h_type = 0u;
				return HEADER_INVALID;
			}
			/* проверка на тип */
			if (sizeof(handle) / sizeof(struct handle) <= c->h_type ||
					c->h_type == 0u) {
				xsyslog(LOG_WARNING, "client[%p] header[type: %u, len: %u]: "
						"invalid type",
						(void*)c->cev, c->h_type, c->h_len);
				c->h_type = 0u;
				/*
				 * отмену можно не делать, только выставить хандлер в ноль
				 * и известить в логе, в хандлере можно позвать начальника
				return HEADER_INVALID;
				*/
			}
		}
	}
	if (size - HEADER_OFFSET < c->h_len)
		return HEADER_MORE;
	/* извлечение пакета */
	{
		void *rawmsg = &buf[HEADER_OFFSET];
		void *msg;
		bool exit = false;
		if (!handle[c->h_type].f) {
			xsyslog(LOG_INFO, "client[%p] header[type: %u, len: %u]: "
					"message has no handle",
					(void*)c->cev, c->h_type, c->h_len);
		} else {
			/* не должно случаться такого, что бы небыло анпакера,
			 * но как-то вот
			 */
			if (!handle[c->h_type].p) {
				if (!handle[c->h_type].f(c, c->h_type, rawmsg))
					exit = true;
			} else {
				msg = handle[c->h_type].p(NULL, c->h_len, (uint8_t*)rawmsg);
				if (!handle[c->h_type].f(c, c->h_type, msg))
					exit = true;
				/* проверять заполненность структуры нужно в компилтайме,
				 * но раз такой возможности нет, то делаем это в рантайме
				 */
				if (!handle[c->h_type].e) {
					xsyslog(LOG_WARNING, "memory leak for message type %u\n",
							c->h_type);
				} else {
					handle[c->h_type].e(msg, NULL);
				}
			}
		}
		if (!exit)
			return (int)(c->h_len + HEADER_OFFSET);
		else
			return HEADER_STOP;
	}
	return HEADER_INVALID;
}

static inline void
client_destroy(struct client *c)
{
	if (!c)
		return;
	if (c->buffer)
		free(c->buffer);
	free(c);
}

static inline struct client*
client_alloc(struct sev_ctx *cev)
{
	/* выделение памяти под структуру и инициализация
	 * TODO: вставить подтягивание конфига
	 */
	struct client *c;
	c = (struct client*)calloc(1, sizeof(struct client));
	if (!c) {
		xsyslog(LOG_WARNING, "client[%p] memory fail: %s",
				(void*)cev, strerror(errno));
		return NULL;
	}
	c->count_error = 3;
	c->cev = cev;
	return c;
}

/* вовзращает положительный результат, если требуется прервать io */
bool
client_iterate(struct sev_ctx *cev, bool last, void **p)
{
	struct client *c = (struct client *)*p;
	int lval = 0;
	/* подчищаем, если вдруг последний раз запускаемся */
	if (last) {
		client_destroy(c);
		*p = NULL;
		return true;
	} else if (p && !c) {
		c = client_alloc(cev);
		if (!(*p = (void*)c))
			return true;
	} else if (!p) {
		xsyslog(LOG_WARNING, "client[%p] field for structure not passed",
				(void*)cev);
		return true;
	}
	/* send helolo */
	if (c->state == CEV_FIRST) {
		size_t reqAuth_len;
		unsigned char *buf;
		Fep__ReqAuth reqAuth = FEP__REQ_AUTH__INIT;
		reqAuth.id = 1;
		reqAuth.text = "hello kitty";
		reqAuth_len = fep__req_auth__get_packed_size(&reqAuth);

		buf = pack_header(FEP__TYPE__tReqAuth, &reqAuth_len);
		if (buf) {
			wait_store_t *s;
			fep__req_auth__pack(&reqAuth, &buf[HEADER_OFFSET]);

			sev_send(cev, buf, reqAuth_len);
			free(buf);
			c->state++;

			if ((s = calloc(1, sizeof (wait_store_t))) != NULL)
				s->cb = (c_cb_t)c_auth_cb;

			if (!s || !wait_id(c, C_MID, reqAuth.id, s)) {
				if (s) free(s);
				xsyslog(LOG_WARNING,
						"client[%p] can't set filter for id %"PRIu64,
						(void*)cev, reqAuth.id);
			}
		} else {
			xsyslog(LOG_WARNING, "client[%p] no hello with memory fail: %s",
					(void*)cev, strerror(errno));
		}
	}
	while (lval >= 0) {
		/* need realloc */
		if (c->blen + BUFFER_ALLOC > c->bsz) {
			void *tmp;
			tmp = realloc(c->buffer, c->bsz + BUFFER_ALLOC);
			if (!tmp) {
				xsyslog(LOG_WARNING, "client %p, grow from %lu to %lu fail: %s",
						(void*)cev, c->bsz, c->bsz + BUFFER_ALLOC,
						strerror(errno));
				/* если обвалились по памяти, то ждём следующей итерации,
				 * так как в процессе может что-то освободиться */
				break;
			}
			c->buffer = tmp;
			c->bsz += BUFFER_ALLOC;
		}
		/* wait data */
		lval = sev_recv(cev, &c->buffer[c->blen], c->bsz - c->blen);
		if (lval < 0) {
			xsyslog(LOG_WARNING, "client[%p] recv %d\n", (void*)cev, lval);
			break;
		} else if (lval == 0) {
			/* pass to cycle sanitize (check timeouts, etc) */
			break;
		}
		c->blen += lval;
		lval = handle_header(c->buffer, c->blen, c);
		/* смещаем хвост в начало буфера */
		if (lval > 0) {
			if (lval < c->blen) {
				/* если вдруг обвалится memove, то восстанавливать, вощем-то,
				 * нечего, потому просто валимся
				 */
				if (!memmove(c->buffer, &c->buffer[lval], c->blen - lval)) {
					xsyslog(LOG_WARNING, "client[%p] memmove() fail: %s",
							(void*)cev, strerror(errno));
					return true;
				}
				c->blen -= lval;
			} else {
				c->blen = 0u;
			}
		} else if (lval == HEADER_INVALID) {
			xsyslog(LOG_WARNING, "client[%p] mismatch protocol:"
					"%x %x %x %x %x %x", (void*)cev,
					c->buffer[0], c->buffer[1], c->buffer[2],
					c->buffer[3], c->buffer[4], c->buffer[5]);
			return true;
		} else if (lval == HEADER_STOP) {
			xsyslog(LOG_WARNING, "client[%p] stop chat with "
					"header[type: %u, len: %u]",
					(void*)cev, c->h_type, c->h_len);
		}
		if (c->count_error <= 0) {
			xsyslog(LOG_INFO, "client[%p] to many errors", (void*)cev);
			return true;
		}
	}
	return false;
}

