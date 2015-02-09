/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.c
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "main.h"
#include "proto/fep.pb-c.h"

#include "client_iterate.h"

bool
_handle_ping(struct sev_ctx *cev, unsigned type, Fep__Ping *ping)
{
	return false;
}

bool
_handle_pong(struct sev_ctx *cev, unsigned type, Fep__Pong *pong)
{
	return false;
}

bool
_handle_auth(struct sev_ctx *cev, unsigned type, Fep__Auth *msg)
{
	/* ответы: Ok, Error, Pending */
	/* TODO: заглушка */
	char *errmsg = NULL;
	if (strcmp(msg->domain, "it-grad.ru")) {
		errmsg = "Domain not served";
	}
	if (msg->authtype != FEP__REQ_AUTH_TYPE__tUserToken) {
		errmsg = "Unknown auth scheme";
	}
	if (!msg->username || !msg->authtoken) {
		errmsg = "Username or Token not passed";
	}
	if (errmsg) {
		unsigned char *buf;
		size_t errlen;
		Fep__Error err = FEP__ERROR__INIT;

		err.message = errmsg;
		errlen = fep__error__get_packed_size(&err);
		buf = pack_header(FEP__TYPE__tError, &errlen);
		CEV_ASSERT_MEM(cev, buf == NULL, return false);
		fep__error__pack(&err, &buf[HEADER_OFFSET]);
		CEV_ASSERT_SEND(cev, sev_send(cev, buf, errlen) == -1, return false);
		free(buf);
	} else {
		unsigned char *buf;
		size_t oklen;
		Fep__Ok ok = FEP__OK__INIT;

		oklen = fep__ok__get_packed_size(&ok);
		buf = pack_header(FEP__TYPE__tOk, &oklen);
		CEV_ASSERT_MEM(cev, buf == NULL, return false);
		fep__ok__pack(&ok, &buf[HEADER_OFFSET]);
		CEV_ASSERT_SEND(cev, sev_send(cev, buf, oklen) == -1, return false);
	}
	return true;
}

static struct handle handle[] =
{
	{FEP__TYPE__tPing,
		(handle_t)_handle_ping,
		(handle_unpack_t)fep__ping__unpack,
		(handle_free_t)fep__ping__free_unpacked},
	{FEP__TYPE__tPong,
		(handle_t)_handle_pong,
		(handle_unpack_t)fep__pong__unpack,
		(handle_free_t)fep__pong__free_unpacked},
	{FEP__TYPE__tError, NULL, NULL, NULL},
	{FEP__TYPE__tOk, NULL, NULL, NULL},
	{FEP__TYPE__tPending, NULL, NULL, NULL},
	{FEP__TYPE__tReqAuth, NULL, NULL, NULL},
	{FEP__TYPE__tAuth,
		(handle_t)_handle_auth,
		(handle_unpack_t)fep__auth__unpack,
		(handle_free_t)fep__auth__free_unpacked}
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
handle_header(unsigned char *buf, size_t size, struct sev_ctx *cev)
{
	if (!cev->h_type) {
		if (size < HEADER_OFFSET) {
			return HEADER_MORE;
		} else {
			memcpy(&cev->h_type, buf, 2);
			memcpy(&cev->h_len, &buf[2], 3);
			cev->h_type = ntohs(cev->h_type);
			cev->h_len = ntohl(cev->h_len << 8);
#if 0
			xsyslog(LOG_DEBUG, "client[%p] got header[type: %u, len: %u]: "
					"%02x %02x %02x %02x %02x %02x",
					(void*)cev, cev->h_type, cev->h_len,
					buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
#endif
			/* бесполезная проверка на длину пакета */
			if (cev->h_len > 1 << 24) {
				xsyslog(LOG_WARNING, "client[%p] header[type: %u, len: %u]: "
						"length can't be great then %d",
						(void*)cev, cev->h_type, cev->h_len,
						1 << 24);
				cev->h_type = 0u;
				return HEADER_INVALID;
			}
			/* проверка на тип */
			if (sizeof(handle) / sizeof(struct handle) <= cev->h_type) {
				xsyslog(LOG_WARNING, "client[%p] header[type: %u, len: %u]: "
						"invalid type",
						(void*)cev, cev->h_type, cev->h_len);
				cev->h_type = 0u;
				return HEADER_INVALID;
			}
		}
	}
	if (size - HEADER_OFFSET < cev->h_len)
		return HEADER_MORE;
	/* извлечение пакета */
	{
		void *rawmsg = &buf[HEADER_OFFSET];
		void *msg;
		bool exit = false;
		if (!handle[cev->h_type].f) {
			xsyslog(LOG_INFO, "client[%p] header[type: %u, len: %u]: "
					"message has no handle",
					(void*)cev, cev->h_type, cev->h_len);
		} else {
			/* не должно случаться такого, что бы небыло анпакера,
			 * но как-то вот
			 */
			if (!handle[cev->h_type].p) {
				if (!handle[cev->h_type].f(cev, cev->h_type, rawmsg))
					exit = true;
			} else {
				msg = handle[cev->h_type].p(NULL, cev->h_len, (uint8_t*)rawmsg);
				if (!handle[cev->h_type].f(cev, cev->h_type, msg))
					exit = true;
				/* проверять заполненность структуры нужно в компилтайме,
				 * но раз такой возможности нет, то делаем это в рантайме
				 */
				if (!handle[cev->h_type].e) {
					xsyslog(LOG_WARNING, "memory leak for message type %u\n",
							cev->h_type);
				} else {
					handle[cev->h_type].e(msg, NULL);
				}
			}
		}
		if (!exit)
			return (int)(cev->h_len + HEADER_OFFSET);
		else
			return HEADER_STOP;
	}
	return HEADER_INVALID;
}

/* вовзращает положительный результат, если требуется прервать io */
bool
client_iterate(struct sev_ctx *cev, bool last, void **p)
{
	struct client *c = (struct client *)*p;
	int lval = 0;
	/* подчищаем, если вдруг последний раз запускаемся */
	if (last) {
		if (c) {
			free(c->buffer);
			free(c);
			*p = NULL;
		}
		return true;
	} else if (p) {
		*p = calloc(1, sizeof(struct client));
		if (!*p) {
			xsyslog(LOG_WARNING, "client[%p] memory fail: %s",
					(void*)cev, strerror(errno));
		}
		c = (struct client*)*p;
	} else {
		xsyslog(LOG_WARNING, "client[%p] field for structure not passed",
				(void*)cev);
		return true;
	}
	/* send helolo */
	if (cev->state == CEV_FIRST) {
		size_t reqAuth_len;
		unsigned char *buf;
		Fep__ReqAuth reqAuth = FEP__REQ_AUTH__INIT;
		reqAuth.target = FEP__REQ_AUTH__TARGET__tInternal;
		reqAuth.type = FEP__REQ_AUTH_TYPE__tUserPassword;
		reqAuth.domain = "example.com";
		reqAuth_len = fep__req_auth__get_packed_size(&reqAuth);

		buf = pack_header(FEP__TYPE__tReqAuth, &reqAuth_len);
		if (buf) {
			fep__req_auth__pack(&reqAuth, &buf[HEADER_OFFSET]);

			sev_send(cev, buf, reqAuth_len);
			free(buf);
			cev->state += 1;
		} else {
			xsyslog(LOG_WARNING, "client[%p] no hello with memory fail: %s",
					(void*)cev, strerror(errno));
		}
	}
	while (lval != -1) {
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
		if (lval <= 0) {
			xsyslog(LOG_WARNING, "client[%p] recv %d\n", (void*)cev, lval);
			break;
		}
		c->blen += lval;
		lval = handle_header(c->buffer, c->blen, cev);
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
					(void*)cev, cev->h_type, cev->h_len);
		}
	}
	return false;
}

