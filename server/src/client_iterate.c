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

static struct handle handle[] =
{
	{FEP__TYPE__tPing, (handle_t)_handle_ping},
	{FEP__TYPE__tPong, (handle_t)_handle_ping},
	{FEP__TYPE__tError, NULL},
	{FEP__TYPE__tOk, NULL},
	{FEP__TYPE__tPending, NULL},
	{FEP__TYPE__tReqAuth, NULL},
	{FEP__TYPE__tAuth, NULL}
};

void
_handle_ping(struct sev_ctx *cev, unsigned type, Fep__Ping *msg, size_t size)
{
	/* TODO */
}

/* return offset */
unsigned char *
pack_header(unsigned type, size_t *len)
{
	unsigned char *buf = (unsigned char*)calloc(1, *len + HEADER_OFFSET);
	uint16_t typeBE = htons(type);
	uint32_t lenBE = htonl(*len);
	/* FIXME: ??? */
	lenBE = lenBE >> 8;
	memcpy(buf, &typeBE, 2);
	memcpy(&buf[2], &lenBE, 3);
#if 0
	xsyslog(LOG_DEBUG, "header[type: %u, len: %lu]: %02x %02x %02x %02x %02x %02x",
			type, *len, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
#endif
	*len += HEADER_OFFSET;
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
		void *msg = &buf[HEADER_OFFSET];
		if (!handle[cev->h_type].f) {
			xsyslog(LOG_INFO, "client[%p] header[type: %u, len: %u]: "
					"message has no handle",
					(void*)cev, cev->h_type, cev->h_len);
		} else {
			handle[cev->h_type].f(cev, cev->h_type, msg, cev->h_len);
		}
		return (int)(cev->h_len + HEADER_OFFSET);
	}
	return HEADER_INVALID;
}

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
		fep__req_auth__pack(&reqAuth, &buf[HEADER_OFFSET]);

		sev_send(cev, buf, reqAuth_len);
		free(buf);
		cev->state += 1;
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
		}
	}
	return false;
}

