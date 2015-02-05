/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.c
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "main.h"
#include "proto/fep.pb-c.h"

void
handle_ping(struct sev_ctx *cev, unsigned type, Fep__Ping *msg)
{

}

typedef void(*handle_t)(struct sev_ctx *, unsigned, void *);

static struct handle
{
	unsigned type;
	handle_t f;
} handle[] =
{
	{FEP__TYPE__tPing, (handle_t)handle_ping},
	{FEP__TYPE__tPong, (handle_t)handle_ping},
	{FEP__TYPE__tError, NULL},
	{FEP__TYPE__tOk, NULL},
	{FEP__TYPE__tPending, NULL},
	{FEP__TYPE__tReqAuth, NULL},
	{FEP__TYPE__tAuth, NULL}
};

#define HEADER_OFFSET 6
/* header:
 * |a|a|b|b|b|_|
 *  ^   ^__________ payload size
 *  |_________ packet type
 * _ - are reserved
 * all values in BE bytes order
 */

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
 */
int
handle_header(unsigned char *buf, size_t *size, struct sev_ctx *cev)
{
	return -1;
}

bool
client_iterate(struct sev_ctx *cev, bool last)
{
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
	return false;
}

