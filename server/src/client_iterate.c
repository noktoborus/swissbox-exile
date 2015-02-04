/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.c
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "main.h"
#include "proto/fet.pb-c.h"

/* header:
 * |a|a|b|b|b|_|
 *  ^   ^__________ payload size
 *  |_________ packet type
 * _ - are reserved
 * all values in BE bytes order
 */


#define HEADER_OFFSET 6
/* return offset */
unsigned char *
pack_header(unsigned type, size_t *len)
{
	unsigned char *buf = (unsigned char*)calloc(1, *len + HEADER_OFFSET);
	uint16_t typeBE = htons(type);
	uint32_t lenBE = htonl(*len);
	lenBE = (lenBE << (sizeof(lenBE) - (sizeof(lenBE) - 3)));
	memcpy(buf, &typeBE, 2);
	/* FIXME: ??? */
	memcpy(&buf[2], &lenBE, 3);
	*len += HEADER_OFFSET;
	return buf;
}

bool
client_iterate(struct sev_ctx *cev)
{
	/* send helolo */
	if (cev->state == CEV_FIRST) {
		size_t reqAuth_len;
		unsigned char *buf;
		FETProto__ReqAuth reqAuth = FETPROTO__REQ_AUTH__INIT;
		reqAuth.target = FETPROTO__REQ_AUTH__TARGET__tInternal;
		reqAuth.type = FETPROTO__REQ_AUTH_TYPE__tUserPassword;
		reqAuth.domain = "example.com";
		reqAuth_len = fetproto__req_auth__get_packed_size(&reqAuth);

		buf = pack_header(FETPROTO__TYPE__tReqAuth, &reqAuth_len);
		fetproto__req_auth__pack(&reqAuth, &buf[HEADER_OFFSET]);

		sev_send(cev, buf, reqAuth_len);
		free(buf);
		cev->state += 1;
	}
	return false;
}

