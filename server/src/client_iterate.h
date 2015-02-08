/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.h
 */
#ifndef _SRC_CLIENT_ITERATE_1423393202_H_
#define _SRC_CLIENT_ITERATE_1423393202_H_

#define BUFFER_ALLOC 1024
#define BUFFER_MAX 65536

struct client {
	unsigned char *buffer;
	size_t blen;
	size_t bsz;
};

typedef void(*handle_t)(struct sev_ctx *, unsigned, void *);
typedef void*(*handle_unpack_t)(ProtobufCAllocator *, size_t, const uint8_t *);
typedef void(*handle_free_t)(void *, ProtobufCAllocator *);

struct handle
{
	unsigned short type;
	handle_t f;
	handle_unpack_t p;
	handle_free_t e;
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
#define HEADER_MORE 0
#define HEADER_INVALID -1

#endif /* _SRC_CLIENT_ITERATE_1423393202_H_ */

