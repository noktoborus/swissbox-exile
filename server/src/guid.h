/* vim: ft=c ff=unix fenc=utf-8
 * file: src/guid.h
 */
#ifndef _SRC_GUID_1425159398_H_
#define _SRC_GUID_1425159398_H_
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct guid {
	uint32_t f1;
	uint16_t f2;
	uint16_t f3;
	uint64_t f4;
} guid_t;

bool string2guid(const char *in, size_t inlen, guid_t *guid);
bool guid2string(guid_t *guid, char *out, size_t outlen);

#endif /* _SRC_GUID_1425159398_H_ */

