/* vim: ft=c ff=unix fenc=utf-8
 * file: src/guid.c
 */
#include "src/guid.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#ifndef MIN
# define MIN(x, y) (x > y ? y : x)
#endif
/* Можно сделать и нормально, через sscanf,
 * но проще перестраховаться и не особо думать.
 *
 * in: 6F9619FF-8B86-D011-B42D-00CF4FC964FF
 */
bool
string2guid(const char *in, size_t inlen, guid_t *guid)
{
	char b[39];
	char a[17];
	if (!guid || !inlen || !in)
		return false;
	if (inlen < 32)
		return false;
	memset(b, 0, sizeof(b));
	/* обрезание '{' и '}'
	 * 36 -- максимальный размер GUID без {}
	 */
	if (in[0] == '{') {
		memcpy(b, &in[1], MIN(inlen - 2, 36));
	} else {
		memcpy(b, in, MIN(inlen, 36));
	}
	/* валидация */
	if (b[8] != '-' || b[13] != '-' || b[18] != '-' || b[23] != '-')
		return false;
	/* первая порция */
	memset(a, 0, sizeof(a));
	memcpy(a, b, 8);
	guid->f1 = (uint32_t)strtoul(a, NULL, 16);
	/* вторая порция */
	memset(a, 0, sizeof(a));
	memcpy(a, b + 9, 4);
	guid->f2 = (uint16_t)strtoul(a, NULL, 16);
	/* третья порция */
	memset(a, 0, sizeof(a));
	memcpy(a, b + 14, 4);
	guid->f3 = (uint16_t)strtoul(a, NULL, 16);
	/* четвёрта и пятая порции */
	memset(a, 0, sizeof(a));
	memcpy(a, b + 19, 4);
	memcpy(a + 4, b + 24, 12);
	guid->f4 = (uint64_t)strtoull(a, NULL, 16);
	return true;
}

bool
guid2string(guid_t *guid, char *out, size_t outlen)
{
	if (!guid || !out || !outlen)
		return false;
	snprintf(out, outlen,
			"%08"PRIX32"-%04"PRIX16"-%04"PRIX16"-%04"PRIX16"-%012"PRIX64,
			guid->f1, guid->f2, guid->f3,
			(uint16_t)(guid->f4 >> 48), (guid->f4 & 0xffffffffffff));
	return true;
}

