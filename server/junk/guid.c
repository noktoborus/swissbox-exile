/* vim: ft=c ff=unix fenc=utf-8
 * file: src/guid.c
 */
#include "guid.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>

#include <polarssl/md5.h>

#ifndef MIN
# define MIN(x, y) (x > y ? y : x)
#endif

bool
any2guid(const char *in, size_t inlen, guid_t *guid)
{
	/* получение md5 хеша входящей строки и формирование гуида */
	char md5o[16];
	md5((const unsigned char*)in, inlen, (unsigned char*)md5o);

	memset(guid, 0u, sizeof(guid_t));

	memcpy(&guid->f1, md5o, 4);
	memcpy(&guid->f2, &md5o[4], 2);
	memcpy(&guid->f3, &md5o[6], 2);
	memcpy(&guid->f4, &md5o[8], 8);

	guid->not_null = true;

	return true;
}

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
	/* на всякий случай всё подчищаем */
	if (guid)
		memset(guid, 0, sizeof(guid_t));
	/* проверка на отсутвие буфера под гуид
	 * и мусора в in,
	 * если inlen != 0 когда in == NULL, значит это шлак
	 */
	if (!guid || ((intptr_t)inlen != 0u && in == NULL)) {
		return false;
	}
	if (inlen < 32)
		return false;
	/* выходим нормально с подчисткой памяти если буфера нет */
	if (!in || !inlen)
		return true;
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
	/* флаг что гуид есть в структуре */
	guid->not_null = true;
	return true;
}

size_t
guid2string(guid_t *guid, char *out, size_t outlen)
{
	int len;
	if (!guid || !out || !outlen || !guid->not_null) {
		if (out && outlen)
			*out = '\0';
		return 0u;
	}
	len = snprintf(out, outlen,
			"%08"PRIX32"-%04"PRIX16"-%04"PRIX16"-%04"PRIX16"-%012"PRIX64,
			guid->f1, guid->f2, guid->f3,
			(uint16_t)(guid->f4 >> 48), (guid->f4 & 0xffffffffffff));
	if (len > 0)
		return (size_t)len;
	else return 0;
}

bool
guid2net(guid_t *guid, uint8_t out[16])
{
	if (!guid->not_null) {
		memset(out, 0u, 16);
	} else {
		*((uint32_t*)&out[0]) = htobe32(guid->f1);
		*((uint16_t*)&out[4]) = htobe16(guid->f2);
		*((uint16_t*)&out[6]) = htobe16(guid->f3);
		*((uint64_t*)&out[8]) = htobe64(guid->f4);
	}
	return true;
}

bool
net2guid(uint8_t in[16], guid_t *guid)
{
	memset(guid, 0u, sizeof(*guid));

	guid->f1 = be32toh(*((uint32_t*)&in[0]));
	guid->f2 = be16toh(*((uint16_t*)&in[4]));
	guid->f3 = be16toh(*((uint16_t*)&in[6]));
	guid->f4 = be64toh(*((uint64_t*)&in[8]));
	guid->not_null = true;

	return true;
}

