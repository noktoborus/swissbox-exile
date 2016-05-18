/* vim: ft=c ff=unix fenc=utf-8
 * file: hex.c
 */
#include "hex.h"

size_t
hex2bin(const char *hex, size_t hex_len, uint8_t *binary, size_t bin_len)
{
	register size_t binpos = 0u;
	register size_t hexpos = 0u;
	for (; binpos < bin_len && hexpos < hex_len; hexpos+= 2) {
		/* first 4 bits */
		if (hex[hexpos] >= '0' && hex[hexpos] <= '9') {
				binary[binpos] = (hex[hexpos] - '0') << 4;
		} else if (hex[hexpos] >= 'A' && hex[hexpos] <= 'F') {
				binary[binpos] = (10 + hex[hexpos] - 'A') << 4;
		} else if (hex[hexpos] >= 'a' && hex[hexpos] <= 'f') {
				binary[binpos] = (10 + hex[hexpos] - 'a') << 4;
		} else
				continue;
		/* seconds 4 bits */
		if (hex[hexpos + 1] >= '0' && hex[hexpos + 1] <= '9') {
				binary[binpos] |= (hex[hexpos + 1] - '0') & 0xff;
		} else if (hex[hexpos + 1] >= 'A' && hex[hexpos + 1] <= 'F') {
				binary[binpos] |= (10 + hex[hexpos + 1] - 'A') & 0xff;
		} else if (hex[hexpos + 1] >= 'a' && hex[hexpos + 1] <= 'f') {
				binary[binpos] |= (10 + hex[hexpos + 1] - 'a') & 0xff;
		} else
				continue;
		/* fullbyte */
		binpos++;
	}
	return binpos;
}

size_t
bin2hex(uint8_t *binary, size_t bin_len, char *string, size_t str_len)
{
	const char hex[16] = "0123456789ABCDEF";
	size_t i;

	if (!string || !str_len || !binary || !bin_len)
		return 0u;

	for (i = 0u; i < str_len - 1 && i < bin_len * 2; i++) {
		if (!(i % 2)) {
			/* first nibble */
			string[i] = hex[binary[i / 2] >> 4 & 0xf];
		} else {
			/* second nibble */
			string[i] = hex[binary[i / 2] & 0xf];
		}
	}
	string[i] = '\0';
	return i;
}

