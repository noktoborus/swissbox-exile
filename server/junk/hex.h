/* vim: ft=c ff=unix fenc=utf-8
 * file: hex.h
 */
#ifndef _HEX_1463573231_H_
#define _HEX_1463573231_H_
#include <stdlib.h>
#include <stdint.h>

size_t hex2bin(const char *hex, size_t hex_len, uint8_t *binary, size_t bin_len);
size_t bin2hex(uint8_t *binary, size_t bin_len, char *string, size_t str_len);

#endif /* _HEX_1463573231_H_ */

