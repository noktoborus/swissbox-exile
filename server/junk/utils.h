/* vim: ft=c ff=unix fenc=utf-8
 * file: utils.h
 */
#ifndef _UTILS_1422516244_H_
#define _UTILS_1422516244_H_

#include <netinet/in.h>
#include <stdint.h>

#if __linux__
# include <linux/limits.h>
#else
# include <limits.h>
#endif

#ifndef PATH_MAX
# ifdef MAX_PATH
#  define PATH_MAX MAX_PATH
# else
#  define PATH_MAX 4096
# endif
#endif

#ifndef MIN
# define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

#define SHA256_MAX 32
#define SHA256HEX_MAX 64
#define HASHHEX_MAX SHA256HEX_MAX
#define HASH_MAX SHA256_MAX

#define AESKEY_MAX 32
#define PUBKEY_MAX 1024

uint32_t hash_pjw(const char *str, size_t size);
size_t hex2bin(const char *hex, size_t hex_len, uint8_t *binary, size_t bin_len);
size_t bin2hex(uint8_t *binary, size_t bin_len, char *string, size_t str_len);

/*
 * отправляет в нижний регистр строку
 * если len == 0, то функция обрабатывает массив до первого '\0'
 * иначе обрабатывает по указанному размеру
 */
size_t tolower_s(char *string, size_t len);

/* рекурсивная реализация mkdir */
int mkpath(const char *path, mode_t mode);

#define SADDR_MIN 48
/*
 * print port and host to str with lenght size
 * output must be have least 48 byte
 *  (len(ipv6) + len(':') + len(SHORT_MAX) + len('\0')) == (41 + 1 + 5 + 1)
 *
 */
void
saddr_char(char *str, size_t size, sa_family_t family, struct sockaddr *sa);

#define PSIZE(x) (x), sizeof(x)
#define PSLEN(x) (x), (x != NULL ? strlen(x) : 0u)
#define PSLEN_S(x) (x), (sizeof(x) - sizeof(*x))

#define _S(x) #x
#define S(x) _S(x)
#endif /* _UTILS_1422516244_H_ */

