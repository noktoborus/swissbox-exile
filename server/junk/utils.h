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

#define SADDR_MIN 48
/*
 * print port and host to str with lenght size
 * output must be have least 48 byte
 *  (len(ipv6) + len(':') + len(SHORT_MAX) + len('\0')) == (41 + 1 + 5 + 1)
 *
 */
void
saddr_char(char *str, size_t size, sa_family_t family, struct sockaddr *sa);

#if MUTEX_DEBUG
# include <pthread.h>
# include "xsyslog.h"
static inline int _pthread_mutex_lock(pthread_mutex_t *m) {
	return pthread_mutex_lock(m);
}

static inline int _pthread_mutex_trylock(pthread_mutex_t *m, const char *file, int line) {
	int r;
	xsyslog(LOG_DEBUG, "[%s:%d] mutex trylock %p", file, line, (void*)m);
	r = pthread_mutex_trylock(m);
	xsyslog(LOG_DEBUG, "[%s:%d] mutex trylock %p -> %d", file, line, (void*)m, r);
	return r;
}

static inline int _pthread_mutex_unlock(pthread_mutex_t *m) {
	return pthread_mutex_unlock(m);
}

static inline int _pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
	return pthread_cond_wait(c, m);
}

# define pthread_mutex_lock(x) {xsyslog(LOG_DEBUG, "mutex lock %p", (void*)x); _pthread_mutex_lock(x); }
# define pthread_mutex_unlock(x) {xsyslog(LOG_DEBUG, "mutex unlock %p", (void*)x); _pthread_mutex_unlock(x); }
# define pthread_mutex_trylock(x)  _pthread_mutex_trylock(x, __FILE__, __LINE__)
# define pthread_cond_wait(x, y) {xsyslog(LOG_DEBUG, "cond unlock %p", (void*)y); _pthread_cond_wait(x, y); }
#endif

#define PSIZE(x) x, sizeof(x)
#define PSLEN(x) x, (x != NULL ? strlen(x) : 0u)
#define _S(x) #x
#define S(x) _S(x)
#endif /* _UTILS_1422516244_H_ */

