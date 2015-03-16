/* vim: ft=c ff=unix fenc=utf-8
 * file: utils.h
 */
#ifndef _UTILS_1422516244_H_
#define _UTILS_1422516244_H_

#include <netinet/in.h>
#include <stdint.h>

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

#endif /* _UTILS_1422516244_H_ */

