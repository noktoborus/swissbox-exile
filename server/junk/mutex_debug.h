/* vim: ft=c ff=unix fenc=utf-8
 * file: junk/mutex_debug.h
 */
#ifndef _JUNK_MUTEX_DEBUG_1441016521_H_
#define _JUNK_MUTEX_DEBUG_1441016521_H_

# include <pthread.h>
# include "xsyslog.h"

static inline int
_pthread_mutex_lock(pthread_mutex_t *m, const char *file, int line) {
	int r;
	xsyslog(LOG_DEBUG, "[%s:%d] mutex lock %p", file, line, (void*)m);
	r = pthread_mutex_lock(m);
	xsyslog(LOG_DEBUG, "[%s:%d] mutex lock %p -> %d", file, line, (void*)m, r);
	return r;
}

static inline int
_pthread_mutex_trylock(pthread_mutex_t *m, const char *file, int line) {
	int r;
	r = pthread_mutex_trylock(m);
	xsyslog(LOG_DEBUG, "[%s:%d] mutex trylock %p -> %d", file, line, (void*)m, r);
	return r;
}

static inline int
_pthread_mutex_unlock(pthread_mutex_t *m, const char *file, int line) {
	int r;
	r = pthread_mutex_unlock(m);
	xsyslog(LOG_DEBUG, "[%s:%d] mutex unlock %p -> %d", file, line, (void*)m, r);
	return r;
}

static inline int
_pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m, const char *file, int line) {
	int r;
	xsyslog(LOG_DEBUG, "[%s:%d] mutex cond_wait %p", file, line, (void*)m);
	r = pthread_cond_wait(c, m);
	xsyslog(LOG_DEBUG, "[%s:%d] mutex cond_wait %p -> %d", file, line, (void*)m, r);
	return r;
}

static inline int
_pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a, const char *file, int line)
{
	int r;
	r = pthread_mutex_init(m, a);
	xsyslog(LOG_DEBUG, "[%s:%d] mutex init %p -> %d", file, line, (void*)m, r);
	return r;
}

static inline int
_pthread_mutex_destroy(pthread_mutex_t *m, const char *file, int line)
{
	int r;
	r = pthread_mutex_destroy(m);
	xsyslog(LOG_DEBUG, "[%s:%d] mutex destroy %p -> %d", file, line, (void*)m, r);
	return r;
}

# define pthread_mutex_init(x, y) _pthread_mutex_init(x, y, __FILE__, __LINE__)
# define pthread_mutex_destroy(x) _pthread_mutex_destroy(x, __FILE__, __LINE__)
# define pthread_mutex_lock(x)  _pthread_mutex_lock(x, __FILE__, __LINE__)
# define pthread_mutex_trylock(x)  _pthread_mutex_trylock(x, __FILE__, __LINE__)
# define pthread_mutex_unlock(x)  _pthread_mutex_unlock(x, __FILE__, __LINE__)
# define pthread_cond_wait(x, y) _pthread_cond_wait(x, y, __FILE__, __LINE__)

#endif /* _JUNK_MUTEX_DEBUG_1441016521_H_ */

