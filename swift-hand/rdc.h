/* vim: ft=c ff=unix fenc=utf-8
 * file: rdc.h
 */
#ifndef _RDC_1439466539_H_
#define _RDC_1439466539_H_
#include <ev.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <hiredis/hiredis.h>
#include <hiredis/adapters/libev.h>

#include "junk/xsyslog.h"

struct rdc_node {
	unsigned num;

	pthread_mutex_t lock;

	uint32_t msghash;
	redisAsyncContext *ac;
	char *command;

	struct rdc_node *next;
	struct rdc *rdc;
};

#define RDC_LIMIT 10
struct rdc {
	struct ev_loop *loop;
	pthread_mutex_t lock;
	const char *addr;
	unsigned serial;
	/* общество количество подключений,
	 * количество активных подключейний,
	 * ограничение количества подключений
	 */
	unsigned c_count;
	unsigned c_inuse;
	unsigned c_limit;
	struct rdc_node *c;
};

void rdc_init(struct rdc *r, struct ev_loop *loop, const char *addr, size_t limit);
void rdc_destroy(struct rdc *r);

/* создание/захват подключения
 *
 * Если command != NULL, то автоматически выполняется
 * комманда при каждом переподключении (удобно для подписок)
 *
 * использовать va_list для комманды здесь не получится, ибо геморройно
 * сохранять значения для переподключения
 */
redisAsyncContext *rdc_acquire(struct rdc *r, char *command);

/*
 * освобождение подключения
 */
void rdc_release(struct redisAsyncContext *ac);

/* выполнение */
bool rdc_execute(struct rdc *r, const char *command, ...);

/*
 * проверить все подключения и переподключиться в случае необходимости
 */
void rdc_refresh(struct rdc *r);

#endif /* _RDC_1439466539_H_ */

