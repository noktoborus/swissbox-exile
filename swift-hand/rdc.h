/* vim: ft=c ff=unix fenc=utf-8
 * file: rdc.h
 */
#ifndef _RDC_1439466539_H_
#define _RDC_1439466539_H_
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <hiredis/hiredis.h>
#include <hiredis/adapters/libev.h>

#include "junk/xsyslog.h"

struct rdc_node {
	redisAsyncContext *ac;
	char *command;
	struct rdc_node *next;
};

#define RDC_LIMIT 10
struct rdc {

	/* общество количество подключений,
	 * количество активных подключейний,
	 * ограничение количества подключений
	 */
	size_t c_count;
	size_t c_active;
	size_t c_limit;
	struct rdc_node *c;
};

void rdc_init(struct rdc *r, size_t limit);
void rdc_destroy(struct rdc *r);

/* создание/захват подключения
 *
 * Если command != NULL, то автоматически выполняется
 * комманда при каждом переподключении (удобно для подписок)
 */
redisAsyncContext *rdc_acquire(struct rdc *r, char *command);

/*
 * освобождение подключения
 */
void rdc_release(struct redisAsyncContext *ac);

/*
 * проверить все подключения и переподключиться в случае необходимости
 */
void rdc_refresh(struct rdc *r);

#endif /* _RDC_1439466539_H_ */

