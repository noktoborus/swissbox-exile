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

enum rdc_node_mode {
	RDC_NORMAL = 0,
	RDC_SUBSCRIBE = 1,
	RDC_PERIODIC = 2
};

struct rdc_node {
	unsigned num;

	enum rdc_node_mode mode;

	pthread_mutex_t lock;

	uint32_t msghash;
	redisAsyncContext *ac;

	char *command;
	redisCallbackFn *cb;
	void *cb_data;

	struct rdc_node *next;
	struct rdc *rdc;
};

#define RDC_LIMIT 10
struct rdc {
	struct ev_loop *loop;
	pthread_mutex_t lock;
	const char *addr;
	unsigned serial;
	/* общество количество подключений */
	unsigned c_count;
	/* количество активных подключейний */
	unsigned c_inuse;
	/* количество подписок */
	unsigned c_back;
	/* ограничение количества подключений */
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
redisAsyncContext *rdc_acquire(struct rdc *r);

/*
 * освобождение подключения
 */
void rdc_release(struct redisAsyncContext *ac);

/* выполнение */

/* подписка на канал/каналы (SUBSCRIBE) */
bool rdc_subscribe(struct rdc *r, redisCallbackFn *cb, void *priv,
		const char *command);
/* переодическая подписка на списки (BLPOP/BRPOP) */
bool rdc_exec_period(struct rdc *r, redisCallbackFn *cb, void *priv,
		const char *command);
/* одиночные комманды (LPOP/LPUSH/PUBLISH/...)
 */
bool rdc_exec_once(struct rdc *r, redisCallbackFn *cb, void *priv,
		const char *command, ...);

/*
 * проверить все подключения и переподключиться в случае необходимости
 */
void rdc_refresh(struct rdc *r);

#endif /* _RDC_1439466539_H_ */

