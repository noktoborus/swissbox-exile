/* vim: ft=c ff=unix fenc=utf-8
 * file: main.h
 */
#ifndef _MAIN_1422961154_H_
#define _MAIN_1422961154_H_

#include "list.h"
#include "junk/xsyslog.h"
#include "junk/almsg.h"
#include "proto/fep.pb-c.h"

#include <hiredis/hiredis.h>
#include <hiredis/adapters/libev.h>

#include <confuse.h>

#include <ev.h>
#include <stdbool.h>
#include <pthread.h>

struct evptr {
	union {
		struct ev_io io;
		struct ev_async async;
	} e;
	struct sev_ctx *cev;
};

/* по 1МБ на буфер */
#define SEV_RECV_BUF 1024 * 1024
#define SEV_SEND_BUF 1024 * 1024

#define SEV_ACTION_READ 1
#define SEV_ACTION_WRITE 2
#define SEV_ACTION_EXIT 4
#define SEV_ACTION_FASTTEST 8
#define SEV_ACTION_DATA 16
struct sev_ctx
{
	/* io */
	struct ev_loop *evloop;
	struct evptr io;
	struct evptr async;

	struct { /* буфер чтения */
		pthread_mutex_t lock;
		uint8_t *buf;
		size_t size; /* размер буфера */
		size_t len; /* длина данных в буфере */
		bool eof;
	} recv;

	struct { /* буфер записи */
		pthread_mutex_t lock;
		uint8_t *buf;
		size_t size;
		size_t len;
		bool eof;
	} send;

	uint8_t action;
	pthread_mutex_t utex;
	pthread_cond_t ond;
	pthread_t thread;

	time_t recv_timeout;
	time_t send_timeout;

	int fd;

	bool isfree;

	unsigned int serial;

	struct sev_ctx *prev;
	struct sev_ctx *next;
};

/* server socket */
struct sev_main
{
	ev_io evio;

	int fd;

	char *host;
	char *port;

	struct sev_ctx *client;

	struct sev_main *prev;
	struct sev_main *next;
};

/* olo */
struct redis_c {
	size_t self;
	uint32_t msghash;
	redisAsyncContext *ac;
	bool connected;

	pthread_mutex_t x;

	struct main *pain;
};

#define	REDIS_C_MAX 2
struct main
{
	ev_signal sigint;
	ev_signal sigpipe;
	ev_timer watcher;
	ev_async alarm;

	/* подключение к редису
	 * нулевое подключение используется для подписок (SUBSCRIBE)
	 */
	struct redis_c rs[REDIS_C_MAX];
	pthread_cond_t rs_wait;
	pthread_mutex_t rs_lock;
	size_t rs_awaits;

	/* server list */
	struct sev_main *sev;

	struct {
		char *name;
		char *redis_chan;
	} options;

};

typedef enum direction
{
	/* в любую сторону, нужно осторожно использовать в циклах */
	DANY = 0,
	/* только в правую сторону */
	DRIGHT,
	/* только в левую сторону */
	DLEFT
} direction_t;

/*
 * void *ctx == struct sev_ctx
 * вовзращает 0, если время ожидания ответа было достигнуто
 * и -1 если произошла ошибка при чтении
 */
int sev_send(void *ctx, const unsigned char *buf, size_t len);
int sev_recv(void *ctx, unsigned char *buf, size_t len);

/* */
bool redis_t(struct main *pain, const char *cmd, const char *ch,
		const char *data, size_t size);
void almsg2redis(struct main *pain, const char *cmd, const char *chan,
		struct almsg_parser *alm);

/* информации о версии */
const char *const sev_version_string();

#endif /* _MAIN_1422961154_H_ */

