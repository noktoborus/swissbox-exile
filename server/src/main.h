/* vim: ft=c ff=unix fenc=utf-8
 * file: main.h
 */
#ifndef _MAIN_1422961154_H_
#define _MAIN_1422961154_H_

#include "xsyslog.h"
#include "proto/fep.pb-c.h"

#include <ev.h>
#include <stdbool.h>
#include <pthread.h>

#define SEV_ACTION_READ 1
#define SEV_ACTION_WRITE 2
#define SEV_ACTION_EXIT 4
struct sev_ctx
{
	/* io */
	ev_io evio;
	struct ev_loop *evloop;
	struct ev_async *alarm;
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
struct main
{
	ev_signal sigint;
	ev_timer watcher;
	ev_async alarm;
	/* server list */
	struct sev_main *sev;
};

struct idlist
{
	uint64_t id;

	struct timeval born;

	void *data;

	struct idlist *left;
	struct idlist *right;
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

/* добавляет новую структу слева от *left */
struct idlist *idlist_alloc(uint64_t id, struct idlist *left);
/* ищет структуру с указанным id, начиная от left в обе стороны */
struct idlist *idlist_find(uint64_t id, struct idlist *left, direction_t dir);
/* освобождает память по указателю и возвращает левую или правую структуру */
struct idlist *idlist_free(struct idlist *idw);
/* поиск устарелых структур, на более чем seconds */
struct idlist *idlist_find_obs(struct idlist *left, time_t seconds, direction_t dir);

/*
 * void *ctx == struct sev_ctx
 * вовзращает 0, если время ожидания ответа было достигнуто
 * и -1 если произошла ошибка при чтении
 */
int sev_send(void *ctx, const unsigned char *buf, size_t len);
int sev_recv(void *ctx, unsigned char *buf, size_t len);

#endif /* _MAIN_1422961154_H_ */

