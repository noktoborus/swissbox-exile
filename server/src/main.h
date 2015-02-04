/* vim: ft=c ff=unix fenc=utf-8
 * file: main.h
 */
#ifndef _MAIN_1422961154_H_
#define _MAIN_1422961154_H_
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <ev.h>
#include "xsyslog.h"

#define SEV_NAME_LEN_C 128
#define SEV_NAME_LEN_S 64
/* client socket */
enum cev_state
{
	CEV_FIRST = 0,
	CEV_AUTH,
	CEV_MORE

};

#define SEV_ACTION_READ 1
#define SEV_ACTION_WRITE 2
#define SEV_ACTION_EXIT 4
struct sev_ctx
{
	/* io */
	ev_io evio;
	struct ev_loop *evloop;
	uint8_t action;
	pthread_mutex_t utex;
	pthread_cond_t ond;
	pthread_t thread;

	int fd;

	bool isfree;

	unsigned int serial;

	struct sev_ctx *prev;
	struct sev_ctx *next;
	/* */
	enum cev_state state;
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
	/* server list */
	struct sev_main *sev;
};


/*
 * void *ctx == struct sev_ctx
 */
int sev_send(void *ctx, const unsigned char *buf, size_t len);
int sev_recv(void *ctx, unsigned char *buf, size_t len);

#endif /* _MAIN_1422961154_H_ */

