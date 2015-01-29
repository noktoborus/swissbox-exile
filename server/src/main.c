/* vim: ft=c ff=unix fenc=utf-8
 * file: main.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <signal.h>
#include <pthread.h>
#include <ev.h>

#include "xsyslog.h"

static unsigned int sev_ctx_seq = 0u;

#define SEV_NAME_LEN 128
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

	int fd;


	char name[SEV_NAME_LEN];
	unsigned int serial;

	/* */
};

void
sev_ctx_init(struct sev_ctx *ctx, char *name)
{
	memset(ctx, 0, sizeof(struct sev_ctx));
	if (name)
		strncpy(ctx->name, name, SEV_NAME_LEN);
	pthread_cond_init(&ctx->ond, NULL);
	pthread_mutex_init(&ctx->utex, NULL);

	ctx->serial = ++sev_ctx_seq;
}

void
sev_ctx_detroy(struct sev_ctx *ctx)
{
	pthread_cond_destroy(&ctx->ond);
	pthread_mutex_destroy(&ctx->utex);
	memset(ctx, 0, sizeof(struct sev_ctx));
}

void
server_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	int sock;
	socklen_t slen;
	struct sockaddr_storage stor;
	/* TODO: */
	if (revents & EV_READ) {
	}
}

void
client_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct sev_ctx *ptx = (struct sev_ctx*)w;
	if (revents & EV_READ) {
		if (pthread_mutex_trylock(&ptx->utex)) {
			if (ptx->action & SEV_ACTION_READ) {
				/* unset event */
				ev_io_stop(loop, &ptx->evio);
				ev_io_set(&ptx->evio, ptx->fd, ptx->evio.events & ~EV_READ);
				ev_io_start(loop, &ptx->evio);
				pthread_mutex_unlock(&ptx->utex);
			}
			/* notify to thread */
			ptx->action |= SEV_ACTION_READ;
			pthread_cond_broadcast(&ptx->ond);
			pthread_mutex_unlock(&ptx->utex);
		}
	}

	if (revents & EV_WRITE) {
		if (pthread_mutex_trylock(&ptx->utex)) {
			if (ptx->action & SEV_ACTION_WRITE) {
				ev_io_stop(loop, &ptx->evio);
				ev_io_set(&ptx->evio, ptx->fd, ptx->evio.events & ~EV_WRITE);
				ev_io_start(loop, &ptx->evio);
			}
			ptx->action |= SEV_ACTION_WRITE;
			pthread_cond_broadcast(&ptx->ond);
			pthread_mutex_unlock(&ptx->utex);
		}
	}
}

/* call in thread */
int
sev_send(void *ctx, const unsigned char *buf, size_t len)
{
	/* 1. lock
	 * 2. wait signal
	 * 3. send
	 * */
	struct sev_ctx *ptx = (struct sev_ctx*)ctx;
	ssize_t re = -1;
	pthread_mutex_lock(&ptx->utex);
	/* update ev info */
	if (!(ptx->evio.events & EV_WRITE)) {
		ev_io_stop(ptx->evloop, &ptx->evio);
		ev_io_set(&ptx->evio, ptx->fd, ptx->evio.events & ~EV_WRITE);
		ev_io_start(ptx->evloop, &ptx->evio);
	}
	/* wait signal */
	if (!(ptx->action & SEV_ACTION_WRITE || ptx->action & SEV_ACTION_EXIT))
		pthread_cond_wait(&ptx->ond, &ptx->utex);
	/* read data */
	if (ptx->action & SEV_ACTION_WRITE) {
		re = write(ptx->fd, (void*)buf, len);
		ptx->action &= ~SEV_ACTION_WRITE;
	}
	/* unset ev */
	pthread_mutex_unlock(&ptx->utex);
	return (int)re;
}

int
sev_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct sev_ctx *ptx = (struct sev_ctx*)ctx;
	ssize_t re = -1;
	pthread_mutex_lock(&ptx->utex);
	if (!(ptx->evio.events & EV_READ)) {
		ev_io_stop(ptx->evloop, &ptx->evio);
		ev_io_set(&ptx->evio, ptx->fd, ptx->evio.events & ~EV_READ);
		ev_io_start(ptx->evloop, &ptx->evio);
	}
	if (!(ptx->action & SEV_ACTION_READ || ptx->action & SEV_ACTION_EXIT))
		pthread_cond_wait(&ptx->ond, &ptx->utex);
	if (ptx->action & SEV_ACTION_READ) {
		re = read(ptx->fd, (void*)buf, len);
		ptx->action &= ~SEV_ACTION_READ;
	}
	pthread_mutex_unlock(&ptx->utex);
	return (int)re;
}

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *thread(void *p)
{
	char c = *(char *)p;
	printf("S S %c\n", c);
	printf("S 1 %c\n", c);
	pthread_mutex_lock(&mutex);
	printf("S 2 %c\n", c);
	pthread_cond_wait(&cond, &mutex);
	printf("S 3 %c\n", c);
	pthread_mutex_unlock(&mutex);
	printf("S 4 %c\n", c);
	pthread_mutex_destroy(&mutex);
	printf("S E %c\n", c);
	return NULL;
}

void sig(int signo)
{
	printf("W 1 %d\n", signo);
	pthread_mutex_lock(&mutex);
	printf("W 2 %d\n", signo);
	pthread_cond_broadcast(&cond);
	printf("W 3 %d\n", signo);
	pthread_mutex_unlock(&mutex);
	printf("W 4 %d\n", signo);
}

int
main(int argc, char *argv[])
{
	pthread_t threa;
	pthread_t threb;
	void *res;
	/*
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	*/
	openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);
	signal(SIGINT, sig);
	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);
	sig(0);
	pthread_create(&threa, NULL, &thread, (void*)"A");
	pthread_create(&threb, NULL, &thread, (void*)"B");
	pthread_join(threa, &res);
	pthread_join(threb, &res);
	closelog();
	return EXIT_SUCCESS;
}

