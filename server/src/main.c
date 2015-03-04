/* vim: ft=c ff=unix fenc=utf-8
 * file: main.c
 */
#include "main.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static unsigned int sev_ctx_seq = 0u;

void
client_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct sev_ctx *ptx = (struct sev_ctx*)w;
	if (revents & EV_READ) {
		if (!pthread_mutex_trylock(&ptx->utex)) {
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
		if (!pthread_mutex_trylock(&ptx->utex)) {
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

bool client_iterate(struct sev_ctx *, bool, void **);

void *
client_thread(void *ctx)
{
	struct sev_ctx *cev = (struct sev_ctx*)ctx;
	struct timespec tv;
	void *p = NULL;
	while (true) {
		if (!client_iterate(cev, false, &p)) {
			xsyslog(LOG_DEBUG, "client %p thread[%p] leave thread",
					(void*)cev, (void*)cev->thread);
			break;
		}
		/* шоп не жрало цпу, делаем слипы до евента */
		pthread_mutex_lock(&cev->utex);
		tv.tv_sec = 0;
		tv.tv_nsec = 100;
		pthread_cond_timedwait(&cev->ond, &cev->utex, &tv);
		if (cev->action & SEV_ACTION_EXIT) {
			xsyslog(LOG_DEBUG, "client %p thread[%p] exit at event",
					(void*)cev, (void*)cev->thread);
			pthread_mutex_unlock(&cev->utex);
			break;
		}
		pthread_mutex_unlock(&cev->utex);
	}
	client_iterate(cev, true, &p);
	cev->isfree = true;
	return NULL;
}

struct sev_ctx *
client_free(struct sev_ctx *cev)
{
	xsyslog(LOG_INFO, "client free(%p, fd#%d)", (void*)cev, cev->fd);

	/* send event */
	if (cev->thread) {
		void *retval;
		xsyslog(LOG_INFO, "client free(%p, fd#%d) wait thread[%p]",
				(void*)cev, cev->fd, (void*)cev->thread);
		pthread_mutex_lock(&cev->utex);
		cev->action |= SEV_ACTION_EXIT;
		pthread_cond_broadcast(&cev->ond);
		pthread_mutex_unlock(&cev->utex);
		xsyslog(LOG_DEBUG, "client free(%p, fd#%d) join thread[%p]",
				(void*)cev, cev->fd, (void*)cev->thread);
		pthread_join(cev->thread, &retval);
		ev_io_stop(cev->evloop, &cev->evio);
		xsyslog(LOG_INFO, "client free(%p, fd#%d) exit thread[%p]",
				(void*)cev, cev->fd, (void*)cev->thread);
	}

	pthread_cond_destroy(&cev->ond);
	pthread_mutex_destroy(&cev->utex);

	if (cev->fd != -1) {
		shutdown(cev->fd, SHUT_RDWR);
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] destroy fd#%d", (void*)cev, cev->fd);
#endif
		close(cev->fd);
		cev->fd = -1;
	}
	{
		struct sev_ctx *ocev = NULL;
		if (cev->prev) {
			cev->prev->next = cev->next;
			ocev = cev->prev;
		}
		if (cev->next) {
			cev->next->prev = cev->prev;
			if (!ocev)
				ocev = cev->next;
		}
		free(cev);
		return ocev;
	}
}

struct sev_ctx *
client_alloc(struct ev_loop *loop, int fd, struct sev_ctx *next)
{
	struct sev_ctx *cev;
	struct main *pain = (struct main*)ev_userdata(loop);
	cev = calloc(1, sizeof(struct sev_ctx));
	if (!cev) {
		xsyslog(LOG_WARNING, "client init(fd#%d) memory fail: %s",
				fd, strerror(errno));
		return NULL;
	}
	cev->fd = -1;

	xsyslog(LOG_INFO, "client init(%p, fd#%d) serial: %u",
			(void*)cev, fd, ++sev_ctx_seq);
	memset(cev, 0, sizeof(struct sev_ctx));
	pthread_cond_init(&cev->ond, NULL);
	pthread_mutex_init(&cev->utex, NULL);

	cev->serial = sev_ctx_seq;

	/* лок для того, что бы тред не попытался прочитать/писать в сокет
	 * до того, как ev_io будет проинициализировано
	 */
	pthread_mutex_lock(&cev->utex);

	if (pthread_create(&cev->thread, NULL, client_thread, (void*)cev)) {
		xsyslog(LOG_WARNING, "client init(%p, fd#%d) thread fail: %s",
				(void*)cev, cev->fd, strerror(errno));
		memset(&cev->thread, 0, sizeof(cev->thread));
		pthread_mutex_unlock(&cev->utex);
		client_free(cev);
		cev = NULL;
		return NULL;
	} else {
		xsyslog(LOG_INFO, "client init(%p, fd#%d) new thread[%p]",
				(void*)cev, fd, (void*)cev->thread);

		/* интеграция в список */
		if (next) {
			cev->next = next;
			if (next->prev) {
				next->prev->next = cev;
				cev->prev = next->prev;
			}
			xsyslog(LOG_DEBUG, "client init(%p, fd#%d) prev: %p, next: %p",
					(void*)cev, fd, (void*)cev->prev, (void*)cev->next);
		}

		/* инициализация вторичных значений */
		cev->fd = fd;
		cev->evloop = loop;
		cev->alarm = &pain->alarm;

		ev_io_init(&cev->evio, client_cb, fd, EV_NONE);
		ev_io_start(cev->evloop, &cev->evio);
	}

	pthread_mutex_unlock(&cev->utex);
	return cev;
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
	ssize_t re = 0;
	pthread_mutex_lock(&ptx->utex);
	/* update ev info */
	if (!(ptx->evio.events & EV_WRITE)) {
		ev_io_stop(ptx->evloop, &ptx->evio);
		ev_io_set(&ptx->evio, ptx->fd, ptx->evio.events | EV_WRITE);
		ev_io_start(ptx->evloop, &ptx->evio);
		ev_async_send(ptx->evloop, ptx->alarm);
	}
	/* wait signal, if flag not setted */
	if (!(ptx->action & SEV_ACTION_WRITE || ptx->action & SEV_ACTION_EXIT)) {
		/* if timeout exists, use timedwait */
		if (ptx->send_timeout) {
			struct timespec tv;
			tv.tv_sec = ptx->send_timeout;
			tv.tv_nsec = 0u;
			pthread_cond_timedwait(&ptx->ond, &ptx->utex, &tv);
		} else
			pthread_cond_wait(&ptx->ond, &ptx->utex);
	}
	/* read data */
	if (ptx->action & SEV_ACTION_WRITE) {
		/* zero value indicate as exception (broken pipe in non-bloking) */
		if (!(re = write(ptx->fd, (void*)buf, len)))
			re = -1;
		ptx->action &= ~SEV_ACTION_WRITE;
	}
	/* unset ev */
	pthread_mutex_unlock(&ptx->utex);
	return (int)re;
}

/* analog to sev_send */
int
sev_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct sev_ctx *ptx = (struct sev_ctx*)ctx;
	ssize_t re = 0;
	pthread_mutex_lock(&ptx->utex);
	if (!(ptx->evio.events & EV_READ)) {
		ev_io_stop(ptx->evloop, &ptx->evio);
		ev_io_set(&ptx->evio, ptx->fd, ptx->evio.events | EV_READ);
		ev_io_start(ptx->evloop, &ptx->evio);
		ev_async_send(ptx->evloop, ptx->alarm);
	}
	if (!(ptx->action & SEV_ACTION_READ || ptx->action & SEV_ACTION_EXIT))
	{
		if (ptx->recv_timeout) {
			struct timespec tv;
			tv.tv_sec = ptx->recv_timeout;
			tv.tv_nsec = 0u;
			pthread_cond_timedwait(&ptx->ond, &ptx->utex, &tv);
		} else
			pthread_cond_wait(&ptx->ond, &ptx->utex);
	}
	if (ptx->action & SEV_ACTION_READ) {
		if (!(re = read(ptx->fd, (void*)buf, len)))
			re = -1;
		ptx->action &= ~SEV_ACTION_READ;
	}
	pthread_mutex_unlock(&ptx->utex);
	return (int)re;
}

void
server_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct sev_ctx *ptx = NULL;
	struct sev_main *sev = (struct sev_main*)w;

	char xaddr[48];
	int sock;
	struct sockaddr_storage sa;
	socklen_t salen = sizeof(struct sockaddr_storage);
	if (revents & EV_READ) {
		sock = accept(sev->fd, (struct sockaddr*)&sa, &salen);
		if (sock == -1) {
			xsyslog(LOG_WARNING, "socket #%d client got away", sock);
			return;
		}
		saddr_char(xaddr, sizeof(xaddr), sa.ss_family, (struct sockaddr*)&sa);
		xsyslog(LOG_INFO, "accept(%s) -> fd#%d", xaddr, sock);

		ptx = client_alloc(loop, sock, sev->client);
		if (!ptx) {
			xsyslog(LOG_WARNING, "accept(%s, fd#%d) allocation failed",
					xaddr, sock);
			close(sock);
			return;
		}
		xsyslog(LOG_DEBUG, "accept(%s, fd#%d) client %p",
				xaddr, ptx->fd, (void*)ptx);
		sev->client = ptx;
	}
}

bool
server_bind(struct ev_loop *loop, struct sev_main *sev)
{
	int lval;
	int fd;

	char xaddr[SADDR_MIN];

	struct addrinfo *res = NULL;
	struct addrinfo *pres = NULL;
	struct addrinfo hints;

	/* останавливаем сокет, если был уже запущен */
	if (sev->fd != -1) {
		xsyslog(LOG_WARNING, "server bind(%p) -> rebind fd#%d",
				(void*)sev, sev->fd);
		close(sev->fd);
		ev_io_stop(loop, &sev->evio);
		sev->fd = -1;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	xsyslog(LOG_INFO, "server bind(%p) -> resolve '%s:%s'",
			(void*)sev, sev->host, sev->port);
	lval = getaddrinfo(sev->host, sev->port, &hints, &res);
	if (lval) {
		xsyslog(LOG_INFO, "server bind(%p) -> getaddrinfo() fail: %s",
				(void*)sev, gai_strerror(lval));
	}
	for (pres = res; pres != NULL; pres = pres->ai_next) {
		xaddr[0] = '\0';
		saddr_char(xaddr, sizeof(xaddr), pres->ai_family, pres->ai_addr);
		fd = socket(pres->ai_family, pres->ai_socktype, pres->ai_protocol);
		if (fd == -1) {
			xsyslog(LOG_WARNING, "server bind(%p) -> socket() fail: %s",
					(void*)sev, strerror(errno));
		} else if (bind(fd, pres->ai_addr, pres->ai_addrlen) == -1) {
			xsyslog(LOG_WARNING, "server bind(%p) -> bind() fail: %s, fd#%d",
					(void*)sev, strerror(errno), fd);
			close(fd);
		} else if (listen(fd, 32) == -1) {
			xsyslog(LOG_WARNING,
					"server bind(%p) -> listen() fail: %s, fd#%d",
					(void*)sev, strerror(errno), fd);
			close(fd);
		} else {
			xsyslog(LOG_INFO, "server bind(%p) -> entry in %s, fd#%d",
					(void*)sev, xaddr, fd);
			sev->fd = fd;
			ev_io_init(&sev->evio, server_cb, sev->fd, EV_READ);
			ev_io_start(loop, &sev->evio);
			break;
		}
	}
	if (res)
		freeaddrinfo(res);

	return (bool)(sev->fd != -1);
}

struct sev_main *
server_alloc(struct main *pain, char *address)
{
	struct sev_main *sev;

	char *port = NULL;
	sev = calloc(1, sizeof(struct sev_main));
	if (!sev) {
		xsyslog(LOG_ERR, "server init -> memory fail: %s",
				strerror(errno));
		return NULL;
	}
	sev->fd = -1;

	/* разбивка строки адреса на хост, порт и назначение их в структуру */
	if (!sev->host) {
		sev->host = strdup(address);
		if ((port = strchr(sev->host, ':')) != NULL) {
			*port = '\0';
			if (!sev->port) {
				sev->port = ++port;
			}
		}
	}

	/* внесение в общий список */
	if (pain->sev)
		pain->sev->prev = sev;
	sev->next = pain->sev;
	pain->sev = sev;

	xsyslog(LOG_INFO, "server init (%p) -> add entry point '%s'",
			(void*)sev, address);
	return sev;
}

/* return previous struct or next or NULL if no more,
 * must be called from main thread */
struct sev_main *
server_free(struct ev_loop *loop, struct sev_main *sev)
{
	xsyslog(LOG_INFO, "server free(%p) -> fd#%d", (void*)sev, sev->fd);
	if (sev->fd != -1) {
		ev_io_stop(loop, &sev->evio);
		close(sev->fd);
	}

	if (sev->host) {
		free(sev->host);
		sev->host = NULL;
		sev->port = NULL;
	}
	/* чистка клиентов */
	while (sev->client)
		sev->client = client_free(sev->client);
	/* финализация, выбираем следующую ноду и освобождаем текущую */
	{
		struct sev_main *osev = NULL;
		if (sev->prev) {
			sev->prev->next = sev->next;
			osev = sev->prev;
		}
		if (sev->next) {
			sev->next->prev = sev->prev;
			if (!osev)
				osev = sev->next;
		}
		if (osev)
			xsyslog(LOG_DEBUG, "server free(%p) -> next node: %p",
					(void*)sev, (void*)osev);
		else
			xsyslog(LOG_DEBUG, "server free(%p) -> last node",
					(void*)sev);
		free(sev);
		return osev;
	}
}

void
signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	xsyslog(LOG_INFO, "break");
	ev_break(loop, EVBREAK_ALL);
}

void
alarm_cb(struct ev_loop *loop, ev_async *w, int revents)
{

}

void
timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct main *pain = (struct main*)ev_userdata(loop);
	if (!pain)
		return;
	/* подчистка устаревших клиентских структур */
	{
		struct sev_main *sev_it = NULL;
		struct sev_ctx *cev_it = NULL;
		sev_it = pain->sev;
		if (!sev_it) {
			xsyslog(LOG_ERR, "watcher: empty server list");
			ev_break(loop, EVBREAK_ALL);
			return;
		} else if (sev_it->fd == -1) {
			/* и, немножко, серверных сокетов */
			server_bind(loop, sev_it);
		}
		if (sev_it->prev) {
			xsyslog(LOG_WARNING, "watcher: server %p has left node %p ",
					(void*)sev_it, (void*)sev_it->prev);
		}
		for (; sev_it; sev_it = sev_it->next) {
			if ((cev_it = sev_it->client) == NULL)
				continue;
			if (cev_it->prev)
				xsyslog(LOG_WARNING, "watcher: client %p has left node %p ",
						(void*)cev_it, (void*)cev_it->prev);
			if (cev_it->isfree) {
				if (cev_it == sev_it->client)
					sev_it->client = client_free(cev_it);
				else
					client_free(cev_it);
			}

		}
	}
}

int
main(int argc, char *argv[])
{
	struct ev_loop *loop;
	struct main pain;
	openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);
	xsyslog(LOG_INFO, "--- START ---");
	loop = EV_DEFAULT;
	{
		memset(&pain, 0, sizeof(struct main));
		ev_signal_init(&pain.sigint, signal_cb, SIGINT);
		ev_signal_start(loop, &pain.sigint);
		/* таймер на чистку всяких устаревших структур и прочего */
		ev_timer_init(&pain.watcher, timeout_cb, 1., 15.);
		ev_timer_start(loop, &pain.watcher);
		/* хреновинка для прерывания лупа */
		ev_async_init(&pain.alarm, alarm_cb);
		ev_async_start(loop, &pain.alarm);
		/* TODO: мультисокет */
		if (server_alloc(&pain, "0.0.0.0:5151")) {
			ev_set_userdata(loop, (void*)&pain);
			/* выход происходит при остановке всех evio в лупе */
			ev_run(loop, 0);
		}
		/* чистка серверных сокетов */
		while (pain.sev)
			pain.sev = server_free(loop, pain.sev);
		/* чистка клиентских сокетов */
		ev_signal_stop(loop, &pain.sigint);
		ev_timer_stop(loop, &pain.watcher);
		ev_async_stop(loop, &pain.alarm);
		ev_loop_destroy(loop);
		closelog();
	}
	xsyslog(LOG_INFO, "--- EXIT ---");
	return EXIT_SUCCESS;
}

