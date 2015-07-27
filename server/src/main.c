/* vim: ft=c ff=unix fenc=utf-8
 * file: main.c
 */
#include "main.h"
#include "junk/utils.h"
#include "simplepq/simplepq.h"
#include "client_iterate.h"

#include <curl/curl.h>
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
#include <sys/select.h>
#include <unistd.h>

static unsigned int sev_ctx_seq = 0u;

bool client_iterate(struct sev_ctx *, bool, void **);
void alarm_cb(struct ev_loop *loop, ev_async *w, int revents);
void client_cb(struct ev_loop *loop, ev_io *w, int revents);

void *
client_thread(void *ctx)
{
	struct sev_ctx *cev = (struct sev_ctx*)ctx;
	struct timespec tv;
	void *p = NULL;
	/* лок в самом начале нужен что бы структуры инициализировались
	 * нормально до старта самого треда
	 */
	pthread_mutex_lock(&cev->utex);
#ifdef __USE_GNU
	char thread_name[sizeof(uintptr_t) * 16 + 1];
	snprintf(thread_name, sizeof(thread_name), "client:%p", (void*)ctx);
	pthread_setname_np(pthread_self(), thread_name);
#endif
	pthread_mutex_unlock(&cev->utex);
	while (true) {
		if (!client_iterate(cev, false, &p)) {
			xsyslog(LOG_DEBUG, "client %p thread[%p] leave thread",
					(void*)cev, (void*)cev->thread);
			break;
		}
		/* если выставлен флаг быстрого прохода или есть необработанные
		 * данные в буфере чтения,
		 * то не засыпаем, снимаем флаг, делаем проверку и возвращаемся
		 * в цикл клиента
		 */
		if (cev->action & SEV_ACTION_FASTTEST) {
			cev->action &= ~SEV_ACTION_FASTTEST;
		} else if (cev->action & SEV_ACTION_DATA) {
			/* если образовались данные нужно побыстрей их прокинуть дальше */
		} else {
		/* шоп не жрало цпу, делаем слипы до евента */
			clock_gettime(CLOCK_REALTIME, &tv);
			pthread_mutex_lock(&cev->utex);
			tv.tv_sec += 1;
			tv.tv_nsec += 300;
			pthread_cond_timedwait(&cev->ond, &cev->utex, &tv);
		}
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
		pthread_cond_signal(&cev->ond);
		pthread_mutex_unlock(&cev->utex);
		xsyslog(LOG_DEBUG, "client free(%p, fd#%d) join thread[%p]",
				(void*)cev, cev->fd, (void*)cev->thread);
		pthread_join(cev->thread, &retval);
		xsyslog(LOG_INFO, "client free(%p, fd#%d) exit thread[%p]",
				(void*)cev, cev->fd, (void*)cev->thread);
	}

	pthread_cond_destroy(&cev->ond);
	pthread_mutex_destroy(&cev->utex);

	ev_async_stop(cev->evloop, (struct ev_async*)&cev->async);
	ev_io_stop(cev->evloop, (struct ev_io*)&cev->io);

	if (cev->fd != -1) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] destroy fd#%d", (void*)cev, cev->fd);
#endif
		shutdown(cev->fd, SHUT_RDWR);
		close(cev->fd);
		cev->fd = -1;
	}
	/* выгребание буферов */
	if (cev->recv.buf) {
		free(cev->recv.buf);
		cev->recv.buf = NULL;
		cev->recv.size = 0u;
#if DEEPDEBUG
		if (cev->recv.len)
			xsyslog(LOG_DEBUG, "client[%p] hash non-empty recv buffer "
					"(%"PRIuPTR" bytes)",
					(void*)cev, cev->recv.len);
#endif
		pthread_mutex_destroy(&cev->recv.lock);
	}
	if (cev->send.buf) {
		free(cev->send.buf);
		cev->send.buf = NULL;
		cev->send.size = 0u;
#if DEEPDEBUG
		if (cev->send.len)
			xsyslog(LOG_DEBUG, "client[%p] hash non-empty send buffer "
					"(%"PRIuPTR" bytes)",
					(void*)cev, cev->send.len);
#endif
		pthread_mutex_destroy(&cev->send.lock);
	}
	/* освобождение структуры клиента */
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

static inline struct sev_ctx *
client_alloc(struct ev_loop *loop, int fd, struct sev_ctx *next)
{
	struct sev_ctx *cev;
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
	/* сигналирование и поллинг
	 * сделать это нужно как можно раньше, похоже
	 * что если это делать после создания потока, в libev что-то ломается
	 */
	cev->async.cev = cev;
	ev_async_init((struct ev_async*)&cev->async, alarm_cb);
	ev_async_start(loop, (struct ev_async*)&cev->async);

	cev->io.cev = cev;
	ev_io_init((struct ev_io*)&cev->io, client_cb, fd, EV_NONE);
	ev_io_start(loop, (struct ev_io*)&cev->io);

	/* память под буфера */
	cev->recv.buf = calloc(1, SEV_RECV_BUF);
	cev->send.buf = calloc(1, SEV_SEND_BUF);
	cev->recv.size = SEV_RECV_BUF;
	cev->send.size = SEV_SEND_BUF;
	/* не получилось */
	if (!cev->recv.buf || !cev->send.buf) {
		xsyslog(LOG_WARNING, "client init(%p, fd#%d) "
				"alloc recv/send buffer failed",
				(void*)cev, fd);
		client_free(cev);
		return NULL;
	}
	pthread_mutex_init(&cev->recv.lock, NULL);
	pthread_mutex_init(&cev->send.lock, NULL);
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
	}
	pthread_mutex_unlock(&cev->utex);
	return cev;
}

/* call in thread */
int
sev_send(void *ctx, const unsigned char *buf, size_t size)
{
	struct sev_ctx *cev = (struct sev_ctx*)ctx;
	register size_t len;

	pthread_mutex_lock(&cev->send.lock);
	/* выходим сразу если ошибка */
	if (cev->send.eof) {
		pthread_mutex_unlock(&cev->send.lock);
		return -1;
	}

	/* подсчёт объёмов копирования
	 * данные должны вместиться в буфер отправки
	 */
	len = cev->send.size - cev->send.len;
	len = MIN(size, len);
	if (len) {
		memcpy(&cev->send.buf[cev->send.len], buf, len);
		cev->send.len += len;
		if (!(((struct ev_io*)&cev->io)->events & EV_WRITE)) {
			pthread_mutex_lock(&cev->utex);
			cev->action |= SEV_ACTION_WRITE;
			pthread_mutex_unlock(&cev->utex);
			ev_async_send(cev->evloop, (struct ev_async*)&cev->async);
		}
	}
	pthread_mutex_unlock(&cev->send.lock);
	return (int)len;
}

/* analog to sev_send */
int
sev_recv(void *ctx, unsigned char *buf, size_t size)
{
	struct sev_ctx *cev = (struct sev_ctx*)ctx;
	int re = 0;
	size_t len = 0u;

	pthread_mutex_lock(&cev->recv.lock);
	if (cev->recv.eof) {
		re = -1;
	} else {
		len = MIN(size, cev->recv.len);
		if (len > 0u) {
			/* копируем буфер и снова переносим оставшийся кусок с memmove
			 * FIXME: пристроить ring buffer
			 */
			memcpy(buf, cev->recv.buf, len);
			if ((cev->recv.len -= len) != 0u) {
				if (!memmove(cev->recv.buf,
							&cev->recv.buf[len], cev->recv.len)) {
					/* протокол поехал, клиентский поток это заметит
					 * и должен завершить общение, но известить об этом нужно
					 */
					xsyslog(LOG_WARNING,
							"client[%p] got memory error at read: %s",
							(void*)cev, strerror(errno));
				}
			} else {
				/* нужно сбросить флажок что есть данные */
				cev->action &= ~SEV_ACTION_DATA;
#if DEEPDEBUG
				memset(cev->recv.buf, 0, cev->recv.size);
#endif
			}
		}
	}

	if (len == 0u) {
		/* буфер пустой, нужно попросить ещё, если мы не в очереди */
		if (!(cev->io.e.io.events & EV_READ)) {
			pthread_mutex_lock(&cev->utex);
			cev->action |= SEV_ACTION_READ;
			pthread_mutex_unlock(&cev->utex);
			ev_async_send(cev->evloop, (struct ev_async*)&cev->async);
		}
	}
	pthread_mutex_unlock(&cev->recv.lock);
	return (re == -1) ? re : (int)len;
}

void
server_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct sev_ctx *ptx = NULL;
	struct sev_main *sev = (struct sev_main*)w;

	char xaddr[48];
	int sock;
	struct sockaddr_storage sa = {0};
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
			shutdown(sock, SHUT_RDWR);
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
		shutdown(sev->fd, SHUT_RDWR);
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
		shutdown(sev->fd, SHUT_RDWR);
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
signal_ignore_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
}

void
signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	xsyslog(LOG_INFO, "break");
	ev_break(loop, EVBREAK_ALL);
}

/* славливаем сигнал от клиента,
 * помещаем его в очередь/извлекаем из очереди
 */
void
alarm_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	struct sev_ctx *cev;
	struct ev_io *evio;
	int actions = 0;

	cev = ((struct evptr*)w)->cev;

	pthread_mutex_lock(&cev->utex);
	evio = (struct ev_io*)&cev->io;
	if (cev->action & SEV_ACTION_READ) {
		cev->action &= ~SEV_ACTION_READ;
		if (evio->events & EV_READ) {
			/* ерунда какая-то */
			xsyslog(LOG_INFO, "client[%p] wtf: already in read queue",
					(void*)cev);

		} else {
			actions |= EV_READ;
		}
	}
	if (cev->action & SEV_ACTION_WRITE) {
		cev->action &= ~SEV_ACTION_WRITE;
		if (evio->events & EV_WRITE) {
			xsyslog(LOG_INFO, "client[%p] wtf: already in write queue",
					(void*)cev);
		} else {
			actions |= EV_WRITE;
		}
	}
	pthread_mutex_unlock(&cev->utex);
	/* назначение событий */
	if (actions) {
		ev_io_stop(loop, evio);
		ev_io_set(evio, evio->fd, evio->events | actions);
		ev_io_start(loop, evio);
	}
}

static inline void
_client_cb_read(struct ev_loop *loop, struct ev_io *w, struct sev_ctx *cev)
{
	register size_t len;
	register ssize_t lval = 0;

	pthread_mutex_lock(&cev->recv.lock);
	/* лочим, подбираем размер, анлочим */
	len = cev->recv.size - cev->recv.len;
	if (len > 0u) {
		lval = read(w->fd, &cev->recv.buf[cev->recv.len], len);
		if (lval <= 0) {
			/* если получили ошибку или нисколько из сокета,
			 * значит завершаемся
			 */
			cev->recv.eof = true;
		} else {
			/* иначе дёргаем счётчик полученных байт */
			cev->recv.len += lval;
		}
	}
	if (lval <= 0) {
		/* если записывать некуда (lval == 0 && len == 0)
		 * или read() ушёл с ошибкой
		 * то прекращаем обработку на чтение данного ивента
		 */
		ev_io_stop(loop, w);
		ev_io_set(w, w->fd, w->events & ~EV_READ);
		ev_io_start(loop, w);
	}
	/* нужно дёрнуть тред клиента
	 * и поставить флажок что информация прибыла
	 */
	pthread_mutex_lock(&cev->utex);
	if (lval > 0)
		cev->action |= SEV_ACTION_DATA;
	pthread_cond_broadcast(&cev->ond);
	pthread_mutex_unlock(&cev->utex);
	pthread_mutex_unlock(&cev->recv.lock);
}

static inline void
_client_cb_write(struct ev_loop *loop, struct ev_io *w, struct sev_ctx *cev)
{
	register ssize_t lval = 0;
	/* нужно делать trylock, но тогда это приведёт к сильному
	 * отжиранию процеесорного времени, если обработка буфера
	 * задержится в потоке-клиенте
	 * а так может тормознуться весь процесс чтения
	 *
	 * можно сделать на двух буферах, как поток клиента читает из своего буфера
	 * сервер пишет во второй буфер, после чего они сменяются.
	 * Но тогда непонятно что будет с очерёдностью получаемой информации
	 */
	pthread_mutex_lock(&cev->send.lock);
	if (cev->send.len != 0u) {
		lval = write(w->fd, cev->send.buf, cev->send.len);
		if (lval <= 0) {
			/* ошибка при записи, выход */
			cev->send.eof = true;
		} else {
			/* перемещаем данные в начало буфера
			 * FIXME: использовать memmove жирно, пристроить ring buffer
			 */
			cev->send.len -= lval;
			if (!memmove(cev->send.buf, &cev->send.buf[lval], cev->send.len)) {
				/* что делать в этом случае не совсем понятно,
				 * но протокол поехал и клиент об этом известит
				 */
				xsyslog(LOG_WARNING,
						"client[%p] got memory error at write: %s",
						(void*)cev, strerror(errno));
			}
		}
	}

	/* двойная провека на случай,
	 * если после записи в буфере ничего не останется
	 */
	if (cev->send.len == 0u || lval <= 0) {
		/* отправлять нечего или произошла ошибка, вынимаем из очереди */
		ev_io_stop(loop, w);
		ev_io_set(w, w->fd, w->events & ~EV_WRITE);
		ev_io_start(loop, w);
	}
	pthread_mutex_unlock(&cev->send.lock);
}

void
client_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct sev_ctx *cev;
	cev = ((struct evptr*)w)->cev;

	if (revents & EV_READ)
		_client_cb_read(loop, w, cev);
	if (revents & EV_WRITE)
		_client_cb_write(loop, w, cev);
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
		}
		/* хуита */
		if (sev_it->prev) {
			xsyslog(LOG_WARNING, "watcher: server %p has left node %p ",
					(void*)sev_it, (void*)sev_it->prev);
		}
		/* обход узлов */
		for (; sev_it; sev_it = sev_it->next) {
			/* ребиндим сокет, если не забинден */
			if (sev_it->fd == -1) {
				server_bind(loop, sev_it);
			}
			/* чистка клиентов */
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

const char *const
sev_version_string()
{
#if GIT_VERSION
# if SQLSTRUCTVER
	return "Version: " S(GIT_VERSION) ", SQL " S(SQLSTRUCTVER) "\n";
# else
	return "Version: " S(GIT_VERSION) "\n";
# endif
#else
# if SQLSTRUCTVER
	return ("Version: unknown, SQL " S(SQLSTRUCTVER) "\n";
# else
	return "Version: " S(GIT_VERSION) ", SQL " S(SQLSTRUCTVER) "\n";
# endif
#endif
}

static bool
check_args(int argc, char **argv)
{
	if (argc > 1) {
		if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")) {
			printf(sev_version_string());
		}
		return true;
	}
	return false;
}

int
main(int argc, char *argv[])
{
	bool _r;
	struct ev_loop *loop;
	struct main pain;
	/* base configuration */
	cfg_t *cfg;
	char *bindline = strdup("0.0.0.0:5151");
	char *pg_connstr = strdup("dbname = fepserver");
	/* */
	char cfgpath[PATH_MAX + 1];
	cfg_opt_t opt[] = {
		CFG_SIMPLE_STR("bind", &bindline),
		CFG_SIMPLE_STR("pg_connstr", &pg_connstr),
		CFG_END()
	};

	if (check_args(argc, argv))
		return EXIT_SUCCESS;

	curl_global_init(CURL_GLOBAL_ALL);
	openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);
	xsyslog(LOG_INFO, "--- START ---");

	snprintf(cfgpath, PATH_MAX, "%s.conf", argv[0]);
	xsyslog(LOG_INFO, "read config: %s", cfgpath);
	cfg = cfg_init(opt, 0);
	cfg_parse(cfg, cfgpath);

	xsyslog(LOG_DEBUG, "pg: \"%s\"", pg_connstr);
	spq_open(10, pg_connstr);
	/* всякая ерунда с бд */
	if ((_r = spq_create_tables()) != false) {
		loop = EV_DEFAULT;
		memset(&pain, 0, sizeof(struct main));
		client_threads_prealloc();
		ev_signal_init(&pain.sigint, signal_cb, SIGINT);
		ev_signal_start(loop, &pain.sigint);
		ev_signal_init(&pain.sigpipe, signal_ignore_cb, SIGPIPE);
		ev_signal_start(loop, &pain.sigpipe);
		/* таймер на чистку всяких устаревших структур и прочего */
		ev_timer_init(&pain.watcher, timeout_cb, 1., 15.);
		ev_timer_start(loop, &pain.watcher);
		/* мультисокет */
		{
			char *_x = strdup(bindline);
			char *_b = _x;
			char *_e = NULL;
			for (; _b; _b = _e) {
				if ((_e = strchr(_b, ',')) != NULL) {
					*_e = '\0';
					_e++;
				}
				server_alloc(&pain, _b);
			}
			free(_x);
		}
		if (pain.sev) {
			ev_set_userdata(loop, (void*)&pain);
			/* выход происходит при остановке всех evio в лупе */
			ev_run(loop, 0);
			/* чистка серверных сокетов */
			while (pain.sev)
				pain.sev = server_free(loop, pain.sev);
		} else {
			_r = false;
		}
		/* чистка клиентских сокетов */
		ev_signal_stop(loop, &pain.sigint);
		ev_timer_stop(loop, &pain.watcher);
		ev_loop_destroy(loop);
		client_threads_bye();
	}
	spq_close();
	closelog();
	xsyslog(LOG_INFO, "--- EXIT ---");

	cfg_free(cfg);
	free(bindline);
	free(pg_connstr);

	curl_global_cleanup();

	if (_r)
		return EXIT_SUCCESS;
	return EXIT_FAILURE;
}

