/* vim: ft=c ff=unix fenc=utf-8
 * file: main.c
 */
#include "main.h"
#include "junk/utils.h"
#include "simplepq/simplepq.h"
#include "client_iterate.h"

#include <pwd.h>
#include <grp.h>

#include <libgen.h>
#include <sys/utsname.h>
#include <curl/curl.h>
#include <arpa/inet.h>
#include <fcntl.h>
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

#include "packet.h"

static unsigned int sev_ctx_seq = 0u;

bool redis_process(struct redis_c *rds, const char *data, size_t size);

void
client_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct sev_ctx *cev = ev_userdata(loop);

	if (!client_iterate(cev, cev->p)) {
		ev_break(loop, EVBREAK_ALL);
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] thread[%p] exit in timer",
				cev->serial, (void*)cev->thread);
	}
}

void
client_alarm_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	bool fast = false;
	bool queue = false;

	struct sev_ctx *cev = ev_userdata(loop);

	/* получение состояний */
	pthread_mutex_lock(&cev->cev_lock);
	if (cev->action & SEV_ACTION_EXIT) {
		/* завершение работы потока */
		ev_break(loop, EVBREAK_ALL);
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] thread[%p] exit at event",
				cev->serial, (void*)cev->thread);
	} /* else if (cev->action & SEV_ACTION_INPUT) {
		cev->action &= ~SEV_ACTION_INPUT;
		queue = true;
	} */ else {
		/* пришло событие на сокеты */
		fast = true;
	}
	pthread_mutex_unlock(&cev->cev_lock);


	if (fast) {
		if (!client_iterate(cev, cev->p)) {
			ev_break(loop, EVBREAK_ALL);
			xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] thread[%p] exit in alarm",
					cev->serial, (void*)cev->thread);
		}
	}

	if (queue) {
		client_bus_input(cev, cev->p);
	}
}

static inline void
client_io_read(struct ev_loop *loop, struct ev_io *w, struct sev_ctx *cev)
{
	register size_t len;
	register ssize_t lval = 0;

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
	if (lval > 0) {
		ev_async_send(loop, &cev->async);
	}
}

static inline void
client_io_write(struct ev_loop *loop, struct ev_io *w, struct sev_ctx *cev)
{
	register ssize_t lval = 0;

	if (cev->send.len != 0u) {
		lval = write(w->fd, cev->send.buf, cev->send.len);
		if (lval <= 0) {
			/* ошибка при записи, выход */
			cev->send.eof = true;
		} else {
			/* перемещаем данные в начало буфера
			 * FIXME: использовать memmove жирно, пристроить ring buffer
			 * FIXME: или не позволять пихать в буфер, пока не освободится
			 */
			cev->send.len -= lval;
			if (!memmove(cev->send.buf, &cev->send.buf[lval], cev->send.len)) {
				/* что делать в этом случае не совсем понятно,
				 * но протокол поехал и клиент об этом известит
				 */
				xsyslog(LOG_WARNING,
						"client[%"SEV_LOG"] got memory error at write: %s",
						cev->serial, strerror(errno));
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
		/* и заодно извещаем что информация убыла
		 * FIXME: ещё не нужно, т.к. буфер не блокируется
		ev_async_send(loop, &cev->async);
		*/
	}
}

void
client_io_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct sev_ctx *cev = ev_userdata(loop);

	if (revents & EV_READ)
		client_io_read(loop, w, cev);
	if (revents & EV_WRITE)
		client_io_write(loop, w, cev);
}

void *
client_main(struct sev_ctx *cev)
{
	/* регистрация себя */
	ev_set_userdata(cev->loop, (void*)cev);

	/* регистрация событий */
	ev_io_init(&cev->io, client_io_cb, cev->fd, EV_NONE);
	ev_async_init(&cev->async, client_alarm_cb);
	ev_timer_init(&cev->timer, client_timeout_cb, 0., 1.);

	ev_io_start(cev->loop, &cev->io);
	ev_async_start(cev->loop, &cev->async);
	ev_timer_start(cev->loop, &cev->timer);

	/* запуск цикла */
	cev->p = client_begin(cev);
	ev_run(cev->loop, 0);
	client_end(cev, cev->p);

	/* чистка */
	ev_io_stop(cev->loop, &cev->io);
	ev_async_stop(cev->loop, &cev->async);
	ev_timer_stop(cev->loop, &cev->timer);

	cev->isfree = true;
	return NULL;
}

struct sev_ctx *
client_free(struct sev_ctx *cev, bool nolock)
{
	struct sev_ctx *ocev = NULL;
	struct sev_main *sev = NULL;

	if (!cev)
		return NULL;

	if (!nolock)
		pthread_mutex_lock(&cev->pain->sev_lock);

	sev = cev->sev;

	xsyslog(LOG_INFO, "client[%"SEV_LOG"] free(fd#%d)", cev->serial, cev->fd);

	/* send event */
	if (cev->thread) {
		void *retval;
		xsyslog(LOG_INFO, "client[%"SEV_LOG"] free(fd#%d) wait thread[%p]",
				cev->serial, cev->fd, (void*)cev->thread);

		/* назначение флагов */
		pthread_mutex_lock(&cev->cev_lock);
		cev->action |= SEV_ACTION_EXIT;
		pthread_mutex_unlock(&cev->cev_lock);

		/* отправка сигнала */
		ev_async_send(cev->loop, &cev->async);

		/* ожидание реакции */
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] free(fd#%d) join thread[%p]",
				cev->serial, cev->fd, (void*)cev->thread);
		pthread_join(cev->thread, &retval);
		xsyslog(LOG_INFO, "client[%"SEV_LOG"] free(fd#%d) exit thread[%p]",
				cev->serial, cev->fd, (void*)cev->thread);
	}

	if (cev->loop) {
		ev_loop_destroy(cev->loop);
		pthread_mutex_destroy(&cev->cev_lock);
		pthread_mutex_destroy(&cev->send.lock);
		pthread_mutex_destroy(&cev->recv.lock);
	}

	if (cev->fd != -1) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG,
				"client[%"SEV_LOG"] destroy fd#%d", cev->serial, cev->fd);
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
			xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] hash non-empty recv buffer "
					"(%"PRIuPTR" bytes)",
					cev->serial, cev->recv.len);
#endif
	}
	if (cev->send.buf) {
		free(cev->send.buf);
		cev->send.buf = NULL;
		cev->send.size = 0u;
#if DEEPDEBUG
		if (cev->send.len)
			xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] hash non-empty send buffer "
					"(%"PRIuPTR" bytes)",
					cev->serial, cev->send.len);
#endif
	}
	/* освобождение структуры клиента */

	if (cev->next) {
		cev->next->prev = cev->prev;
		ocev = cev->next;
	}

	if (cev->prev) {
		cev->prev->next = cev->next;
		if (!ocev)
			ocev = cev->prev;
	}

	if (sev && sev->client == cev) {
		sev->client = ocev;
	}

	xsyslog(LOG_DEBUG, "client free(%p):%"PRIu64
			" [prev: %p:%"PRIu64", next: %p:%"PRIu64"]"
			", return(%p):%"PRIu64,
			(void*)cev, cev->serial,
			(void*)cev->prev, (cev->prev ? cev->prev->serial : 0lu),
			(void*)cev->next, (cev->next ? cev->next->serial : 0lu),
			(void*)ocev, (ocev ? ocev->serial : 0lu));

	if (!nolock)
		pthread_mutex_unlock(&cev->pain->sev_lock);
	free(cev);
	return ocev;
}

static inline struct sev_ctx *
client_alloc(struct ev_loop *loop, int fd, struct sev_ctx *next, struct sev_main *sev)
{
	struct main *pain = (struct main*)ev_userdata(loop);
	struct sev_ctx *cev;

	cev = calloc(1, sizeof(struct sev_ctx));
	if (!cev) {
		xsyslog(LOG_WARNING,
				"init(fd#%d) memory error: %s", fd, strerror(errno));
		return NULL;
	}

	cev->serial = ++sev_ctx_seq;
	xsyslog(LOG_INFO, "client[%"SEV_LOG"] init(fd#%d) ptr: %p",
			cev->serial, fd, (void*)cev);

	/* сигналирование и поллинг
	 * сделать это нужно как можно раньше, похоже
	 * что если это делать после создания потока, в libev что-то ломается
	 */
	cev->fd = -1;
	cev->pain = pain;
	cev->ev_lock = &pain->ev_lock;
	cev->sev = sev;

	/* память под буфера */
	cev->recv.buf = calloc(1, SEV_RECV_BUF);
	cev->send.buf = calloc(1, SEV_SEND_BUF);
	cev->recv.size = SEV_RECV_BUF;
	cev->send.size = SEV_SEND_BUF;

	/* не получилось */
	if (!cev->recv.buf || !cev->send.buf) {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] init(fd#%d) "
				"alloc recv/send buffer failed",
				cev->serial, fd);
		client_free(cev, true);
		return NULL;
	}

	if (!(cev->loop = ev_loop_new(EVFLAG_AUTO))) {
		client_free(cev, true);
		return NULL;
	}

	cev->fd = fd;
	pthread_mutex_init(&cev->recv.lock, NULL);
	pthread_mutex_init(&cev->send.lock, NULL);
	pthread_mutex_init(&cev->cev_lock, NULL);

	if (pthread_create(&cev->thread, NULL,
				(void*(*)(void*))client_main, (void*)cev)) {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] init(fd#%d) thread fail: %s",
				cev->serial, cev->fd, strerror(errno));
		/* на всякий случай */
		memset(&cev->thread, 0, sizeof(cev->thread));
		/* костыль, что бы сокет закрывался только там, откуда были вызваны */
		cev->fd = -1;
		client_free(cev, true);
		return NULL;
	} else {
		xsyslog(LOG_INFO, "client[%"SEV_LOG"] init(fd#%d) new thread[%p]",
				cev->serial, fd, (void*)cev->thread);

		/* интеграция в список */
		pthread_mutex_lock(&pain->sev_lock);
		if (next) {
			cev->next = next;
			if (next->prev) {
				next->prev->next = cev;
				cev->prev = next->prev;
			}
			next->prev = cev;
			xsyslog(LOG_DEBUG,
					"client[%"SEV_LOG"] "
					"init(fd#%d) prev: %"SEV_LOG":%p, next: %"SEV_LOG":%p",
					cev->serial, fd,
					(cev->prev ? cev->prev->serial : 0), (void*)cev->prev,
					(cev->next ? cev->next->serial : 0), (void*)cev->next);
		}
		pthread_mutex_unlock(&pain->sev_lock);
	}

	return cev;
}

/* call in thread */

bool
sev_continue(struct sev_ctx *cev)
{
	ev_async_send(cev->loop, &cev->async);
	return true;
}

bool
sev_perhaps(struct sev_ctx *cev, int action)
{
	bool retval = true;
	switch(action) {
		case SEV_ACTION_WRITE:
			if (cev->send.eof || cev->send.len >= cev->send.size)
				retval = false;
			break;
		case SEV_ACTION_READ:
			if (!cev->recv.len)
				retval = false;
			break;
		default:
			xsyslog(LOG_WARNING, "sev_perhaps: unknow argument: %d", action);
			return false;
	}
	return retval;
}

/* sev_send() и sev_recv()
 * должны возвращать три значения:
 * -1: ошибка чтения/записи (дальнейшая работа с сокетом невозможна)
 *  0: нет возможности записать/прочитать (но позже появится)
 *  n: прочитанное/записанное количество байт
 */
int
sev_send(struct sev_ctx *cev, const unsigned char *buf, size_t size)
{
	register size_t len;
	/* всё это выполняется в одном клиентском потоке, потому mutex не нужен */

	if (cev->send.eof) {
		return -1;
	}

	if (cev->send.size - cev->send.len < size) {
		size_t _bsize = cev->send.len + size;
		uint8_t *_btmp = realloc(cev->send.buf, _bsize);
		/* если размер буфера меньше запрашиваемого, то нужно увеличить размер
		 */
		if (!_btmp) {
			xsyslog(LOG_WARNING, "client[%"SEV_LOG"] realloc "
					"from %"PRIuPTR" to %"PRIuPTR" failed in send: %s",
					cev->serial, cev->send.size, _bsize, strerror(errno));
			return -1;
		}
		xsyslog(LOG_INFO, "client[%"SEV_LOG"] send buffer grow "
				"from %"PRIuPTR" to %"PRIuPTR,
				cev->serial, cev->send.size, _bsize);
		cev->send.buf = _btmp;
		cev->send.size = _bsize;
	}

	/* подсчёт объёмов копирования
	 * данные должны вместиться в буфер отправки
	 */
	len = cev->send.size - cev->send.len;
	len = MIN(size, len);
	if (len) {
		memcpy(&cev->send.buf[cev->send.len], buf, len);
		cev->send.len += len;
		if (!(cev->io.events & EV_WRITE)) {
			ev_io_stop(cev->loop, &cev->io);
			ev_io_set(&cev->io, cev->io.fd, cev->io.events | EV_WRITE);
			ev_io_start(cev->loop, &cev->io);
		}
	}

	return (int)len;
}

/* analog to sev_send */
int
sev_recv(struct sev_ctx *cev, unsigned char *buf, size_t size)
{
	int re = 0;
	size_t len = 0u;

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
							"client[%"SEV_LOG"] got memory error at read: %s",
							cev->serial, strerror(errno));
				}
			} else {
#if DEEPDEBUG
				memset(cev->recv.buf, 0, cev->recv.size);
#endif
			}
		}
	}

	if (len == 0u) {
		if (!(cev->io.events & EV_READ)) {
			ev_io_stop(cev->loop, &cev->io);
			ev_io_set(&cev->io, cev->io.fd, cev->io.events | EV_READ);
			ev_io_start(cev->loop, &cev->io);
		}
	}
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

		ptx = client_alloc(loop, sock, sev->client, sev);
		if (!ptx) {
			xsyslog(LOG_WARNING, "accept(%s, fd#%d) allocation failed",
					xaddr, sock);
			shutdown(sock, SHUT_RDWR);
			close(sock);
			return;
		}
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] socket(%s, fd#%d)",
				ptx->serial, xaddr, ptx->fd);
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

	pthread_mutex_lock(&pain->sev_lock);
	/* внесение в общий список */
	if (pain->sev)
		pain->sev->prev = sev;
	sev->next = pain->sev;
	pain->sev = sev;
	sev->pain = pain;
	pthread_mutex_unlock(&pain->sev_lock);

	xsyslog(LOG_INFO, "server init (%p) -> add entry point '%s'",
			(void*)sev, address);
	return sev;
}

/* return previous struct or next or NULL if no more,
 * must be called from main thread */
bool
server_free(struct ev_loop *loop, struct sev_main *sev)
{
	struct main *pain = (struct main*)ev_userdata(loop);
	if (!sev)
		return false;

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
	while (client_free(sev->client, false)) {};
	/* финализация, выбираем следующую ноду и освобождаем текущую */
	{
		pthread_mutex_lock(&pain->sev_lock);
		if (sev->prev) {
			sev->prev->next = sev->next;
		}
		if (sev->next) {
			sev->next->prev = sev->prev;
		}

		if (pain->sev == sev) {
			pain->sev = (sev->prev ? sev->prev : sev->next);
		}

		if (pain->sev) {
			xsyslog(LOG_DEBUG, "server free(%p) [prev: %p, next: %p]",
					(void*)sev, (void*)sev->prev, (void*)sev->next);
		} else {
			xsyslog(LOG_DEBUG, "server free(%p) last node",
					(void*)sev);
		}

		pthread_mutex_unlock(&pain->sev_lock);
		free(sev);
		return (pain->sev != NULL);
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
	if (w->signum == SIGINT) {
		xsyslog(LOG_INFO, "SIGINT");
	}
	ev_break(loop, EVBREAK_ALL);
}

void
rds_disconnect_cb(const redisAsyncContext *ac, int status)
{
	struct redis_c *rds = (struct redis_c*)ac->data;
	if (!rds)
		return;

	if (status != REDIS_OK) {
		uint32_t _m = hash_pjw(ac->errstr, strlen(ac->errstr));
		if (_m != rds->msghash) {
			xsyslog(LOG_INFO, "redis[%02"PRIuPTR"] disconnected: %s",
					rds->self, ac->errstr);
			rds->msghash = _m;
		}
	} else {
		syslog(LOG_INFO, "redis[%02"PRIuPTR"] disconnected, status: %d\n",
				rds->self, status);
		rds->msghash = 0u;
	}

	rds->connected = false;
}

void
rds_incoming_cb(redisAsyncContext *ac, redisReply *r, void *priv)
{
	struct redis_c *rds = (struct redis_c*)ac->data;
	if (!rds)
		return;

	if (!r)
		return;

	if (r->type != REDIS_REPLY_ARRAY) {
		 xsyslog(LOG_INFO, "redis[%02"PRIuPTR"] incoming not array: %d",
				 rds->self, r->type);
		 return;
	 }
	 if (r->elements != 3) {
		xsyslog(LOG_INFO, "redis[%02"PRIuPTR"] "
				"incoming not has 3 elements: %"PRIuPTR,
				rds->self,
				r->elements);
		return;
	 }

	if(r->element[2]->len) {
#if DEEPDEBUG
		/*xsyslog(LOG_DEBUG, "redis[%02"PRIuPTR"] message in \"%s\": \"%s\"",
				rds->self, r->element[1]->str, r->element[2]->str);*/
#endif
		/* если сообщение пришло во входяший канал */
		if (!strcmp(r->element[1]->str, rds->pain->options.redis_chan)) {
			/* проталкиваем его дальше */
			redis_process(rds, r->element[2]->str, (size_t)r->element[2]->len);
		} else {
			/* сообщаем что кто-то шумит
			 * TODO: вставить шумоподавитель
			 */
			xsyslog(LOG_INFO, "redis[%02"PRIuPTR"] noise in channel '%s', "
					"size: %d",
					rds->self,
					r->element[2]->str, r->element[3]->len);
		}
	} else {
		struct almsg_parser _ap;
		xsyslog(LOG_DEBUG, "redis[%02"PRIuPTR"] channel \"%s\": subscribed",
				rds->self, r->element[1]->str);
		almsg_init(&_ap);
		almsg_insert(&_ap, PSLEN_S("action"), PSLEN_S("server-starts"));
		almsg_insert(&_ap, PSLEN_S("from"), PSLEN(rds->pain->options.name));
		almsg2redis(rds->pain, "PUBLISH", rds->pain->options.redis_chan, &_ap);
		almsg_destroy(&_ap);

	}
}

void
rds_connect_cb(const redisAsyncContext *ac, int status)
{
	struct redis_c *rds = (struct redis_c*)ac->data;
	if (!rds)
		return;

	if (status != REDIS_OK) {
		uint32_t _m = hash_pjw(ac->errstr, strlen(ac->errstr));
		if (_m != rds->msghash) {
			xsyslog(LOG_INFO, "redis[%02"PRIuPTR"] connect error: %s",
					rds->self, ac->errstr);
			rds->msghash = _m;
		}
		rds->connected = false;
		return;
	}
	syslog(LOG_INFO, "redis[%02"PRIuPTR"] connected, status: %d\n",
			rds->self, status);
	rds->msghash = 0u;
}

/* cmd:
 *  PUBLISH
 *  LPUSH
 *  RPUSH
 */
bool
redis_t(struct main *pain, const char *cmd, const char *ch, const char *data, size_t size)
{
	bool awaited = false;
	/* с еденицы, потому что первый нужен для
	 * подписок
	 *
	 */
	if (ch == NULL) {
		ch = pain->options.redis_chan;
	}
	while (!awaited) {
		/* отправка сообщения */
		/* FIXME: магическая константа по количеству "базовых" каналов */
		for (size_t i = 3u; i < REDIS_C_MAX; i++) {
			if (!pthread_mutex_trylock(&pain->rs[i].x)) {
				redisAsyncCommand(pain->rs[i].ac, NULL, NULL, "%s %s %b",
						cmd, ch, data, size);
				pthread_mutex_unlock(&pain->rs[i].x);
				/* не броадкастить нужно для того, что бы не срывались
				 * все сразу и не гнались за ресурсом
				 */
				pthread_cond_signal(&pain->rs_wait);
				return true;
			}
		}
		/* что бы не ждать больше одного цикла */
		awaited = true;
		/* сообщение не отправилось, нужно дождаться сигнала
		 * и попытаться снова
		 */
		pthread_mutex_lock(&pain->rs_lock);
		pain->rs_awaits++;
		if (!pthread_cond_wait(&pain->rs_wait, &pain->rs_lock)) {
			pain->rs_awaits--;
			pthread_mutex_unlock(&pain->rs_lock);
			continue;
		}
		break;
	}
	return false;
}

/* запрос в очередь и ожидание ответ
 * ответ приходит в sev_ctx.bus
 * TODO: добавил lock() т.к. процедура вызывается из внешних тредов
 * или лучше семафорить, т.к. изменение списка должно производиться
 * тогда, когда не производится действий над подключениями
 */
uint64_t
bus_query(struct sev_ctx *cev, struct almsg_parser *a, void *data)
{
	struct bus_result *br;
	char *p = NULL;
	uint64_t hash = 0ul;
	/* (* 2) количество блоков под long
	 * (* 2) количество hex-символов в char
	 * (+ 1) нолик
	 */
	char idbuf[sizeof(long) * 2 * 2 + 1] = {0};
	size_t l = 0u;
	char *chan = "unknown_channel";

	snprintf(idbuf, sizeof(idbuf), "%lx:%lx", random(), random());
	hash = hash_pjw(idbuf, strlen(idbuf));
	/* ожидание ответа */
	almsg_insert(a, PSLEN_S("from"), PSLEN(cev->pain->options.name));
	almsg_append(a, PSLEN_S("id"), PSLEN(idbuf));
	/*almsg_insert(a, PSLEN_S("action"), PSLEN_S("query"));*/

	if (!(br = calloc(1, sizeof(*br)))
			|| !list_alloc(&cev->pain->bus_task, hash, (void*)br)) {
		if (br)
			free(br);
		xsyslog(LOG_WARNING, "bus_query error: queue allocation failed");
		return false;
	}
	br->cev = cev;
	br->cev_serial = cev->serial;
	br->cev_bus_id = ++cev->bus_idgen;
	br->data = data;

	if (!pthread_mutex_lock(&cev->cev_lock)) {
		if (!list_alloc(&cev->bus_wanted, br->cev_bus_id, br)) {
			/* ну не добавили и хрен с ней, на самом деле, запрос всё равно
			 * может пройти, а в некоторых случаях он нужен сам по себе,
			 * без ответа но известить нужно.
			 */
			xsyslog(LOG_WARNING,
					"bus_query warning: can't add pointer into queue");
		}
		pthread_mutex_unlock(&cev->cev_lock);
	} else {
		xsyslog(LOG_WARNING, "bus_query warning: cev lock failed");
	}

	/* отправка сообщения в redis */
	almsg_format_buf(a, &p, &l);
	if (p) {
		if (l)
			redis_t(cev->pain, "PUBLISH", chan, p, l);
	} else {
		xsyslog(LOG_WARNING, "bus_query: empty almsg buffer (elem: %"PRIuPTR")",
				almsg_count(a, NULL, 0u));
	}
	return true;
}

bool
bus_cancel(struct sev_ctx *cev, uint64_t id)
{
	struct listNode *n = NULL;
	struct listPtr p = {0};
	bool rval = false;

	list_ptr(&cev->bus_wanted, &p);
	if (!pthread_mutex_lock(&cev->cev_lock)) {
		if ((n = list_find(&p, id))) {
			list_free_node(n, NULL);
			rval = true;
		}
		pthread_mutex_unlock(&cev->cev_lock);
	}
	return rval;

}

void
almsg2redis(struct main *pain, const char *cmd, const char *chan,
		struct almsg_parser *alm)
{
	char *p = NULL;
	size_t l = 0u;

	almsg_format_buf(alm, &p, &l);
	if (p) {
		if (l)
			redis_t(pain, cmd, chan, p, l);
		free(p);
	} else {
		xsyslog(LOG_WARNING, "almsg2redis: empty buffer (elem: %"PRIuPTR")",
				almsg_count(alm, NULL, 0u));
	}
}

void
timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct main *pain = (struct main*)ev_userdata(loop);
	if (!pain)
		return;

	fcac_tick(&pain->fcac);

	/* подключение к редису */
	for (size_t i = 0u; i < REDIS_C_MAX; i++) {
		if (!pain->rs[i].connected) {
			/* простая  чистка */
			if (pain->rs[i].ac) {
				pain->rs[i].ac = NULL;
			}
			/* аллокация структур */
			pain->rs[i].ac = redisAsyncConnect("127.0.0.1", 6379);
			if (pain->rs[i].ac) {
				if (pain->rs[i].ac->err) {
					/* проверка ошибки */
					xsyslog(LOG_INFO, "hiredis alloc error: %s",
							pain->rs[i].ac->errstr);
					redisAsyncFree(pain->rs[i].ac);
					pain->rs[i].ac = NULL;
				 } else {
					/* цепляемся к libev */
					pain->rs[i].ac->data = (void*)&pain->rs[i];
					redisLibevAttach(loop, pain->rs[i].ac);
					redisAsyncSetConnectCallback(pain->rs[i].ac,
						rds_connect_cb);
					redisAsyncSetDisconnectCallback(pain->rs[i].ac,
						rds_disconnect_cb);
					/* если это нулевое подключение, то
					 * подписываемся на каналы
					 */
					switch(i) {
						case 0:
							/* подписка на общий канал */
							redisAsyncCommand(pain->rs[i].ac,
									(redisCallbackFn*)rds_incoming_cb,
									NULL,
									"SUBSCRIBE %s", pain->options.redis_chan);
							break;
						case 1:
							/* подписка на канал класса */
							redisAsyncCommand(pain->rs[i].ac,
									(redisCallbackFn*)rds_incoming_cb,
									NULL,
									"SUBSCRIBE %s%%fep",
									pain->options.redis_chan);
							break;
						case 2:
							/* подписка на персональный канал */
							redisAsyncCommand(pain->rs[i].ac,
									(redisCallbackFn*)rds_incoming_cb,
									NULL,
									"SUBSCRIBE %s@%s",
									pain->options.redis_chan,
									pain->options.name);
							break;
						default:
							break;
					}
					pain->rs[i].connected = true;
				}
			}
		}
	} /* for */
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
			xsyslog(LOG_WARNING, "server %p has left node %p ",
					(void*)sev_it, (void*)sev_it->prev);
		}
		/* обход узлов */
		for (; sev_it; sev_it = sev_it->next) {
			void *_cev_next = NULL;
			/* ребиндим сокет, если не забинден */
			if (sev_it->fd == -1) {
				server_bind(loop, sev_it);
			}
			/* если клиентов не обслуживается на узле, то выходим */
			if ((cev_it = sev_it->client) == NULL)
				continue;
			/* пускаем предупреждение, если у узла какой-то косяк
			 * в связности структур
			if (cev_it->prev)
				xsyslog(LOG_WARNING,
						"client[%"SEV_LOG"] has left node %"SEV_LOG":%p",
						cev_it->serial, cev_it->serial, (void*)cev_it->prev);
			 */
			/* обход списка */
			pthread_mutex_lock(&pain->sev_lock);
			for(; cev_it; cev_it = _cev_next) {
				_cev_next = cev_it->next;
				/* клиент готов к отчистке */
				if (cev_it->isfree) {
					client_free(cev_it, true);
				}
			}
			pthread_mutex_unlock(&pain->sev_lock);
		}
	}
}

static void
bus_inq_free(struct bus_inq_message *b) {
	/*
	switch(b->type) {
	default:
		break;
	}
	*/
	free(b);
}

bool
cev_bus_result(struct sev_ctx *cev, uint64_t bus_id, struct bus_inq_message *b)
{
	struct listPtr p = {0};
	struct listNode *n = {0};
	bool rval = false;
	if (!pthread_mutex_lock(&cev->cev_lock)) {
		list_ptr(&cev->bus_wanted, &p);
		if ((n = list_find(&p, bus_id)) != NULL) {
			/* если не получилось отправить сообщение,
			 * то результат всё равно будет положительным
			 */
			rval = true;
			/* сразу освбождаем */
			list_free_node(n, NULL);
			/* кладём сообщение в очередь */
			if (b) {
				squeue_send(&cev->bus_inqueue,
						b, (void(*)(void*))bus_inq_free);
			}
		}
		pthread_mutex_unlock(&cev->cev_lock);
	}
	return rval;
}

struct sev_ctx *
cev_by_serial(struct main *pain, size_t serial)
{
	struct sev_main *sev = NULL;
	struct sev_ctx *cev = NULL;
	pthread_mutex_lock(&pain->sev_lock);
	/* TODO */
	for (sev = pain->sev; sev; sev = sev->next) {
		for (cev = sev->client; cev; cev = cev->next) {
			if (cev->serial == serial) {
				if (cev->isfree) {
					/* обнуляем указатель, если структура помечена
					 * как освобождённая
					 */
					cev = NULL;
				}
				break;
			}
		}
	}
	pthread_mutex_unlock(&pain->sev_lock);
	return cev;
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
	if (argc > 1 || !argc) {
		if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")) {
			printf(sev_version_string());
		}
		return true;
	}
	return false;
}

static bool
chuser(struct main *pain)
{
	if ((pain->options.group && *pain->options.group)) {
		struct group *g = NULL;
		if (!(g = getgrnam(pain->options.group))) {
			xsyslog(LOG_ERR, "getgrnam(%s) error: %s",
					pain->options.group, strerror(errno));
			return false;
		}
		if (setgid(g->gr_gid) != -1) {
			xsyslog(LOG_ERR, "gid changed to '%s' (%d)",
					g->gr_name, g->gr_gid);
		} else {
			xsyslog(LOG_ERR, "setgid(%d) error: %s",
					g->gr_gid, strerror(errno));
			return false;
		}
	}

	if ((pain->options.user && *pain->options.user)) {
		struct passwd *p = NULL;
		if (!(p = getpwnam(pain->options.user))) {
			xsyslog(LOG_ERR, "getpwnam(%s) error: %s", pain->options.user,
					strerror(errno));
			return false;
		}
		if (setuid(p->pw_uid) != -1) {
			xsyslog(LOG_ERR, "uid changed to '%s' (%d)",
					p->pw_name, p->pw_uid);
		} else {
			xsyslog(LOG_ERR, "setuid(%d) error: %s",
					p->pw_uid, strerror(errno));
			return false;
		}
	}

	return true;
}

static bool
pidfile_accept(struct main *pain)
{
	pid_t pid = 0u;
	pid_t spid = 0u;
	int fd;
	char bf[64] = {0};
	/* ок, если pidfile не назначен */
	if (!*pain->options.pidfile)
		return true;

	spid = getpid();
	xsyslog(LOG_DEBUG, "use '%s' as pidfile, self pid: %u",
			pain->options.pidfile, spid);
	/* читаем содержимое */
	if ((fd = open(pain->options.pidfile, O_RDONLY)) != -1) {
		read(fd, bf, sizeof(bf));
		pid = strtoul(bf, NULL, 10);
		if (pid != 0u && kill(pid, 0) != -1) {
			xsyslog(LOG_ERR, "already runned as pid %u", pid);
			close(fd);
			return false;
		}
		close(fd);
	}

	snprintf(bf, sizeof(bf), "%u", spid);
	if ((fd = open(pain->options.pidfile,
			O_WRONLY | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) != -1) {
		write(fd, bf, strlen(bf));
		close(fd);
	} else {
		xsyslog(LOG_ERR, "can't create pidfile: %s", strerror(errno));
		return false;
	}

	return true;
}

static inline void
cfg_load(struct main *pain)
{
	char cfgpath[PATH_MAX + 1];

	snprintf(cfgpath, PATH_MAX, "%s.conf", pain->a_basename);
	xsyslog(LOG_INFO, "read config: %s", cfgpath);
	cfg_parse(pain->cfg, cfgpath);
	snprintf(cfgpath, PATH_MAX, "/etc/%s.conf", pain->a_basename);
	xsyslog(LOG_INFO, "read config: %s", cfgpath);
	cfg_parse(pain->cfg, cfgpath);

	/* небольшие проверки */
	if (pain->options.pg_poolsize <= SPQ_DEFAULT_POOLSIZE) {
		xsyslog(LOG_WARNING,
				"ignore cfg's pg_poolsize value"
				" (%ld <= "S(SPQ_DEFAULT_POOLSIZE)")",
				pain->options.pg_poolsize);
		pain->options.pg_poolsize = SPQ_DEFAULT_POOLSIZE;
	}
}

/*
 * возвращает true, если конфигурация была перечитана
 */
static inline bool
cfg_update(struct main *pain)
{
	cfg_load(pain);

	/* опции для перезагрузки:
	 * packet_verbose
	 * pg_poolsize
	 */

	/* изменение размера пула подключений */
	spq_resize((unsigned)pain->options.pg_poolsize);
	spq_set_log_failed_queries((bool)pain->options.log_failed_queries);
	/* инициализация лога сервера */
	if (*pain->options.packet_verbose)
		packet_verbose(pain->options.packet_verbose);

	/* TODO */
	return true;
}

int
main(int argc, char *argv[])
{
	bool _r;
	struct ev_loop *loop;
	struct main pain;
	/* base configuration */

	memset(&pain, 0, sizeof(struct main));
	{
		struct utsname buf;

		if (!(pain.a_basename = basename(argv[0]))) {
			xsyslog(LOG_ERR, "no basename in '%s'", argv[0]);
			return EXIT_FAILURE;
		}

		memset(&buf, 0, sizeof(struct utsname));
		if (uname(&buf) != -1 && *buf.nodename) {
			pain.options.name = strdup(buf.nodename);
		} else {
			pain.options.name = strdup("fepizer");
		}

		pain.options.redis_chan = strdup("fep_broadcast");
		pain.options.cache_dir = strdup("user/");
		pain.options.pidfile = strdup("");
		pain.options.user = strdup("");
		pain.options.group = strdup("");

		pain.options.bindline = strdup("0.0.0.0:5151");
		pain.options.pg_connstr = strdup("dbname = fepserver");
		pain.options.packet_verbose = strdup("");
		pain.options.pg_poolsize = 10;
		pain.options.unique_device_id = true;
	}
	/* получение конфигурации */
	{
		cfg_opt_t opt[] = {
			CFG_SIMPLE_STR("bind", &pain.options.bindline),
			CFG_SIMPLE_STR("pg_connstr", &pain.options.pg_connstr),
			CFG_SIMPLE_INT("pg_poolsize", &pain.options.pg_poolsize),
			CFG_SIMPLE_BOOL("log_failed_queries",
					&pain.options.log_failed_queries),
			CFG_SIMPLE_STR("redis_chan", &pain.options.redis_chan),
			CFG_SIMPLE_STR("server_name", &pain.options.name),
			CFG_SIMPLE_STR("cache_dir", &pain.options.cache_dir),
			/* эти опции не очень нужны, т.к. дублируют
			 * возможности start-stop-daemon
			 */
			CFG_SIMPLE_STR("pidfile", &pain.options.pidfile),
			CFG_SIMPLE_STR("user", &pain.options.user),
			CFG_SIMPLE_STR("group", &pain.options.group),
			/* конфигурация лога */
			CFG_SIMPLE_STR("packet_verbose", &pain.options.packet_verbose),
			/* некоторые проверки */
			CFG_SIMPLE_BOOL("unique_device_id", &pain.options.unique_device_id),
			/* лимиты */
			CFG_SIMPLE_INT("limit_global_sql_queries",
					&pain.options.limit_global_sql_queries),
			CFG_SIMPLE_INT("limit_global_fd_queries",
					&pain.options.limit_global_fd_queries),

			CFG_SIMPLE_INT("limit_local_sql_queries",
					&pain.options.limit_local_sql_queries),
			CFG_SIMPLE_INT("limit_local_fd_queries",
					&pain.options.limit_local_fd_queries),

			CFG_END()
		};

		if (check_args(argc, argv))
			return EXIT_SUCCESS;

		openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);
		xsyslog(LOG_INFO, "--- START ---");

		pain.cfg = cfg_init(opt, 0);
		cfg_load(&pain);
	}
	if ((_r = pidfile_accept(&pain)) && (_r = chuser(&pain))) {
		xsyslog(LOG_DEBUG, "pg: \"%s\"", pain.options.pg_connstr);
		spq_open(SPQ_DEFAULT_POOLSIZE, pain.options.pg_connstr);
		/* всякая ерунда с бд */
		if ((_r = spq_create_tables()) != false) {
			loop = EV_DEFAULT;
			client_threads_prealloc();
			ev_signal_init(&pain.sigterm, signal_cb, SIGTERM);
			ev_signal_start(loop, &pain.sigterm);
			ev_signal_init(&pain.sigint, signal_cb, SIGINT);
			ev_signal_start(loop, &pain.sigint);
			ev_signal_init(&pain.sigpipe, signal_ignore_cb, SIGPIPE);
			ev_signal_start(loop, &pain.sigpipe);
			/* таймер на чистку всяких устаревших структур и прочего */
			ev_timer_init(&pain.watcher, timeout_cb, 1., 10.);
			ev_timer_start(loop, &pain.watcher);
			pthread_mutex_init(&pain.ev_lock, NULL);
			/* инициализация curl */
			cuev_init(&pain.cuev, loop);
			/* инициализация структур редиса */
			pthread_mutex_init(&pain.rs_lock, NULL);
			pthread_cond_init(&pain.rs_wait, NULL);
			for (size_t i = 0u; i < REDIS_C_MAX; i++) {
				pthread_mutex_init(&pain.rs[i].x, NULL);
				pain.rs[i].self = i;
				pain.rs[i].pain = &pain;
			}
			/*  */
			fcac_init(&pain.fcac, true);
			pthread_mutex_init(&pain.sev_lock, NULL);
			pthread_mutex_init(&pain.values.lock, NULL);
			/* мультисокет */
			{
				char *_x = strdup(pain.options.bindline);
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
				/* обновление настроек */
				cfg_update(&pain);
				/* выход происходит при остановке всех evio в лупе */
				ev_run(loop, 0);
				/* чистка серверных сокетов */
				while (server_free(loop, pain.sev));
			} else {
				_r = false;
			}
			/* подчистка подключений к редису */
			for (size_t i = 0u; i < REDIS_C_MAX; i++) {
				if (pain.rs[i].ac && pain.rs[i].connected) {
					redisAsyncFree(pain.rs[i].ac);
					pain.rs[i].ac = NULL;
					pthread_mutex_destroy(&pain.rs[i].x);
				}
			}
			pthread_mutex_destroy(&pain.values.lock);
			pthread_mutex_destroy(&pain.ev_lock);
			pthread_mutex_destroy(&pain.rs_lock);
			pthread_cond_destroy(&pain.rs_wait);
			pthread_mutex_destroy(&pain.sev_lock);
			/* */
			fcac_destroy(&pain.fcac);
			/* деинициализация curl */
			cuev_destroy(&pain.cuev);
			/* чистка клиентских сокетов */
			ev_signal_stop(loop, &pain.sigterm);
			ev_signal_stop(loop, &pain.sigint);
			ev_timer_stop(loop, &pain.watcher);
			ev_loop_destroy(loop);
			client_threads_bye();
		}
		spq_close();
	}
	closelog();

	cfg_free(pain.cfg);
	free(pain.options.bindline);
	free(pain.options.pg_connstr);
	free(pain.options.packet_verbose);
	free(pain.options.redis_chan);
	free(pain.options.name);
	free(pain.options.cache_dir);
	free(pain.options.pidfile);
	free(pain.options.user);
	free(pain.options.group);

	xsyslog(LOG_INFO, "--- EXIT ---");

	if (_r)
		return EXIT_SUCCESS;
	return EXIT_FAILURE;
}

