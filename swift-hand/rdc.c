/* vim: ft=c ff=unix fenc=utf-8
 * file: rdc.c
 */
#include <hiredis/adapters/libev.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include "junk/xsyslog.h"

#include "rdc.h"

void rdc_init(struct rdc *r, struct ev_loop *loop,
		const char *addr, size_t limit)
{
	memset(r, 0u, sizeof(struct rdc));
	r->c_limit = limit;
	r->loop = loop;
	if (addr) {
		r->addr = strdup(addr);
	} else {
		r->addr = strdup("localhost");
	}

	pthread_mutex_init(&r->lock, NULL);

}

void rdc_destroy(struct rdc *r)
{
	struct rdc_node *nn;
	struct rdc_node *fn;

	for (nn = r->c; nn; nn = fn) {
		fn = nn->next;
		if (nn->ac) {
			redisAsyncFree(nn->ac);
		}
		if (nn->command)
			free(nn->command);
		memset(nn, 0, sizeof(struct rdc_node));
		free(nn);
	}

	free((void*)r->addr);
	pthread_mutex_destroy(&r->lock);
	memset(r, 0u, sizeof(struct rdc));
}

static void
rdc_connect_cb(const redisAsyncContext *ac, int status)
{
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	pthread_mutex_lock(&nn->lock);
	if (status != REDIS_OK) {
		nn->ac = NULL;
		xsyslogs(LOG_INFO, &nn->msghash, "rdc#%03u: connect: %s", nn->num,
				ac->errstr);
	} else {
		xsyslogs(LOG_INFO, &nn->msghash, "rdc#%03u: connected", nn->num);
	}
	pthread_mutex_unlock(&nn->lock);
}

static void
rdc_disconnect_cb(const redisAsyncContext *ac, int status)
{
	/* в худшем случае подобный код может привести к дедлоку
	 * (в ситуации когда один из тредов захватил управление,
	 * а libev среагировал на отключение сокета)
	 * в лучшем -- такой ситуации никогда не возникнет
	 */
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	pthread_mutex_lock(&nn->lock);
	nn->ac = NULL;
	pthread_mutex_unlock(&nn->lock);
	xsyslogs(LOG_INFO, &nn->msghash, "rdc#%03u: disconnected: %s", nn->num,
			ac->errstr);
}

redisAsyncContext *
rdc_acquire(struct rdc *r)
{
	struct rdc_node *nn = NULL;
	pthread_mutex_lock(&r->lock);
	/* 1. найти свободное подключение
	 * если активных подключений меньше, чем созданных,
	 * то определённо должно быть что-то свободное */
	if (r->c_inuse < r->c_count) {
		/* TODO */
		for (nn = r->c; nn; nn = nn->next) {
			/* пропускаем, если не удалось заблокировать,
			 * вероятно, структура уже используется
			 */
			if (pthread_mutex_trylock(&nn->lock)) {
				continue;
			}
			/*
			 * инкремент счётчиков и выход
			 */
			if (nn->ac && !nn->command) {
				r->c_inuse++;
				return nn->ac;
			} else if (!nn->ac) {
				/* получение отключившегося сокета для релокации */
				break;
			}
			/* если это не подходящий узел, то нужно освободить его */
			pthread_mutex_unlock(&nn->lock);
		}
	}

	if (!nn && r->c_count >= r->c_limit) {
		/* 2. если не найдено, то создать новое
		 * создаётся только в случае, если не привышен лимит подключений
		 */
		xsyslog(LOG_WARNING, "rdc: connections limit exceeded: %d/%d",
				r->c_count, r->c_limit);
		pthread_mutex_unlock(&r->lock);
		return NULL;
	} else if (!nn) {
		/*
		 * выделение памяти под новую структуру
		 */
		nn = calloc(1, sizeof(struct rdc_node));
		if (!nn) {
			xsyslog(LOG_WARNING, "rdc: malloc failed: %s", strerror(errno));
			pthread_mutex_unlock(&r->lock);
			return NULL;
		}
		pthread_mutex_init(&nn->lock, NULL);
		pthread_mutex_lock(&nn->lock);
	}
	/* если создание прошло успешно */
	if (nn) {
		/* пытаемся выделить место под структуры hiredis */
		nn->ac = redisAsyncConnect(r->addr, 6379);
		if (!nn->ac || nn->ac->err) {
			xsyslog(LOG_WARNING, "rdc: redis connect failed: %s",
					(nn->ac ? nn->ac->errstr : NULL));
			pthread_mutex_unlock(&r->lock);
			if (nn->ac) {
				redisAsyncFree(nn->ac);
				nn->ac = NULL;
			}
			if (nn->command)
				free(nn->command);
			free(nn);
			return NULL;
		}
		nn->ac->data = nn;
		/* подключение к libev */
		redisLibevAttach(r->loop, nn->ac);
		redisAsyncSetConnectCallback(nn->ac, rdc_connect_cb);
		redisAsyncSetDisconnectCallback(nn->ac, rdc_disconnect_cb);

		nn->rdc = r;
		nn->num = ++r->serial;
		nn->next = r->c;
		r->c = nn;
		r->c_count++;
		r->c_inuse++;

		pthread_mutex_unlock(&r->lock);
		xsyslogs(LOG_INFO, &nn->msghash, "rdc#%03u created", nn->num);
		return nn->ac;
	} else {
		xsyslog(LOG_WARNING, "rdc: wtf?");
	}
	pthread_mutex_unlock(&r->lock);
	return NULL;
}

void
rdc_release(struct redisAsyncContext *ac)
{
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	if (pthread_mutex_trylock(&nn->lock)) {
		pthread_mutex_lock(&nn->rdc->lock);
		nn->rdc->c_inuse--;
		pthread_mutex_unlock(&nn->rdc->lock);
		pthread_mutex_unlock(&nn->lock);
	} else if (nn->mode != RDC_NORMAL) {
		/* если "режим" структуры подписка, то она и не должна быть залочена */
		pthread_mutex_lock(&nn->lock);
		if (nn->ac) {
			/* если структура была с автопереподключением, то
			 * самый простой способ сбросить состояние -
			 * переподключиться
			 */
			redisAsyncFree(ac);
			free(nn->command);
			nn->command = NULL;
			nn->ac = NULL;
			nn->cb = NULL;
		}
		pthread_mutex_lock(&nn->rdc->lock);
		nn->rdc->c_inuse--;
		nn->rdc->c_back--;
		pthread_mutex_unlock(&nn->rdc->lock);
		pthread_mutex_unlock(&nn->lock);
	}
}

static void
rdc_periodic_cb(redisAsyncContext *ac, redisReply *r, void *priv)
{
	struct rdc_node *nn = (struct rdc_node*)ac->data;

	if (!nn || nn->mode != RDC_PERIODIC) {
		return;
	}

	if (nn->cb) {
		nn->cb(ac, r, priv);
	}

	redisAsyncCommand(ac, (redisCallbackFn*)rdc_periodic_cb, priv, nn->command);
	return;
}

void
rdc_refresh(struct rdc *r)
{
	struct rdc_node *nn;
	/* если не выходит залочить структуру
	 */
	if (pthread_mutex_trylock(&r->lock)) {
		return;
	}
	xsyslog(LOG_DEBUG, "rdc: refresh");
	/* обновление состояния подключений, если отвалились, то переподключить */
	for (nn = r->c; nn; nn = nn->next) {
		/* нужно залочиться */
		if (pthread_mutex_trylock(&nn->lock)) {
			continue;
		}
		/* если подключение присутсвует, то пропускаем */
		if (nn->ac) {
			pthread_mutex_unlock(&nn->lock);
			continue;
		}
		nn->ac = redisAsyncConnect(r->addr, 6379);
		if (!nn->ac) {
			xsyslogs(LOG_WARNING,
					&nn->msghash, "rdc#%03u: redis reconnect failed", nn->num);
			continue;
		}
		/* подключение к libev */
		nn->ac->data = nn;
		redisLibevAttach(r->loop, nn->ac);
		redisAsyncSetConnectCallback(nn->ac, rdc_connect_cb);
		redisAsyncSetDisconnectCallback(nn->ac, rdc_disconnect_cb);
		/* если была назначена комманда, то её требуется выполнить */
		if (nn->mode == RDC_PERIODIC) {
			redisAsyncCommand(nn->ac, (redisCallbackFn*)rdc_periodic_cb,
					NULL, nn->command);
		} else if (nn->mode == RDC_SUBSCRIBE) {
			redisAsyncCommand(nn->ac, (redisCallbackFn*)nn->cb,
					NULL, nn->command);
		}
		/*xsyslogs(LOG_INFO, &nn->msghash, "rdc#%03u: reconnect", nn->num);*/
		pthread_mutex_unlock(&nn->lock);
	}
	pthread_mutex_unlock(&r->lock);
}

/* выполнение */
bool
rdc_subscribe(struct rdc *r, redisCallbackFn *cb, void *priv,
		const char *command)
{
	redisAsyncContext *ac = NULL;
	struct rdc_node *nn = NULL;
	/* 1. захват */
	ac = rdc_acquire(r);
	if (!ac) {
		xsyslog(LOG_WARNING, "rdc: subscribe command failed ('%s')", command);
		return false;
	}
	nn = (struct rdc_node*)ac->data;
	/* 2. выполнение комманды */
	redisAsyncCommand(ac, cb, priv, command);
	/* 3. фиксация значений для постоянного использования */
	nn->mode = RDC_SUBSCRIBE;
	nn->cb = cb;
	nn->command = strdup(command);
	pthread_mutex_lock(&nn->rdc->lock);
	nn->rdc->c_back++;
	pthread_mutex_unlock(&nn->rdc->lock);
	/* 4. релиз структуры делать не нужно, но снять лок обязательно */
	pthread_mutex_unlock(&nn->lock);
	return true;
}

bool
rdc_exec_period(struct rdc *r, redisCallbackFn *cb, void *priv,
		const char *command)
{
	struct rdc_node *nn = NULL;
	redisAsyncContext *ac = NULL;

	ac = rdc_acquire(r);
	if (!ac) {
		xsyslog(LOG_WARNING, "rdc: periodic exec failed ('%s')", command);
		return false;
	}
	nn = (struct rdc_node*)ac->data;
	/* 2. выполнение комманды со своим калбеком */
	redisAsyncCommand(ac, (redisCallbackFn*)rdc_periodic_cb, priv, command);
	/* 3. фиксация значений */
	nn->mode = RDC_PERIODIC;
	nn->cb = cb;
	nn->command = strdup(command);
	pthread_mutex_lock(&nn->rdc->lock);
	nn->rdc->c_back++;
	pthread_mutex_unlock(&nn->rdc->lock);

	pthread_mutex_unlock(&nn->lock);
	return true;
}

bool
rdc_exec_once(struct rdc *r, redisCallbackFn *cb, void *priv,
		const char *command, ...)
{
	struct rdc_node *nn = NULL;
	redisAsyncContext *ac = NULL;
	va_list va;

	ac = rdc_acquire(r);
	if (!ac) {
		xsyslog(LOG_WARNING, "rdc: exec failed ('%s')", command);
		return false;
	}
	nn->mode = RDC_NORMAL;
	va_start(va, command);
	redisvAsyncCommand(ac, (redisCallbackFn*)rdc_periodic_cb, priv, command, va);
	va_end(va);
	rdc_release(ac);
	return false;
}

