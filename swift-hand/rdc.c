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
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	pthread_mutex_lock(&nn->lock);
	nn->ac = NULL;
	pthread_mutex_unlock(&nn->lock);
	xsyslogs(LOG_INFO, &nn->msghash, "rdc#%03u: disconnected: %s", nn->num,
			ac->errstr);
}

static void
rdc_command_cb(redisAsyncContext *ac, redisReply *r, void *priv)
{
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	if (!r)
		return;
	xsyslogs(LOG_INFO, &nn->msghash, "rdc#%03u incoming data for '%s'",
			nn->num,
			nn->command);
}

redisAsyncContext *
rdc_acquire(struct rdc *r, char *command, redisCallbackFn *cb)
{
	pthread_mutex_lock(&r->lock);
	/* 1. найти свободное подключение
	 * если активных подключений меньше, чем созданных,
	 * то определённо должно быть что-то свободное */
	if (r->c_inuse < r->c_count) {
		struct rdc_node *nn;
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
			if (nn->ac) {
				r->c_inuse++;
				return nn->ac;
			}
			pthread_mutex_unlock(&nn->lock);
		}
	}
	/* 2. если не найдено, то создать новое
	 * создаётся только в случае, если не привышен лимит подключений
	 */
	if (r->c_count < r->c_limit) {
		struct rdc_node *nn;
		nn = calloc(1, sizeof(struct rdc_node));
		if (!nn) {
			xsyslog(LOG_WARNING, "rdc: malloc failed: %s", strerror(errno));
			pthread_mutex_unlock(&r->lock);
			return NULL;
		}
		if (command) {
			if (!(nn->command = strdup(command))) {
				xsyslog(LOG_WARNING, "rdc: dup connect string failed: %s",
						strerror(errno));
				pthread_mutex_unlock(&r->lock);
				return NULL;
			}
		}
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
		pthread_mutex_init(&nn->lock, NULL);
		redisLibevAttach(r->loop, nn->ac);
		redisAsyncSetConnectCallback(nn->ac, rdc_connect_cb);
		redisAsyncSetDisconnectCallback(nn->ac, rdc_disconnect_cb);
		if (command) {
			redisAsyncCommand(nn->ac,
					(cb ? cb : (redisCallbackFn*)rdc_command_cb),
					NULL, command);
		}
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
		xsyslog(LOG_WARNING, "rdc: connections limit exceeded: %d/%d",
				r->c_count, r->c_limit);
	}
	pthread_mutex_unlock(&r->lock);
	return NULL;
}

void
rdc_release(struct redisAsyncContext *ac)
{
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	if (pthread_mutex_trylock(&nn->lock)) {
		/* если структура была заблокирована, то нужно почистить счётчики */
		pthread_mutex_lock(&nn->rdc->lock);
		nn->rdc->c_inuse--;
		pthread_mutex_unlock(&nn->rdc->lock);
	}
	pthread_mutex_unlock(&nn->lock);
}

void
rdc_refresh(struct rdc *r)
{
	struct rdc_node *nn;
	/* если не выходит залочить структуру,
	 * то можно проигнорировать проход
	 * FIXME: постоянно игнорировать нельзя, нужен счётчик
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
		if (nn->command)
			redisAsyncCommand(nn->ac, (redisCallbackFn*)rdc_command_cb,
					NULL, nn->command);
		/*xsyslogs(LOG_INFO, &nn->msghash, "rdc#%03u: reconnect", nn->num);*/
		pthread_mutex_unlock(&nn->lock);
	}
	pthread_mutex_unlock(&r->lock);
}

/* выполнение */
bool
rdc_execute(struct rdc *r, const char *command, ...)
{
	redisAsyncContext *ac;
	va_list va;

	if (!(ac = rdc_acquire(r, NULL, NULL))) {
		return false;
	}

	va_start(va, command);
	redisvAsyncCommand(ac, NULL, NULL, command, va);
	va_end(va);

	rdc_release(ac);
	return true;
}

