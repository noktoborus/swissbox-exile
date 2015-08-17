/* vim: ft=c ff=unix fenc=utf-8
 * file: rdc.c
 */
#include <hiredis/adapters/libev.h>
#include <errno.h>
#include <string.h>
#include "junk/xsyslog.h"

#include "rdc.h"

void rdc_init(struct rdc *r, struct ev_loop *loop, size_t limit)
{
}

void rdc_destroy(struct rdc *r)
{
}

static void
rdc_connect_cb(const redisAsyncContext *ac, int status)
{
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	pthread_mutex_lock(&nn->lock);
	if (status != REDIS_OK) {
		nn->assigned = false;
	}
	pthread_mutex_unlock(&nn->lock);
}

static void
rdc_disconnect_cb(const redisAsyncContext *ac, int status)
{
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	pthread_mutex_lock(&nn->lock);
	nn->assigned = false;
	pthread_mutex_unlock(&nn->lock);
}

static void
rdc_command_cb(redisAsyncContext *ac, redisReply *r, void *priv)
{
	struct rdc_node *nn = (struct rdc_node*)ac->data;
	/*xsyslog(LOG_INFO, "rdc#%03u command executed: %s", nn->num);*/
}

redisAsyncContext *
rdc_acquire(struct rdc *r, char *command)
{
	pthread_mutex_lock(&r->lock);
	/* 1. найти свободное подключение
	 * если активных подключений меньше, чем созданных,
	 * то определённо должно быть что-то свободное */
	if (r->c_active < r->c_count) {
		/* TODO */
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
		nn->ac = redisAsyncConnect(r->host, 6379);
		if (!nn->ac) {
			xsyslog(LOG_WARNING, "rdc: redis connect failed");
			pthread_mutex_unlock(&r->lock);
			if(nn->command)
				free(nn->command);
			free(nn);
			return NULL;
		}
		nn->ac->data = nn;
		pthread_mutex_init(&nn->lock, NULL);
		redisLibevAttach(r->loop, nn->ac);
		redisAsyncSetConnectCallback(nn->ac, rdc_connect_cb);
		redisAsyncSetDisconnectCallback(nn->ac, rdc_disconnect_cb);
		if (command)
			redisAsyncCommand(nn->ac, (redisCallbackFn*)rdc_command_cb,
					NULL, command);
		nn->assigned = true;
		nn->num = ++r->serial;
		nn->next = r->c;
		r->c = nn->next;
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
}

void
rdc_refresh(struct rdc *r)
{
	struct rdc_node *nn;
	/* обновление состояния подключений, если отвалились, то переподключить */
	pthread_mutex_lock(&r->lock);
	for (nn = r->c; nn; nn = nn->next) {
		if (pthread_mutex_trylock(&nn->next) || nn->assigned) {
			continue;
		}
		nn->ac = redisAsyncConnect(r->host, 6379);
		if (!nn->ac) {
			xsyslog(LOG_WARNING, "rdc: redis reconnect failed");
			continue;
		}
		nn->ac->data = nn;
		redisLibevAttach(r->loop, nn->ac);
		redisAsyncSetConnectCallback(nn->ac, rdc_connect_cb);
		redisAsyncSetDisconnectCallback(nn->ac, rdc_disconnect_cb);
		if (nn->command)
			redisAsyncCommand(nn->ac, (redisCallbackFn*)rdc_command_cb,
					NULL, command);
		nn->assigned = true;
		xsyslog(LOG_INFO, "rdc#%03u: reconnect", nn->num);
		pthread_mutex_unlock(&nn->next);
	}
	pthread_mutex_unlock(&r->lock);
}

