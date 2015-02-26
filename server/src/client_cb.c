/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_cb.c
 */
#include "client_cb.h"
#include "main.h"
#include "client_iterate.h"

#include <string.h>

bool
c_pong_cb(struct client *c, uint64_t id,
		unsigned int msgtype, Fep__Pong *msg, struct timeval *data)
{
	struct timeval tv;
	char *errmsg = NULL;
	if (msgtype != FEP__TYPE__tPong)
		errmsg = "Expected Pong only";

	if (errmsg)
		return send_error(c, id, errmsg, -1);

	gettimeofday(&tv, NULL);

	if (tv.tv_usec < data->tv_usec) {
		tv.tv_usec += 1000;
		tv.tv_sec++;
	}

	xsyslog(LOG_INFO, "client[%p] pong received in %"PRIu64".%06u seconds",
			(void*)c->cev,
			(uint64_t)(tv.tv_sec - data->tv_sec),
			(unsigned)(tv.tv_usec - data->tv_usec));
	return true;
}

bool
c_auth_cb(struct client *c, uint64_t id, unsigned int msgtype, void *msg, void *data)
{
	bool lval;
	char *errmsg = NULL;
	Fep__Auth *amsg = (Fep__Auth*)msg;
	/* ответы: Ok, Error, Pending */
	/* TODO: заглушка */
	if (msgtype != FEP__TYPE__tAuth) {
		errmsg = "Wanted only Auth message";
	} else if (c->state != CEV_AUTH) {
		errmsg = "Already authorized";
	} else if (strcmp(amsg->domain, "it-grad.ru")) {
		errmsg = "Domain not served";
	} else if (amsg->authtype != FEP__REQ_AUTH_TYPE__tUserToken) {
		errmsg = "Unknown auth scheme";
	} else if (!amsg->username || !amsg->authtoken) {
		errmsg = "Username or Token not passed";
	} else if (!amsg->username[0] || !amsg->authtoken[0]) {
		errmsg = "Username or Token has zero lenght";
	}

	if (errmsg) {
		lval = sendlog_error(c, id, errmsg, --c->count_error);
		if (c->count_error <= 0) {
			xsyslog(LOG_INFO, "client[%p] to many login attempts",
					(void*)c->cev);
			return false;
		}
		return lval;
	}
	c->state++;

	strcpy(c->name, amsg->username);
	xsyslog(LOG_INFO, "client[%p] authorized as %s", (void*)c->cev, c->name);
	if (!client_load(c)) {
		/* отправляем сообщение и выходим */
		send_error(c, id, "Can't load user info", 0);
		return false;
	}
	return send_ok(c, id);
}

