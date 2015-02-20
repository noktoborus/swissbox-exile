/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_cb.c
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <inttypes.h>

#include "client_cb.h"

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
	}

	if (errmsg) {
		lval = send_error(c, id, errmsg, --c->count_error);
		if (c->count_error <= 0) {
			xsyslog(LOG_INFO, "client[%p] to many login attempts",
					(void*)c->cev);
			return false;
		}
		return lval;
	}
	c->state++;

	return send_ok(c, id);
}

