/* vim: ft=c ff=unix fenc=utf-8
 * file: main.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <curl/curl.h>
#include <confuse.h>

#include "../server/junk/xsyslog.h"
#include "keystone-client/keystone-client.h"

/*
 * 1. интерфейс к redis
 * 2. интерфейс к swift
 *
 */

struct w {
	struct {
		char *auth;
		char *service;
	} c;
	struct {
		char *url;
		char *tenant;
		char *user;
		char *secret;
	} t;
};

typedef struct w w_t;

void
swh_clear(w_t *w)
{
	if (w->c.auth) free(w->c.auth);
	if (w->c.service) free(w->c.service);

	if (w->t.url) free(w->t.url);
	if (w->t.tenant) free(w->t.tenant);
	if (w->t.user) free(w->t.user);
	if (w->t.secret) free(w->t.secret);

	memset(w, 0u, sizeof(w_t));
}

bool
swift_token(w_t *w)
{
	keystone_context_t kctx;
	enum keystone_error kerr;
	memset(&kctx, 0u, sizeof(keystone_context_t));

	keystone_start(&kctx);
#if 0
	keystone_set_debug(&kctx, 1);
#endif

	kerr = keystone_authenticate(&kctx,
			w->t.url, w->t.tenant, w->t.user, w->t.secret);

	if (kerr != KSERR_SUCCESS) {
		xsyslog(LOG_WARNING, "keystone auth: code %d", kerr);
		keystone_end(&kctx);
		return false;
	}

	{
		char *_t;
		if ((_t = (char*)keystone_get_auth_token(&kctx)) != NULL) {
			w->c.auth = strdup(_t);
		}
		if ((_t = (char*)keystone_get_service_url(&kctx,
						OS_SERVICE_SWIFT, 2, OS_ENDPOINT_URL_PUBLIC)) != NULL) {
			w->c.service = strdup(_t);
		}
	}

	xsyslog(LOG_DEBUG, "keystone auth: %s, url: %s", w->c.auth, w->c.service);
	keystone_end(&kctx);
	return true;
}

int
main(int argc, char *argv[])
{
	w_t w;
	memset(&w, 0u, sizeof(w_t));

	w.t.url = strdup("https://swissbox-swift.it-grad.ru/v2.0/tokens");
	w.t.tenant = strdup("project01");
	w.t.user = strdup("user01");
	w.t.secret = strdup("4edcMKI*");

	openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);
	xsyslog(LOG_INFO, "--- START ---");

	if (curl_global_init(CURL_GLOBAL_ALL))  {
		xsyslog(LOG_ERR, "Curl initialization failed");
		return EXIT_FAILURE;
	}
	/* begin */
	swift_token(&w);
	/* cleanup */
	xsyslog(LOG_INFO, "--- END ---");
	curl_global_cleanup();
	swh_clear(&w);
	return EXIT_SUCCESS;
}

