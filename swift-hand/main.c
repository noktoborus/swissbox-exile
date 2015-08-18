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

#include <ev.h>

#include "rdc.h"
#include "../server/junk/xsyslog.h"
#include "keystone-client/keystone-client.h"

/*
 * 1. интерфейс к redis
 * 2. интерфейс к swift
 *
 */

struct main {
	struct {
		char *redis_chan;
	} options;
	struct rdc rdc;
};

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

void
signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	xsyslog(LOG_INFO, "SIG#%d, exit", w->signum);
	ev_break(loop, EVBREAK_ALL);
}

void
signal_ignore_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	xsyslog(LOG_INFO, "SIG#%d, ignore", w->signum);
}

void
timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct main *pain = (struct main*)ev_userdata(loop);
	rdc_refresh(&pain->rdc);
}

void
rloop(struct main *pain)
{
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal sigint;
	ev_signal sigpipe;
	ev_timer timeout;
	/* инициализация */
	ev_signal_init(&sigint, signal_cb, SIGINT);
	ev_signal_init(&sigpipe, signal_ignore_cb, SIGPIPE);
	ev_timer_init(&timeout, timeout_cb, 1., 5.);

	ev_signal_start(loop, &sigint);
	ev_signal_start(loop, &sigpipe);
	ev_timer_start(loop, &timeout);

	ev_set_userdata(loop, (void*)pain);

	rdc_init(&pain->rdc, loop, "localhost", 10);

	ev_run(loop, 0);

	rdc_destroy(&pain->rdc);

	/* деинициализация */

	ev_signal_stop(loop, &sigint);
	ev_signal_stop(loop, &sigpipe);
	ev_timer_stop(loop, &timeout);
	ev_loop_destroy(loop);
}

int
main(int argc, char *argv[])
{
	struct main pain;
	cfg_t *cfg;
	w_t w;
	memset(&w, 0u, sizeof(w_t));
	memset(&pain, 0u, sizeof(struct main));

	if (argc < 2) {
		fprintf(stderr, "usage: %s server.conf\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* базовые значения */
	pain.options.redis_chan = strdup("fep_broadcast");

	w.t.url = strdup("https://swissbox-swift.it-grad.ru/v2.0/tokens");
	w.t.tenant = strdup("project01");
	w.t.user = strdup("user01");
	w.t.secret = strdup("4edcMKI*");

	/* получение конфигурации */
	{
		cfg_opt_t opt[] = {
			CFG_SIMPLE_STR("bind", CFGF_NONE),
			CFG_SIMPLE_STR("pg_connstr", CFGF_NONE),
			CFG_SIMPLE_STR("redis_chan", &pain.options.redis_chan),
			CFG_END()
		};
		cfg = cfg_init(opt, 0);
		cfg_parse(cfg, argv[1]);
	}

	openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);
	xsyslog(LOG_INFO, "--- START ---");
#if 0
	if (curl_global_init(CURL_GLOBAL_ALL))  {
		xsyslog(LOG_ERR, "Curl initialization failed");
		return EXIT_FAILURE;
	}
#endif
	/* begin */
	/*swift_token(&w);*/
	rloop(&pain);
	/* cleanup */
	xsyslog(LOG_INFO, "--- END ---");
#if 0
	curl_global_cleanup();
#endif
	swh_clear(&w);

	free(pain.options.redis_chan);

	return EXIT_SUCCESS;
}

