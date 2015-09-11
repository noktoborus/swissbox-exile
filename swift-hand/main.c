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

#include "junk/almsg.h"
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
		char *name;
		char *cache_dir;
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
initiate(struct main *pain)
{
	/* отправка сообщения от том, что хочется получится список файлов
	 * для переноса
	 */
	char *_a = NULL;
	size_t _l = 0u;
	struct almsg_parser ap;
	almsg_init(&ap);
	almsg_append(&ap, PSLEN("from"), PSLEN(pain->options.name));
	almsg_append(&ap, PSLEN("action"), PSLEN("files"));
	almsg_append(&ap, PSLEN("channel"), PSLEN(pain->options.redis_chan));

	almsg_format_buf(&ap, &_a, &_l);
	rdc_exec_once(&pain->rdc, NULL, NULL, "PUBLISH %s %b",
			pain->options.redis_chan, _a, _l);
	almsg_destroy(&ap);
}

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

static void
rdc_broadcast_cb(redisAsyncContext *ac, redisReply *r, struct main *pain)
{
	struct almsg_parser ap;
	if (!r || r->elements != 3)
		return;
	if (r->type != REDIS_REPLY_ARRAY || r->elements != 3) {
		return;
	}
	xsyslog(LOG_INFO, "broadcast data in chan: '%s' (%d bytes)",
			r->element[1]->str, r->element[1]->len);
	/* разбор буфера */
	almsg_init(&ap);
	if (almsg_parse_buf(&ap, r->element[2]->str, r->element[2]->len)) {
		uint32_t _hash;
		const char *_action = NULL;
		_action = almsg_get(&ap, PSLEN_S("action"), ALMSG_ALL);
		if (!_action) {
			almsg_destroy(&ap);
			return;
		}
		_hash = hash_pjw(_action, strlen(_action));
		/* TODO: заменить на таблицу */
		if (_hash == hash_pjw(PSLEN_S("server-starts"))) {
			/* сообщение от сервера что он запустился,
			 * можно дёрнуть список файлов
			 */
			initiate(pain);
		}
	}
	almsg_destroy(&ap);
	return;
}

bool
process_file(struct main *pain, const char *owner, const char *path)
{
	/* TODO: ... */
	return true;
}

void
rdc_blpop_cb(redisAsyncContext *ac, redisReply *r, struct main *pain)
{
	struct almsg_parser ap;
	const char *id;
	const char *owner;
	const char *path;
	if (!r)
		return;

	if (r->elements != 2 && r->type != REDIS_REPLY_ARRAY) {
		xsyslog(LOG_WARNING,
				"redis broadcast unknown data: type=%d, elements=%"PRIuPTR,
				r->type, r->elements);
		return;
	}

	if (r->element[1]->type != REDIS_REPLY_STRING) {
		xsyslog(LOG_WARNING,
				"redis broadcast shit: element[1].type != STRING (%d)",
				r->element[1]->type);
		return;
	}
	almsg_init(&ap);
	almsg_parse_buf(&ap, r->element[1]->str, r->element[1]->len);

	id = almsg_get(&ap, PSLEN_S("id"), ALMSG_ALL);
	owner = almsg_get(&ap, PSLEN_S("owner"), ALMSG_ALL);
	path = almsg_get(&ap, PSLEN_S("path"), ALMSG_ALL);

	if (process_file(pain, owner, path)) {
		struct almsg_parser rap;
		char *rap_buf = NULL;
		size_t rap_bsz;
		almsg_init(&rap);
		almsg_insert(&rap, PSLEN_S("from"), PSLEN(pain->options.name));
		almsg_insert(&rap, PSLEN_S("action"), PSLEN_S("accept"));
		almsg_insert(&rap, PSLEN_S("id"), PSLEN(id));
		almsg_insert(&rap, PSLEN_S("driver"), PSLEN_S("dev"));
		almsg_insert(&rap, PSLEN_S("address"), PSLEN_S("null"));

		if (!almsg_format_buf(&rap, &rap_buf, &rap_bsz)) {
			xsyslog(LOG_WARNING, "almsg format buffer error");
		} else {
			rdc_exec_once(&pain->rdc, NULL, NULL, "PUBLISH %s %b",
					pain->options.redis_chan, rap_buf, rap_bsz);
			free(rap_buf);
			xsyslog(LOG_INFO, "file id#%s moved", id);
			/* отправка сообщения об успешном переносе */
		}
		almsg_destroy(&rap);
	} else {
		xsyslog(LOG_INFO, "file id#%s not moved", id);
	}

	almsg_destroy(&ap);
	return;
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
	/* регистрация на редисе */
	{
		char _buf[1024];
		snprintf(_buf, sizeof(_buf), "SUBSCRIBE %s", pain->options.redis_chan);
		rdc_subscribe(&pain->rdc,
				(redisCallbackFn*)rdc_broadcast_cb, pain, _buf);
		snprintf(_buf, sizeof(_buf), "BLPOP %s 0", pain->options.redis_chan);
		rdc_exec_period(&pain->rdc,
				(redisCallbackFn*)rdc_blpop_cb, pain, _buf);
		initiate(pain);
	}

	ev_run(loop, 0);

	rdc_destroy(&pain->rdc);


	ev_signal_stop(loop, &sigpipe);
	ev_timer_stop(loop, &timeout);
	ev_loop_destroy(loop);
}

int
main(int argc, char *argv[])
{
	struct main pain;
	cfg_t *cfg;
	cfg_t *pcfg;
	w_t w;
	memset(&w, 0u, sizeof(w_t));
	memset(&pain, 0u, sizeof(struct main));

	if (argc < 2) {
		fprintf(stderr, "usage: %s server.conf\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* базовые значения */
	pain.options.redis_chan = strdup("fep_broadcast");
	pain.options.name = strdup("swift-hand");
	pain.options.cache_dir = strdup("../server/user");

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
			CFG_SIMPLE_STR("cache_dir", &pain.options.cache_dir),
			CFG_END()
		};
		cfg_opt_t opt_priv[] = {
			CFG_SIMPLE_STR("name", &pain.options.name),
			CFG_SIMPLE_STR("cache_dir", &pain.options.cache_dir),
			CFG_END()
		};
		cfg = cfg_init(opt, 0);
		pcfg = cfg_init(opt_priv, 0);
		cfg_parse(cfg, argv[1]);
		cfg_parse(pcfg, "swift-hand.conf");
		cfg_free(cfg);
		cfg_free(pcfg);
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
	free(pain.options.name);
	free(pain.options.cache_dir);

	return EXIT_SUCCESS;
}

