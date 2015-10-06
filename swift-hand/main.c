/* vim: ft=c ff=unix fenc=utf-8
 * file: main.c
 */
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <curl/curl.h>
#include <confuse.h>
#include <polarssl/sha256.h>

#include <ev.h>

#include "junk/almsg.h"
#include "rdc.h"
#include "../server/junk/xsyslog.h"
#include "keystone-client/keystone-client.h"

/*
 * 1. интерфейс к redis
 * 2. интерфейс к swift
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
	struct {
		/* контейнер, куда будет падать всё,
		 * что оказалось без явного контейнера
		 */
		char *garbage_catalog;
	} e;
};

struct main {
	struct {
		char *redis_chan;
		char *name;
		char *cache_dir;
	} options;
	struct rdc rdc;
	struct w w;
	/* время последней активности */
	time_t laction;
};

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
swh_clear(struct w *w)
{
	if (w->c.auth) free(w->c.auth);
	if (w->c.service) free(w->c.service);

	if (w->t.url) free(w->t.url);
	if (w->t.tenant) free(w->t.tenant);
	if (w->t.user) free(w->t.user);
	if (w->t.secret) free(w->t.secret);

	memset(w, 0u, sizeof(*w));
}

bool
swift_token(struct w *w)
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
	time_t ctime;
	struct main *pain = (struct main*)ev_userdata(loop);
	rdc_refresh(&pain->rdc);
	/* простой */
	ctime = time(NULL);
	if (pain->laction && difftime(ctime, pain->laction) > 15) {
		xsyslog(LOG_DEBUG, "vacant state");
		pain->laction = 0;
	}
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
	pain->laction = time(NULL);
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

static size_t
_curl_nostd_cb(void *b, size_t size, size_t nmemb, void *p)
{
	return size * nmemb;
}

static CURL *
_curl_init(struct w *w, char *resource, struct curl_slist **header)
{
	CURL *curl = NULL;
	char buf[4096] = {0};

	if (!header) {
		xsyslog(LOG_ERR, "curl error: *header must be exists");
		exit(1);
	}

	snprintf(buf, sizeof(buf), "X-Auth-Token: %s", w->c.auth);
	*header = curl_slist_append(*header, buf);
	*header = curl_slist_append(*header,
			"Content-Type: application/octet-stream");
	if (!*header) {
		return NULL;
	}

	curl = curl_easy_init();
	if (!curl) {
		xsyslog(LOG_WARNING, "curl error: init failed");
		curl_slist_free_all(*header);
		return NULL;
	}

	if (resource) {
		snprintf(buf, sizeof(buf),
				(*resource == '/' ? "%s%s" : "%s/%s"),
				w->c.service, resource);
	} else {
		snprintf(buf, sizeof(buf), "%s", w->c.service);
	}

	curl_easy_setopt(curl, CURLOPT_URL, buf);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0l);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *header);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5l);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10l);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1l);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_nostd_cb);

	/*curl_easy_setopt(curl, CURLOPT_VERBOSE, 1l);*/

	return curl;
}

#define _CURL_BUF_CHUNK 1024
struct _curl_buf {
	char *data;
	size_t len;
	size_t size;
};

static size_t
_curl_read_to_buf_cb(void *ptr, size_t size, size_t n, struct _curl_buf *cbuf)
{
	size_t len = size * n;
	if (!len) {
		/*xsyslog(LOG_DEBUG, "");*/
		return 0u;
	}

	if (cbuf->len + len > cbuf->size) {
		size_t _ts = 0u;
		char *_tb;
		_ts = (1 + (cbuf->len + len) / _CURL_BUF_CHUNK) * _CURL_BUF_CHUNK + 1;
		_tb = realloc(cbuf->data, _ts);
		if (!_tb) {
			xsyslog(LOG_WARNING, "relloc(%"PRIuPTR"):541 failed: %s",
					_ts, strerror(errno));
			return 0u;
		}
		cbuf->data = _tb;
		cbuf->size = _ts;
	}

	memcpy(&cbuf->data[cbuf->len], ptr, len);
	cbuf->len += len;
	cbuf->data[cbuf->len] = '\0';

	return len;
}

bool
ossw_v1_create_container(struct w *w, char *container)
{
	/* создать или проверить существование контейнера
	 * отправка PUT-запроса на адрес контейнера, ответы:
	 *  HTTP 201 - контейнер создан
	 *  HTTP 202 - контейнер существует
	 */
	CURL *curl;
	CURLcode res;
	long httpcode;
	struct curl_slist *header = NULL;

	if (!(curl = _curl_init(w, container, &header))) {
		return false;
	}

	curl_easy_setopt(curl, CURLOPT_PUT, 1l);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		xsyslog(LOG_WARNING, "curl perform:606 error: %s",
				curl_easy_strerror(res));
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
	curl_easy_cleanup(curl);
	curl_slist_free_all(header);

	if (httpcode == 201l || httpcode == 202l) {
		return true;
	}
	xsyslog(LOG_WARNING, "creation container '%s' failed: %ld",
			container, httpcode);
	return false;
}

char *
ossw_v1_first_container(struct w *w)
{
	CURL *curl;
	CURLcode res;
	struct _curl_buf cbuf;
	char *container = NULL;
	struct curl_slist *header = NULL;
	/* http://docs.rackspace.com/files/api/v1/cf-devguide/content/containerServicesOperations_d1e000.html
	 */

	if (!(curl = _curl_init(w, NULL, &header))) {
		return NULL;
	}

	/* TODO */
	memset(&cbuf, 0u, sizeof(cbuf));
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_read_to_buf_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &cbuf);
	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		xsyslog(LOG_WARNING, "curl perform:551 error: %s",
				curl_easy_strerror(res));
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(header);

	xsyslog(LOG_DEBUG, "containers: (%"PRIuPTR") %s", cbuf.len, cbuf.data);

	if (cbuf.len) {
		char *_p;
		_p = strchr(cbuf.data, '\n');
		if (_p)
			*_p = '\0';
		container = strdup(cbuf.data);
	}

	if (cbuf.data)
		free(cbuf.data);

	return container;
}

bool
ossw_v1_upload(struct w *w, const char *path, char *container, char *uniq_name,
		char target_resource[PATH_MAX])
{
	/*
	http://docs.rackspace.com/files/api/v1/cf-devguide/content/objectServicesOperations_d1e000.html
	*/
	/* 4Кб для url должно хватить */
	char buf[4096];
	bool retval = true;
	CURL *curl;
	CURLcode res;
	long httpcode = 0l;
	struct curl_slist *header = NULL;
	off_t file_sz = 0ul;
	FILE *file_src = NULL;
	struct stat st;

	if (stat(path, &st) == -1) {
		xsyslog(LOG_WARNING, "stat(%s) failed: %s",
				path, strerror(errno));
		return false;
	}

	if (st.st_size == 0ul) {
		/* TODO: не нужно сообщать или использовать какую-то метку
		 * в нормальных ситуациях файлов с _нулевым_ размером быть не должно
		 */
		xsyslog(LOG_INFO, "stat(%s) file size is zero",
				path);
		return false;
	}

	if (!(file_src = fopen(path, "r"))) {
		/* TODO: предпологается что ошибка постоянная, потому нужно
		 * ставить какой-то флаг, что этот файл не операбелен
		 */
		xsyslog(LOG_WARNING, "fopen(%s) error: %s", path, strerror(errno));
		return false;
	}


	if (!container || !*container) {
		container = w->e.garbage_catalog;
	}

	if (!*container) {
		xsyslog(LOG_INFO, "container not setted for upload");
		fclose(file_src);
		return false;
	}

	if (!ossw_v1_create_container(w, container)) {
		fclose(file_src);
		return false;
	}

	snprintf(buf, sizeof(buf), "%s/%s", container, uniq_name);
	if (!(curl = _curl_init(w, buf, &header))) {
		fclose(file_src);
		return false;
	}

	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl, CURLOPT_PUT, 1L);

	curl_easy_setopt(curl, CURLOPT_READDATA, file_src);

	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
			(curl_off_t)file_sz);

	{
		char *_tr = NULL;
		curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &_tr);
		if (_tr) {
			/* отбрасывается базовая часть */
			_tr += strlen(w->c.service);
			memset(target_resource, 0u, PATH_MAX);
			memcpy(target_resource, _tr, strlen(_tr));
		} else {
			xsyslog(LOG_WARNING, "curl error: no url for '%s'", path);
			fclose(file_src);
			curl_easy_cleanup(curl);
			curl_slist_free_all(header);
			return false;
		}
	}

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		xsyslog(LOG_WARNING, "curl perform error: %s",
				curl_easy_strerror(res));
		retval = false;
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);

	if (httpcode != 201l) {
		xsyslog(LOG_WARNING, "upload(%s) not completed, response code: %ld",
				path, httpcode);
		retval = false;
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(header);
	fclose(file_src);

	return retval;
}

bool
process_file(struct main *pain, const char *owner, const char *path,
		char target_resource[PATH_MAX])
{
	/* предпологается что путь к файлу представляет собой уникальный
	 * идентификатор, потому уникальное имя файла
	 * представляешь собой хеш от пути
	 *
	 * имя пользователя используется в качестве контейнера
	 */
	char h_sha256[32] = {0};
	char h_sha256_hex[128] = {0};
	memset(h_sha256, 0u, sizeof(h_sha256));
	memset(h_sha256_hex, 0u, sizeof(h_sha256_hex));
	sha256((const unsigned char*)path, strlen(path),
			(unsigned char *)h_sha256, 0);
	bin2hex((uint8_t*)h_sha256, sizeof(h_sha256) * sizeof(uint8_t),
			h_sha256_hex, sizeof(h_sha256_hex));
	/* попытки залить файл */
	if (ossw_v1_upload(&pain->w, path, (char*)owner, h_sha256_hex,
				target_resource)) {
		return true;
	}

	return false;
}

void
rdc_blpop_cb(redisAsyncContext *ac, redisReply *r, struct main *pain)
{
	struct almsg_parser ap;
	const char *id = NULL;
	const char *owner = NULL;
	const char *path = NULL;
	char _path[PATH_MAX];
	char target_resource[PATH_MAX];
	if (!r)
		return;

	pain->laction = time(NULL);

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
	path = almsg_get(&ap, PSLEN_S("file"), ALMSG_ALL);

	if (!path || !owner || !id) {
		xsyslog(LOG_WARNING, "no data for process: "
				"(id='%s', owner='%s', path='%s')",
				id, owner, path);
		almsg_destroy(&ap);
		return;
	}

	snprintf(_path, sizeof(_path), "%s/%s", pain->options.cache_dir, path);
	if (process_file(pain, owner, path, target_resource)) {
		struct almsg_parser rap;
		char *rap_buf = NULL;
		size_t rap_bsz;
		almsg_init(&rap);
		almsg_insert(&rap, PSLEN_S("from"), PSLEN(pain->options.name));
		almsg_insert(&rap, PSLEN_S("action"), PSLEN_S("accept"));
		almsg_insert(&rap, PSLEN_S("id"), PSLEN(id));
		almsg_insert(&rap, PSLEN_S("driver"), PSLEN_S("swift"));
		almsg_insert(&rap, PSLEN_S("address"), PSLEN(target_resource));

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
	memset(&pain, 0u, sizeof(struct main));

	if (argc < 2) {
		fprintf(stderr, "usage: %s server.conf\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* базовые значения */
	pain.options.redis_chan = strdup("fep_broadcast");
	pain.options.name = strdup("swift-hand");
	pain.options.cache_dir = strdup("../server/user");

	pain.w.t.url = strdup("https://swissbox-swift.it-grad.ru/v2.0/tokens");
	pain.w.t.tenant = strdup("project01");
	pain.w.t.user = strdup("user01");
	pain.w.t.secret = strdup("4edcMKI*");
	pain.w.e.garbage_catalog = strdup("~unknown~");

	/* получение конфигурации */
	{
		cfg_opt_t opt[] = {
			CFG_SIMPLE_STR("bind", CFGF_NONE),
			CFG_SIMPLE_STR("pidfile", CFGF_NONE),
			CFG_SIMPLE_STR("pg_connstr", CFGF_NONE),
			CFG_SIMPLE_STR("redis_chan", &pain.options.redis_chan),
			CFG_SIMPLE_STR("cache_dir", &pain.options.cache_dir),
			CFG_END()
		};
		cfg_opt_t opt_priv[] = {
			CFG_SIMPLE_STR("name", &pain.options.name),
			CFG_SIMPLE_STR("cache_dir", &pain.options.cache_dir),
			CFG_SIMPLE_STR("swift_url", &pain.w.t.url),
			CFG_SIMPLE_STR("swift_tenant", &pain.w.t.tenant),
			CFG_SIMPLE_STR("swift_user", &pain.w.t.user),
			CFG_SIMPLE_STR("swift_secret", &pain.w.t.secret),
			CFG_SIMPLE_STR("garbage_catalog", &pain.w.e.garbage_catalog),
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
#if 1
	if (curl_global_init(CURL_GLOBAL_ALL))  {
		xsyslog(LOG_ERR, "Curl initialization failed");
		return EXIT_FAILURE;
	}
#endif
	/* begin */
	swift_token(&pain.w);
	rloop(&pain);
	/* cleanup */
	xsyslog(LOG_INFO, "--- END ---");
#if 1
	curl_global_cleanup();
#endif
	swh_clear(&pain.w);

	free(pain.options.redis_chan);
	free(pain.options.name);
	free(pain.options.cache_dir);

	return EXIT_SUCCESS;
}

