/* vim: ft=c ff=unix fenc=utf-8
 * file: curlev.h
 */
#ifndef _CURLEV_1447073509_H_
#define _CURLEV_1447073509_H_

#include <ev.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <stdint.h>
#include <stdbool.h>

#if 1
#include "xsyslog.h"
#else
#include <syslog.h>
#define xsyslog syslog
#endif


typedef size_t(*curlev_cb_t)(void *data, size_t size, void *priv);

struct curlev {
	CURLM *multi;
	bool timered;
	struct ev_timer timer;
	struct ev_loop *loop;
};

struct curlex {
	curlev_cb_t cb;
	void *cb_data;
};


bool cuev_init(struct curlev *cuev, struct ev_loop *loop);
void cuev_destroy(struct curlev *cuev);

bool cuev_emit(struct curlev *cuev, char *url, struct curl_slist *headers,
	curlev_cb_t cb, void *cb_data);

#endif /* _CURLEV_1447073509_H_ */

