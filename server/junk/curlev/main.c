/* vim: ft=c ff=unix fenc=utf-8
 * file: main.c
 * ${CC} -I../ -std=c99 -ggdb2 -D_DEFAULT_SOURCE main.c curlev.c -lev -lcurl
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "curlev.h"

static size_t
cb(void *data, size_t size, void *priv)
{
	xsyslog(LOG_DEBUG, "### got data[%p] in %"PRIuPTR" bytes (%"PRIuPTR")",
			(void*)data, size, (size_t)priv);
	return size;
}

static void
runner_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	static size_t c = 0;
	char *url = "http://ya.ru";
	struct curlev *cuev = ev_userdata(loop);
	/* генератор урлов для получения данных */
	xsyslog(LOG_INFO, "get url: %s", url);

	c++;
	cuev_emit(cuev, url, NULL, cb, (void*)c);
}

int
main(int argc, char *argv[])
{
	struct curlev cuev = {0};

	struct ev_loop *loop = EV_DEFAULT;
	struct ev_timer runner;

	ev_set_userdata(loop, &cuev);
	cuev_init(&cuev, loop);

	openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);

	ev_timer_init(&runner, runner_cb, 2., 1.);
	ev_timer_start(loop, &runner);

	ev_run(loop, 0);

	ev_timer_stop(loop, &runner);
	cuev_destroy(&cuev);
	ev_loop_destroy(loop);
	closelog();
	return EXIT_SUCCESS;
}

