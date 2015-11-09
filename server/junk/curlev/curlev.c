/* vim: ft=c ff=unix fenc=utf-8
 * file: curlev.c
 * пример использования curl multi и libev
*/
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>

#include "curlev.h"

static size_t
_curl_write_cb(void *ptr, size_t size, size_t nmemb, struct curlex *ex)
{
	if (ex && ex->cb) {
		return ex->cb(ptr, size * nmemb, ex->cb_data);
	}
	return size * nmemb;
}

static void
_ev_event_curl_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct curlev *cuev = w->data;
	CURLMcode cc;
	int curla = (revents & EV_READ ? CURL_POLL_IN : 0) |
		( revents & EV_WRITE ? CURL_POLL_OUT : 0);
	int running = 0;

	cc = curl_multi_socket_action(cuev->multi, w->fd, curla, &running);
	/* TODO: ? */
	/* проверка состояния */
	{
		int _msgs = 0;
		CURLMsg *_msg = NULL;
		CURL *_easy = NULL;
		struct curlex *_ex = NULL;
		while ((_msg = curl_multi_info_read(cuev->multi, &_msgs)) != NULL) {
			if (_msg->msg == CURLMSG_DONE) {
				_easy = _msg->easy_handle;
				/* освбождение всякого мусора */
				curl_multi_remove_handle(cuev->multi, _easy);
				if (curl_easy_getinfo(_easy, CURLINFO_PRIVATE, &_ex) && _ex) {
					free(_ex);
				}
				curl_easy_cleanup(_easy);
			}
		} /* while */
	}

}

static void
_ev_timer_curl_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	int running = 0;
	struct curlev *cuev = w->data;
	curl_multi_socket_action(cuev->multi, CURL_SOCKET_TIMEOUT, 0, &running);
	xsyslog(LOG_INFO, "ev timer: %p, running: %d", (void*)cuev, running);
}

static int
_curl_timer_cb(CURLM *multi, long timeout_ms, struct curlev *cuev)
{
	if (cuev->timered) {
		ev_timer_stop(cuev->loop, &cuev->timer);
		cuev->timered = false;
	}
	xsyslog(LOG_INFO, "curl update timer to %ldms", timeout_ms);
	if (timeout_ms > 0) {
		double _t = timeout_ms / 1000.0;
		ev_timer_set(&cuev->timer, _t, 0.);
		ev_timer_start(cuev->loop, &cuev->timer);
		cuev->timered = true;
	} else {
		_ev_timer_curl_cb(cuev->loop, &cuev->timer, 0);
	}
	return 0;
}

static int
_curl_socket_cb(CURL *e, curl_socket_t s, int what,
		struct curlev *cuev, struct ev_io *evio)
{
	xsyslog(LOG_INFO, "socket #%d action: %d, evio %p", s, what, evio);
	/* события curl с сокетами (what):
	 * CURL_POLL_NONE: ничего
	 * CURL_POLL_REMOVE: удаление
	 * CURL_POLL_IN: регистрирация для чтения
	 * CURL_POLL_OUT: регистрация для записи
	 * CURL_POLL_INOUT: регистрация для чтения и записи
	 *
	 * до вызова curl_multi_assign() аргумент evio == NULL
	 */
	if (what == CURL_POLL_REMOVE) {
		xsyslog(LOG_DEBUG, "curl remove socket #%d", s);
		if (!evio) {
			xsyslog(LOG_WARNING, "curl: no data to remove");
			return 0;
		}
		ev_io_stop(cuev->loop, evio);
		free(evio);
	} else {
		int eva = (what & CURL_POLL_IN ? EV_READ : 0) |
			(what & CURL_POLL_OUT ? EV_WRITE : 0);
		if (!evio) {
			xsyslog(LOG_DEBUG, "curl alloc socket #%d (action: %d)", s, eva);
			/* не проциниализировано */
			evio = calloc(1, sizeof(struct ev_io));
			evio->data = cuev;
			ev_io_init(evio, _ev_event_curl_cb, s, eva);
			ev_io_start(cuev->loop, evio);
			curl_multi_assign(cuev->multi, s, evio);
		} else {
			xsyslog(LOG_DEBUG, "curl update socket #%d (action: %d)", s, eva);
			/* изменение состояния */
			ev_io_stop(cuev->loop, evio);
			ev_io_set(evio, s, eva);
			ev_io_start(cuev->loop, evio);
		}
	}
	return 0;
}

bool
cuev_init(struct curlev *cuev, struct ev_loop *loop)
{
	memset(cuev, 0, sizeof(*cuev));
	cuev->loop = loop;

	cuev->multi = curl_multi_init();
	curl_multi_setopt(cuev->multi, CURLMOPT_SOCKETFUNCTION, _curl_socket_cb);
	curl_multi_setopt(cuev->multi, CURLMOPT_SOCKETDATA, cuev);

	curl_multi_setopt(cuev->multi, CURLMOPT_TIMERFUNCTION, _curl_timer_cb);
	curl_multi_setopt(cuev->multi, CURLMOPT_TIMERDATA, cuev);

	/* инициализация колбека для таймера */
	ev_timer_init(&cuev->timer, _ev_timer_curl_cb, 0., 0.);
	cuev->timer.data = cuev;

	return true;
}

void
cuev_destroy(struct curlev *cuev)
{
	if (!cuev)
		return;
	if (cuev->multi)
		curl_multi_cleanup(cuev->multi);
	if (cuev->timered)
		ev_timer_stop(cuev->loop, &cuev->timer);
	memset(cuev, 0, sizeof(*cuev));
}

bool
cuev_emit(struct curlev *cuev, char *url, struct curl_slist *headers,
	curlev_cb_t cb, void *cb_data)
{
	struct curlex *ex = NULL;
	CURL *easy = curl_easy_init();
	CURLMcode code;
	if (!easy) {
		xsyslog(LOG_WARNING, "curl_easy_init() failed for url '%s' (errno: %d)",
				url, errno);
		return false;
	}
	curl_easy_setopt(easy, CURLOPT_URL, url);
	curl_easy_setopt(easy, CURLOPT_VERBOSE, 0L);

	curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);

	curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, _curl_write_cb);
	if (cb) {
		ex = calloc(1, sizeof(*ex));
		if (!ex) {
			xsyslog(LOG_WARNING, "cuev_emit() failed: calloc(%d) with errno: %d",
				   (int)sizeof(*ex), errno);
			curl_easy_cleanup(easy);
			return false;
		}
		curl_easy_setopt(easy, CURLOPT_WRITEDATA, ex);
		curl_easy_setopt(easy, CURLOPT_PRIVATE, ex);
	} else {
		curl_easy_setopt(easy, CURLOPT_WRITEDATA, NULL);
		curl_easy_setopt(easy, CURLOPT_PRIVATE, NULL);
	}

	if (headers) {
		/* TODO: добавить хидеры */
	}

	if ((code = curl_multi_add_handle(cuev->multi, easy)) != CURLM_OK) {
		xsyslog(LOG_WARNING, "curl_multi_add_handle() failed for url '%s', code: %d",
				url, code);
		curl_easy_cleanup(easy);
		return false;
	}
	return true;
}

