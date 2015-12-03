/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_cb.c
 */
#include "client_cb.h"
#include "main.h"
#include "client_iterate.h"
#include "as3/as3.h"

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

	xsyslog(LOG_INFO, "client[%"SEV_LOG"] pong received in %"PRIu64".%06u seconds",
			c->cev->serial,
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

	struct spq_hint hint;
	struct spq_UserInfo user;

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

	memset(&user, 0u, sizeof(struct spq_UserInfo));
	memset(&hint, 0u, sizeof(struct spq_hint));

	if (!spq_check_user(amsg->username, amsg->authtoken, amsg->device_id,
				&user, &hint)) {
		if (*hint.message)
			errmsg = hint.message;
		else
			errmsg = "Internal error 96";
	} else if (!user.authorized && *user.next_server) {
		/* TODO: выбор драйвера для авторизации */
		if (!as3_auth(user.next_server, amsg->username, amsg->authtoken,
				amsg->device_id)) {
			errmsg = "Incorrect external auth data";
		} else {
			xsyslog(LOG_INFO,
					"accept external user: '%s'",
					amsg->username);
			/* добавление пользователя в бд */
			if (!spq_add_user(amsg->username, amsg->authtoken, NULL)) {
				errmsg = "Internal error 116";
			}
		}
	} else if (!user.authorized) {
		errmsg = "Incorrect auth data";
	}

	if (errmsg) {
		lval = sendlog_error(c, id, errmsg, --c->count_error);
		if (c->count_error <= 0) {
			xsyslog(LOG_INFO, "client[%"SEV_LOG"] to many login attempts",
					c->cev->serial);
			return false;
		}
		return lval;
	}

	/* TODO: отправка State */
	c->state++;
	c->status.auth_ok = true;
	c->device_id = amsg->device_id;
	/* регистрация в списке и подписка на сообщения */
	if (!(c->cum = client_cum_create(hash_pjw(c->name, strlen(c->name))))) {
		send_error(c, id, "Internal error 135", 0);
		return false;
	}
	squeue_subscribe(&c->cum->broadcast, &c->broadcast_c);

	/* проверка на подключённое устройство с тем же device_id */
		pthread_mutex_lock(&c->cum->lock);
		if (!list_find(&c->cum->devices, c->device_id)) {
			/* никаких данных не передаётся
			 * вообще, список содержит только уникальные значения,
			 * что проверить уникальность device_id
			 * можно было бы и попыткой добавления в список,
			 * но так подробнее
			 */
			if (!list_alloc(&c->cum->devices, c->device_id, NULL) &&
					c->cev->pain->options.unique_device_id) {
				/*
				 * если не получилось добавить в список при включенных
				 * уникальных device_id, то нужно отключить клиента
				 */
				send_error(c, id, "Internal error 153", 0);
				pthread_mutex_unlock(&c->cum->lock);
				return false;
			}
		} else if (c->cev->pain->options.unique_device_id) {
			char __e[80] = {0};
			snprintf(__e, sizeof(__e),
					"Device id (%"PRIX64") already taken", c->device_id);
			send_error(c, id, __e, 0);
			pthread_mutex_unlock(&c->cum->lock);
			return false;
		}
		pthread_mutex_unlock(&c->cum->lock);

	strcpy(c->name, amsg->username);
	xsyslog(LOG_INFO, "client[%"SEV_LOG"] authorized as %s, device=%"PRIX64,
			c->cev->serial, c->name, c->device_id);
	if (!client_load(c)) {
		/* отправляем сообщение и выходим */
		send_error(c, id, "Can't load user info", 0);
		return false;
	}
	if (!send_ok(c, id, C_OK_SIMPLE, NULL))
		return false;
	/* отправка сообщения State */
	{
		Fep__State smsg = FEP__STATE__INIT;

		smsg.id = generate_id(c);
		smsg.has_devices = true;
		smsg.has_last_auth_device = true;
		smsg.devices = user.devices;
		smsg.last_auth_device = user.last_device;
		return send_message(c->cev, FEP__TYPE__tState, &smsg);
	}
}

