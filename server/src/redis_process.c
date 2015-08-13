/* vim: ft=c ff=unix fenc=utf-8
 * file: src/redis_process.c
 */
#include <stdbool.h>
#include <string.h>

#include "simplepq/simplepq.h"

#include "main.h"
#include "junk/utils.h"
#include "junk/xsyslog.h"
#include "junk/almsg.h"

void
almsg2redis(struct main *pain, const char *cmd, const char *chan,
		struct almsg_parser *alm)
{
	char *p = NULL;
	size_t l = 0u;

	almsg_format_buf(alm, &p, &l);
	if (p) {
		if (l)
			redis_t(pain, cmd, chan, p, l);
		free(p);
	} else {
		xsyslog(LOG_WARNING, "almsg2redis: empty buffer (elem: %"PRIuPTR")",
				almsg_count(alm, NULL, 0u));
	}
}

static bool
_action_accept(struct almsg_parser *p, const char *val, size_t val_len,
	size_t i, struct main *pain)
{
	const char *driver = NULL;
	const char *address = NULL;

	driver = almsg_get(p, PSLEN("driver"), i);
	address = almsg_get(p, PSLEN("address"), i);
	if (!driver || !address) {
		xsyslog(LOG_WARNING, "empty driver ('%s') or address ('%s') "
				"for file id#%s", driver, address, val);
		return false;
	}

	/* TODO: завершение переноса */
	xsyslog(LOG_INFO, "file id#%s moved to %s:%s", val, driver, address);
	return true;
}

/*
 * сообщениие серверу, что файл перенесён
 * Запрос (может содержать несколько файлов):
 *  from: <unique nodename>
 *  action: accept
 *  id: <file id>
 *  driver: <driver name>
 *  address: <new path to file>
 *  [id: <file id>]
 *  [driver: <driver name>]
 *  [address: <new path to file]
 *
 * Ответ:
 *  from: <unique nodename>
 *  response: accept
 *  id: <file id>
 */
static bool
action_accept(struct main *pain, struct almsg_parser *alm, char *action)
{
	/* 1. обработать сообщение */
	almsg_each(alm, PSLEN("id"), ALMSG_ALL,
			(almsg_each_cb)_action_accept, pain);
	/* 2. обновить значения в бд */
	/* 3. сформировать ответ */
	return true;
}

/*
 * получение списка файлов
 * запрос:
 *  from: <unique nodename>
 *  action: files
 *  [channel: <response channel>]
 *  [split: <number of lines>]
 *
 * ответ:
 *  from: <unique nodename>
 *  response: files
 *
 * результирующий список:
 *  from: <unique nodename>
 *  action: files
 *  file: <path to file>
 *  id: <file id>
 *  owner: <file owner>
 */
static bool
action_files(struct main *pain, struct almsg_parser *alm, char *action)
{
	const char *tmp;
	const char *chan = almsg_get(alm, PSLEN("channel"), ALMSG_ALL);
	unsigned long split = 0u;
	if ((tmp = almsg_get(alm, PSLEN("split"), ALMSG_ALL)) != NULL) {
		split = strtoul(tmp, NULL, 10);
	}
	/* сбрасываем состояние */
	almsg_reset(alm, false);
	/* получение списка */
	{
		struct almsg_parser ap;
		struct getLocalFiles lf;
		char _cc[64];
		size_t i = 0u;
		memset(&ap, 0u, sizeof(struct getLocalFiles));
		memset(&lf, 0u, sizeof(struct getLocalFiles));
		almsg_init(&ap);

		spq_getLocalFiles(&lf, NULL);

		snprintf(_cc, sizeof(_cc), "%u", lf.max);
		almsg_append(alm, PSLEN("count"), PSLEN(_cc));

		for (i = 0u; spq_getLocalFiles_it(&lf); i++) {
			snprintf(_cc, sizeof(_cc), "%"PRIu64, lf.file_id);
			almsg_append(&ap, PSLEN("from"), PSLEN(pain->options.name));
			almsg_append(&ap, PSLEN("id"), PSLEN(_cc));
			almsg_append(&ap, PSLEN("file"), PSLEN(lf.path));
			almsg_append(&ap, PSLEN("owner"), PSLEN(lf.owner));
			/* разделение сообщений */
			if (i == split || !split) {
				almsg2redis(pain, "LPUSH", chan, &ap);
				almsg_reset(&ap, false);
				/* обнуление счётчика для простоты счёта */
				i = 0u;
			}
		}
		if (almsg_count(&ap, NULL, 0u)) {
			almsg2redis(pain, "LPUSH", chan, &ap);
		}

		/* отчистка */
		spq_getLocalFiles_free(&lf);
		almsg_destroy(&ap);
	}
	/* формируем ответ */
	return true;
}

static struct redis_actions {
	uint32_t action;
	bool (*f)(struct main*, struct almsg_parser*, char*);
	char action_str[32];
} _actions[] = {
	{ 0u, action_files, "files"},
	{ 0u, action_accept, "accept"},
	{ 0u, NULL, "" }
};

bool
redis_process(struct redis_c *rds, const char *data, size_t size)
{
	struct almsg_parser alm;
	const char *action;
	almsg_init(&alm);
	if (!almsg_parse_buf(&alm, data, size)) {
		xsyslog(LOG_DEBUG, "invalid input data (%"PRIuPTR") %s",
				size, data);
	} else if ((action = almsg_get(&alm, PSLEN("action"), ALMSG_ALL)) != NULL) {
		size_t i;
		uint32_t hash = hash_pjw(PSLEN(action));
		for (i = 0u; _actions[i].f; i++) {
			if (_actions[i].action == 0u) {
				_actions[i].action =
					hash_pjw(PSLEN(_actions[i].action_str));
			}
			if (_actions[i].action == hash) {
				if (_actions[i].f(rds->pain, &alm, _actions[i].action_str)) {
					/* добавление специальных полей */
					almsg_insert(&alm,
							PSLEN("response"), PSLEN(_actions[i].action_str));
					almsg_insert(&alm,
							PSLEN("from"), PSLEN(rds->pain->options.name));

					/* формирование буфера и отправка ответа */
					almsg2redis(rds->pain, "PUBLISH", NULL, &alm);
				}
			}
		}
	}

	almsg_destroy(&alm);
	return true;
}


