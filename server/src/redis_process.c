/* vim: ft=c ff=unix fenc=utf-8
 * file: src/redis_process.c
 */
#include <stdbool.h>
#include <string.h>

#include "main.h"
#include "junk/utils.h"
#include "junk/xsyslog.h"
#include "junk/almsg.h"

/*
 * получение списка файлов
 */
static bool
action_files(struct main *pain, struct almsg_parser *alm, char *action)
{
	/* сбрасываем состояние */
	almsg_reset(alm, false);
	/* формируем ответ */
	almsg_add(alm, PSLEN("from"), PSLEN(pain->options.name));
	return true;
}

static struct redis_actions {
	uint32_t action;
	bool (*f)(struct main*, struct almsg_parser*, char*);
	char action_str[32];
} _actions[] = {
	{ 0u, action_files, "files"},
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
	} else if ((action = almsg_get(&alm, PSLEN("action"), 0u)) != NULL) {
		size_t i;
		uint32_t hash = hash_pjw(PSLEN(action));
		for (i = 0u; _actions[i].f; i++) {
			if (_actions[i].action == 0u) {
				_actions[i].action =
					hash_pjw(PSLEN(_actions[i].action_str));
			}
			if (_actions[i].action == hash) {
				if (_actions[i].f(rds->pain, &alm, _actions[i].action_str)) {
					char *_p = NULL;
					size_t _s = 0u;
					almsg_format_buf(&alm, &_p, &_s);
					if (_p && _s) {
						redis_t(rds->pain, NULL, _p, _s);
					} else {
						xsyslog(LOG_DEBUG,
								"redis: zero result buffer: %p, %"PRIuPTR,
								_p, _s);
					}
				}
			}
		}
	}

	almsg_destroy(&alm);
	return true;
}


