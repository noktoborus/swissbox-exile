/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client/reqs.c
 */
#include "junk/xsyslog.h"
#include "src/client_iterate.h"

bool
client_reqs_acquire(struct client *c, enum handle_reqs_t reqs)
{
	register long isql = 0l;
	register long ifd = 0l;

	/* FIXME: пока только локальные лимиты */

	if (reqs & H_REQS_SQL) {
		if (c->values.sql_queries_count + 1 <
				c->options.limit_local_sql_queries) {
			isql++;
		}
	}

	if (reqs & H_REQS_FD) {
		if (c->values.fd_queries_count + 1 <
				c->options.limit_local_fd_queries) {
			ifd++;
		}
	}

	if (c->options.limit_local_sql_queries && !isql) {
		return false;
	}

	if (c->options.limit_local_fd_queries && !ifd) {
		return false;
	}

	/* счётчики инкрементируем даже если опции выключены */
	c->values.sql_queries_count += isql;
	c->values.fd_queries_count += ifd;

	return true;
}

void
client_reqs_release(struct client *c, enum handle_reqs_t reqs)
{
	if (reqs && H_REQS_SQL) {
		if (c->values.sql_queries_count) {
			c->values.sql_queries_count--;
		} else {
			xsyslog(LOG_WARNING,
					"client[%"SEV_LOG"] "
					"error decrement zero value in sql counter",
					c->cev->serial);
		}
	}

	if (reqs && H_REQS_FD) {
		if (c->values.fd_queries_count) {
			c->values.fd_queries_count--;
		} else {
			xsyslog(LOG_WARNING,
					"client[%"SEV_LOG"] "
					"error decrement zero value in fd counter",
					c->cev->serial);
		}
	}
}

bool
client_reqs_queue(struct client *c, enum handle_reqs_t reqs,
		unsigned type, void *msg)
{
	/* TODO: ... */
	return false;
}


void
client_reqs_unqueue(struct client *c, enum handle_reqs_t reqs)
{
	/* TODO: ... */
}

