/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client/include/reqs.c
 */

bool
client_reqs_acquire(struct client *c, enum handle_reqs_t reqs)
{
	register long isql = 0l;
	register long ifd = 0l;

	/*
	 * предпологается что счётчик будет инкрементироваться только при
	 * прохождении всех предварительных проверок
	 */

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
	struct h_reqs_store_t *hrs = NULL;
	size_t len = 0u;

	if (!(len = sizeof_message(type, msg)))
		return false;

	hrs = calloc(1, sizeof(*hrs) + len);
	if (!hrs) {
		return false;
	}

	if (!pack_message(type, msg, hrs->msg)) {
		free(hrs);
		return false;
	}

	hrs->len = len;
	hrs->type = type;
	hrs->reqs = reqs;

	if (!list_alloc(&c->msg_delayed, 0, (void*)hrs)) {
		free(hrs);
		return false;
	}

	return true;
}

static bool
_find_val_cb(struct h_reqs_store_t *list_d,
		uint64_t id,
		enum handle_reqs_t *reqs)
{
	if ((list_d->reqs & *reqs) == list_d->reqs) {
		return true;
	}
	return false;
}

bool
client_reqs_unqueue(struct client *c, enum handle_reqs_t reqs)
{
	struct listPtr p = {0};
	struct listNode *n = NULL;
	struct h_reqs_store_t *h = NULL;
	int r = 0;

	list_ptr(&c->msg_delayed, &p);
	n = list_find_val(&p, (list_cmp_cb)_find_val_cb, &reqs);
	if (!n) {
		return true;
	}
	h = n->data;

	/* пытаемся вызвать процедурку */
	r = exec_bufmsg(c, h->type, h->msg, h->len);

	if (r == HEADER_STOP) {
		list_free_node(n, free);
		return false;
	}

	if (r == HEADER_INVALID || r == HEADER_MORE) {
		xsyslog(LOG_WARNING,
				"reqs_unqueue error: handle_header() returns %s",
				(r == HEADER_INVALID ? "HEADER_INVALID" :
				 (r == HEADER_STOP ? "HEADER_STOP" : "UNKNOWN")));
		list_free_node(n, free);
		return false;
	}

	/* освобождаем узел, т.к. дальше он нам не потребуется в любом случае */
	list_free_node(n, free);
	return true;
}

