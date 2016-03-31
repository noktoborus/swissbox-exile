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
		if (!c->options.limit_local_sql_queries ||
				c->values.sql_queries_count + 1 <=
				c->options.limit_local_sql_queries) {
			isql++;
		} else return false;
	}

	if (reqs & H_REQS_FD) {
		if (!c->options.limit_local_fd_queries ||
				c->values.fd_queries_count + 1 <=
				c->options.limit_local_fd_queries) {
			ifd++;
		} else return false;
	}

	/* счётчики инкрементируем даже если опции выключены */
	c->values.sql_queries_count += isql;
	c->values.fd_queries_count += ifd;

#if DEEPDEBUG
	if (isql) {
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] "
				"acquire SQL, value: %lu",
				c->cev->serial, c->values.sql_queries_count);
	}

	if (ifd) {
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] "
				"acquire FD, value: %lu",
				c->cev->serial, c->values.fd_queries_count);
	}
#endif

	return true;
}

void
client_reqs_release_all(struct client *c)
{
	xsyslog(LOG_INFO,
			"client[%"SEV_LOG"] counters -> sql: %ld, fd: %ld",
			c->cev->serial,
			c->values.sql_queries_count, c->values.fd_queries_count);

	/* TODO: скрутить с глобального счётчика локальный счётчик */
}

void
client_reqs_release(struct client *c, enum handle_reqs_t reqs)
{
	if (reqs & H_REQS_SQL) {
		if (c->values.sql_queries_count) {
			c->values.sql_queries_count--;
#if DEEPDEBUG
			xsyslog(LOG_DEBUG,
					"client[%"SEV_LOG"] "
					"release SQL, value: %lu",
					c->cev->serial, c->values.sql_queries_count);
#endif
		} else {
			xsyslog(LOG_WARNING,
					"client[%"SEV_LOG"] "
					"error decrement zero value in sql counter",
					c->cev->serial);
		}
	}

	if (reqs & H_REQS_FD) {
		if (c->values.fd_queries_count) {
			c->values.fd_queries_count--;
#if DEEPDEBUG
			xsyslog(LOG_DEBUG,
					"client[%"SEV_LOG"] "
					"release FD, value: %lu",
					c->cev->serial, c->values.fd_queries_count);
#endif
		} else {
			xsyslog(LOG_WARNING,
					"client[%"SEV_LOG"] "
					"error decrement zero value in fd counter",
					c->cev->serial);
		}
	}
}

enum header_result
client_reqs_queue(struct client *c, enum handle_reqs_t reqs,
		unsigned type, void *msg, uint64_t id)
{
	struct h_reqs_store_t *hrs = NULL;

	hrs = calloc(1, sizeof(*hrs));
	if (!hrs) {
		xsyslog(LOG_WARNING, "reqs error calloc(%"PRIuPTR") -> %s",
				sizeof(*hrs), strerror(errno));
		return HEADER_R_FAIL;
	}

	hrs->msg = msg;
	hrs->type = type;
	hrs->reqs = reqs;
	hrs->serial = ++c->delay_serial;
	hrs->id = id;

	if (!list_alloc(&c->msg_delayed, 0, (void*)hrs)) {
		free(hrs);
		return HEADER_R_FAIL;
	}

	/* DL = delay */
	xsyslog(LOG_DEBUG,
			"client[%"SEV_LOG"] DL >> {%s? id=%"PRIu64", ...} "
			"(sql: %ld, fd: %ld) "
			"[delay serial: %"PRIu64"]",
			c->cev->serial, Fepstr(type), hrs->id,
			c->values.sql_queries_count, c->values.fd_queries_count,
			hrs->serial);

	return HEADER_R_DELAED;
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

	/* сборка маски */
	if (reqs == H_REQS_Z) {
		if (!c->options.limit_local_sql_queries ||
				c->values.sql_queries_count + 1 <=
					c->options.limit_local_sql_queries) {
			reqs |= H_REQS_SQL;
		}

		if (!c->options.limit_local_fd_queries ||
				c->values.fd_queries_count + 1 <=
					c->options.limit_local_fd_queries) {
			reqs |= H_REQS_FD;
		}
		/* не имеет смысла дальше ходиь по списку,
		 * если нет доступных ресурсов
		 */
		if (reqs == H_REQS_Z) {
			return true;
		}
	}

	/* поиск по маске */
	list_ptr(&c->msg_delayed, &p);
	n = list_find_val(&p, (list_cmp_cb)_find_val_cb, &reqs);
	if (!n) {
		return true;
	}
	h = n->data;

	/* DP = dispatch */
	xsyslog(LOG_DEBUG,
			"client[%"SEV_LOG"] DP << {%s? id=%"PRIu64", ...} "
			"(sql: %ld, fd: %ld) "
			"[delay serial: %"PRIu64"]",
			c->cev->serial, Fepstr(h->type), h->id,
			c->values.sql_queries_count, c->values.fd_queries_count,
			h->serial);

	/* пытаемся вызвать процедурку */
	if (!exec_message(c, h->type, h->msg)) {
		/* если ошибка -> выходим, чистимся */
		list_free_node(n, free);
		return false;
	}

	/* освобождаем узел, т.к. дальше он нам не потребуется в любом случае */
	list_free_node(n, free);
	return true;
}

