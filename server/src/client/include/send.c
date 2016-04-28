/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client/include/send.c
 */

/* простые сообщения */

bool
send_end(struct client *c, uint32_t session_id, uint32_t packets)
{
	Fep__End msg = FEP__END__INIT;

	msg.id = generate_id(c);
	msg.session_id = session_id;
	msg.packets = packets;

	return send_message(c->cev, FEP__TYPE__tEnd, &msg);
}

bool
send_ping(struct client *c)
{
	Fep__Ping ping = FEP__PING__INIT;
	struct timeval tv;
	wait_store_t *s;

	if (gettimeofday(&tv, NULL) == -1) {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] gettimeofday() fail in ping: %s",
				c->cev->serial, strerror(errno));
		return false;
	}

	ping.id = generate_id(c);
	ping.sec = tv.tv_sec;
	ping.usec = tv.tv_usec;

	if (!send_message(c->cev, FEP__TYPE__tPing, &ping)) {
		return false;
	}
	s = calloc(1, sizeof(wait_store_t) + sizeof(struct timeval));
	if (!s) {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] memory fail: %s",
				c->cev->serial, strerror(errno));
		return false;
	}
	s->cb = (c_cb_t)c_pong_cb;
	s->data = s + 1;
	memcpy(s->data, &tv, sizeof(struct timeval));
	if (!wait_id(c, &c->mid, ping.id, s)) {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] can't set filter for pong id %"PRIu64,
				c->cev->serial, ping.id);
		free(s);
		return false;
	}
	return true;
}

bool
send_error(struct client *c, uint64_t id, char *message, int remain)
{
	Fep__Error err = FEP__ERROR__INIT;

	err.id = id;
	err.message = message;
	if (remain > 0)
		err.remain = (unsigned)remain;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] send error(%d): %s",
			c->cev->serial, remain, message);
#endif
	return send_message(c->cev, FEP__TYPE__tError, &err);
}

bool
sendlog_error(struct client *c, uint64_t id, char *message, int remain)
{
	xsyslog(LOG_INFO, "client[%"SEV_LOG"] send_error: %s", c->cev->serial, message);
	return send_error(c, id, message, remain);
}

bool
send_ok(struct client *c, uint64_t id, uint64_t checkpoint, char *message)
{
	if (checkpoint == C_OK_SIMPLE) {
		Fep__Ok ok = FEP__OK__INIT;

		ok.id = id;
		if (message)
			ok.message = message;
		return send_message(c->cev, FEP__TYPE__tOk, &ok);
	} else {
		Fep__OkUpdate oku = FEP__OK_UPDATE__INIT;

		oku.id = id;
		oku.checkpoint = checkpoint;
		if (message)
			oku.message = message;
		return send_message(c->cev, FEP__TYPE__tOkUpdate, &oku);
	}
}

bool
send_pending(struct client *c, uint64_t id)
{
	Fep__Pending pending = FEP__PENDING__INIT;

	pending.id = id;
	return send_message(c->cev, FEP__TYPE__tPending, &pending);
}

bool
send_satisfied(struct client *c, uint64_t id, char *message)
{
	Fep__Satisfied msg = FEP__SATISFIED__INIT;

	msg.id = id;
	if (message)
		msg.message = message;

	return send_message(c->cev, FEP__TYPE__tSatisfied, &msg);
}

