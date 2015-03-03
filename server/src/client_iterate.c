/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_iterate.c
 */

#include "client_iterate.h"
#include "client_cb.h"

#include <ev.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>

TYPICAL_HANDLE_F(Fep__Pong, pong, C_MID)
TYPICAL_HANDLE_F(Fep__Auth, auth, C_MID)
TYPICAL_HANDLE_F(Fep__Ok, ok, C_MID)
TYPICAL_HANDLE_F(Fep__Error, error, C_MID)
TYPICAL_HANDLE_F(Fep__Pending, pending, C_MID)
TYPICAL_HANDLE_F(Fep__WriteOk, write_ok, C_MID)
TYPICAL_HANDLE_F(Fep__RenameChunk, rename_chunk, C_MID)

NOTIMP_HANDLE_F(Fep__ReadAsk, read_ask)

uint64_t
guid2hash(const char *key)
{
	register uint64_t h = 0u;
	register uint64_t hl, hr;

	while (*key) {
		if (*key == '{' || *key == '}' || *key == '-') {
			key++;
			continue;
		}
		h += *key;
		hl = 0x5c5c5 ^ (h & 0xfff00000) >> 30;
		hr = (h & 0x000fffff);
		h = hl ^ hr ^ *(key++);
	}
	return h;
}

static inline bool
is_legal_guid(char *guid)
{
	register size_t guid_len;
	register size_t i;

	for (guid_len = strlen(guid), i = 0u; i < guid_len; i++)
	{
		if (!((guid[i] >= 'A' && guid[i] <= 'Z')
				|| (guid[i] >= 'a' && guid[i] <= 'z')
				|| (guid[i] >= '0' && guid[i] <= '9')
				|| guid[i] == '-'
				|| guid[i] == '{'
				|| guid[i] == '}'))
			return false;
	}

	return true;
}

bool
_handle_write_ask(struct client *c, unsigned type, Fep__WriteAsk *msg)
{
	char *errmsg = NULL;
	char path[PATH_MAX];
	struct wait_store *ws;
	struct wait_xfer wx;

	uint64_t hash;
	struct wait_store *fid_ws;
	struct wait_file fid_wf;
	Fep__WriteOk wrok = FEP__WRITE_OK__INIT;

	if (msg->size == 0u) {
		errmsg = "Zero-size chunk? PFF";
	}

	if (!*msg->rootdir_guid || !*msg->file_guid\
			|| !*msg->chunk_guid) {
		errmsg = "Chunk without guids? No way";
	}

	if (!is_legal_guid(msg->rootdir_guid))
		errmsg = "illegal guid: rootdir_guid";
	if (!is_legal_guid(msg->file_guid))
		errmsg = "illegal guid: file_guid";
	if (!is_legal_guid(msg->chunk_guid))
		errmsg = "illegal guid: chunk_guid";

	if (errmsg)
		return send_error(c, msg->id, errmsg, -1);

	/* путь: <root_guid>/<file_guid>/<chunk_guid> */
	snprintf(path, PATH_MAX, "%s/%s", c->options.home, msg->rootdir_guid);
	/* открытие дескриптора файла и создание структуры для ожидания данных */
	if (mkdir(path, S_IRWXU) == -1 && errno != EEXIST) {
		errmsg = "Internal error: cache not available";
		xsyslog(LOG_WARNING, "client[%p] can't create path %s as cachedir: %s",
				(void*)c->cev, path, strerror(errno));
	} else {
		struct stat st;
		snprintf(path, PATH_MAX, "%s/%s/%s",
				c->options.home, msg->rootdir_guid, msg->file_guid);
		mkdir(path, S_IRWXU);
		snprintf(path, PATH_MAX, "%s/%s/%s/%s",
				c->options.home, msg->rootdir_guid,
				msg->file_guid, msg->chunk_guid);
		if (stat(path, &st) == -1 && errno != ENOENT) {
			errmsg = "Internal error: prepare space failed";
			xsyslog(LOG_WARNING, "client[%p] stat(%s) error: %s",
					(void*)c->cev, path, strerror(errno));
		} else if (errno != ENOENT) {
			if (st.st_size > 0u) {
				errmsg = "Interval error: overwrite not permited";
				xsyslog(LOG_WARNING, "client[%p] overwrite to %s not permited",
						(void*)c->cev, path);
			}
			if (unlink(path)) {
				xsyslog(LOG_WARNING, "client[%p] can't unlink %s: %s",
						(void*)c->cev, path, strerror(errno));
			}
		}
	}

	if (errmsg)
		return send_error(c, msg->id, errmsg, -1);

	{
		bool fid_in; /* логический костыль */
		hash = guid2hash(msg->file_guid);
		fid_in = ((fid_ws = touch_id(c, C_FID, hash)) != NULL);

		if (!fid_ws)
			fid_ws = calloc(1, sizeof(struct wait_store)
					+ sizeof(struct wait_file));
		memset(&wx, 0, sizeof(struct wait_xfer));
		ws = calloc(1, sizeof(struct wait_store) + sizeof(struct wait_xfer));
		/* открытие/создание файла */
		wx.fd = open(path, O_CREAT | O_TRUNC, S_IRWXU);
		if (wx.fd == -1 || !ws || !fid_ws) {
			errmsg = "Internal error: cache not available";
		}
		memcpy(wx.path, path, PATH_MAX);
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] fd#%d for %s",
				(void*)c->cev, wx.fd, wx.path);
#endif

		if (fid_in)
			fid_ws = NULL;
	}

	if (errmsg) {
		if (ws)
			free(ws);
		if (wx.fd != -1)
			close(wx.fd);
		if (fid_ws)
			free(fid_ws);
		xsyslog(LOG_WARNING, "client[%p] open(%s) failed: %s",
				(void*)c->cev, path, strerror(errno));
		return send_error(c, msg->id, errmsg, -1);
	}
	/* пакуем структуры */
	wrok.id = msg->id;
	wrok.session_id = generate_id(c);

	ws->data = ws + 1;
	memcpy(ws->data, &wx, sizeof(struct wait_xfer));

	wait_id(c, C_SID, wrok.session_id, ws);
	if (fid_ws) {
		fid_ws->data = fid_ws + 1;
		memcpy(fid_ws->data, &fid_wf, sizeof(struct wait_file));
		wait_id(c, C_FID, hash, fid_ws);
	}

	return send_message(c->cev, FEP__TYPE__tWriteOk, &wrok);
}

/* простые сообщения */

bool
send_ping(struct client *c)
{
	Fep__Ping ping = FEP__PING__INIT;
	struct timeval tv;
	wait_store_t *s;

	if (gettimeofday(&tv, NULL) == -1) {
		xsyslog(LOG_WARNING, "client[%p] gettimeofday() fail in ping: %s",
				(void*)c->cev, strerror(errno));
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
		xsyslog(LOG_WARNING, "client[%p] memory fail: %s",
				(void*)c->cev, strerror(errno));
		return false;
	}
	s->cb = (c_cb_t)c_pong_cb;
	s->data = s + 1;
	memcpy(s->data, &tv, sizeof(struct timeval));
	if (!wait_id(c, C_MID, ping.id, s)) {
		xsyslog(LOG_WARNING, "client[%p] can't set filter for pong id %"PRIu64,
				(void*)c->cev, ping.id);
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
	/* дропаем сразу подключение */
	return send_message(c->cev, FEP__TYPE__tError, &err);
}

bool
sendlog_error(struct client *c, uint64_t id, char *message, int remain)
{
	xsyslog(LOG_INFO, "client[%p] send_error: %s", (void*)c->cev, message);
	return send_error(c, id, message, remain);
}

bool
send_ok(struct client *c, uint64_t id)
{
	Fep__Ok ok = FEP__OK__INIT;

	ok.id = id;
	return send_message(c->cev, FEP__TYPE__tOk, &ok);
}

bool
send_pending(struct client *c, uint64_t id)
{
	Fep__Pending pending = FEP__PENDING__INIT;

	pending.id = id;
	return send_message(c->cev, FEP__TYPE__tPending, &pending);
}

/*
 * Удаляет сообщение из очереди или добавляет сообщение в корень,
 * если корень пустой
 */
static inline struct idlist*
_struct_drop_or_root(struct idlist **root, struct idlist *target)
{
	if (!root)
		return NULL;
	if (target) {
		if (*root == target)
			*root = idlist_free(target);
		else if (!*root)
			*root = target;
		else
			return idlist_free(target);
	}
	return *root;
}

/*
 * стуктура, переданная в *drop будет извлечена из указанного списка
 */
static inline struct idlist*
_struct_id(struct client *c, client_idl_t idl, struct idlist *drop)
{
	switch (idl) {
		case C_MID:
			return _struct_drop_or_root(&c->mid, drop);
		case C_SID:
			return _struct_drop_or_root(&c->scope_id, drop);
		case C_FID:
			return _struct_drop_or_root(&c->file_id, drop);
		default:
			xsyslog(LOG_WARNING, "client[%p] unknown client_idl no: %d",
					(void*)c->cev, idl);
			return NULL;
	}
}

/* постановка id в очередь ожидания TODO */
bool
wait_id(struct client *c, client_idl_t idl, uint64_t id, wait_store_t *s)
{
	struct idlist *wid;

	/* ещё одна бесполезная проверка */
	if (!s) {
		xsyslog(LOG_DEBUG, "client[%p] wait_id() not receive wait_store or cb",
				(void*)c->cev);
		return false;
	}

	if (!(wid = _struct_id(c, idl, NULL))) {
		/* корень пустой */
		if ((wid = idlist_alloc(id, wid)) != NULL) {
			/* бесполезная проверка на вкручиваемость узла в корень */
			if (!(_struct_id(c, idl, wid))) {
				idlist_free(wid);
				wid = NULL;
			}
		}
	} else {
		/* новый узел без обновления корня */
		wid = idlist_alloc(id, wid);
	}

	if (!wid) {
		return false;
	} else {
		wid->data = (void*)s;
		return true;
	}
}

wait_store_t*
query_id(struct client *c, client_idl_t idl, uint64_t id)
{
	struct idlist *wid;
	wait_store_t *data;

	if (!(wid = _struct_id(c, idl, NULL)))
		return NULL;

	if (!(wid = idlist_find(id, wid, DANY)))
		return NULL;

	data = (wait_store_t*)wid->data;

	/* удаление ненужной структуры */
	_struct_id(c, idl, wid);
	return data;
}

wait_store_t*
touch_id(struct client *c, client_idl_t idl, uint64_t id)
{
	struct idlist *wid;

	if (!(wid = _struct_id(c, idl, NULL)))
		return NULL;

	if (!(wid = idlist_find(id, wid, DANY)))
		return NULL;

	return (wait_store_t*)wid->data;
}

/* всякая ерунда */
uint64_t
generate_id(struct client *c)
{
	return ++c->genid;
}

bool
_handle_xfer(struct client *c, unsigned type, Fep__Xfer *xfer)
{
	struct wait_store *ws;
	struct wait_xfer *wx;
	char *errmsg = NULL;

	ws = touch_id(c, C_SID, xfer->session_id);
	if (!ws)
		return send_error(c, xfer->id, "Unexpected xfer message", -1);
	wx = ws->data;

	if (xfer->data.len + xfer->offset > wx->size) {
		errmsg = "Owerdose input data";
	} else if (lseek(wx->fd, (off_t)xfer->offset, SEEK_SET) == (off_t)-1) {
		errmsg = "Can't set offset";
	} else if (write(wx->fd, xfer->data.data, xfer->data.len) != xfer->data.len) {
		errmsg = "Write fail";
	} else {
		return true;
	}

	/* больше чанк нам не нужен, т.к. его должны переслать заного */
	if ((ws = query_id(c, C_SID, xfer->session_id)) != NULL)
		free(ws);
	close(wx->fd);
	unlink(wx->path);
	return send_error(c, xfer->id, errmsg, -1);
}

void
file_check_update(struct client *c, struct wait_file *wf)
{
	/* TODO: разослать уведомление */
	if (wf->chunks == wf->chunks_ok) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] file fin: %u/%u[%u]",
				(void*)c->cev, (unsigned)wf->chunks_ok,
				(unsigned)wf->chunks, (unsigned)wf->chunks_fail);
#endif
	}
}

bool
_handle_file_update(struct client *c, unsigned type, Fep__FileUpdate *fu)
{
	uint64_t hash;
	wait_store_t *ws;
	struct wait_file *wf;

	hash = guid2hash(fu->file_guid);

	ws = touch_id(c, C_FID, hash);
	/* если записи нет, нужно создать новую */
	if (!ws) {
		ws = calloc(1, sizeof(wait_store_t) + sizeof (struct wait_file));
		if (!ws) {
			xsyslog(LOG_INFO, "client[%p] memory fail in fileUpdate: %s",
					(void*)c->cev, strerror(errno));
			return send_error(c, fu->id, "Infernal error", -1);
		}
		ws->data = ws + 1;
		wf = ws->data;
		string2guid(fu->file_guid, strlen(fu->file_guid), &wf->file_guid);
	}
	wf->chunks = fu->chunks;
	return send_ok(c, fu->id);
}

bool
_handle_end(struct client *c, unsigned type, Fep__End *end)
{
	struct wait_store *ws;
	struct wait_xfer *wx;
	char *errmsg = NULL;

	/* TODO: добавить в бд запись */
	ws = query_id(c, C_SID, end->session_id);
	if (!ws)
		return send_error(c, end->id, "Unexpected End message", -1);
	wx = ws->data;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] close fd#%d",
			(void*)c->cev, wx->fd);
#endif
	close(wx->fd);
	if (wx->filling != wx->size) {
		errmsg = "Infernal sizes";
	}


	if (!errmsg) {
		wx->wf->chunks_ok++;
		file_check_update(c, wx->wf);
		return send_ok(c, end->id);
	}
	wx->wf->chunks_fail++;
	unlink(wx->path);
	return send_error(c, end->id, errmsg, -1);
}

bool
_handle_ping(struct client *c, unsigned type, Fep__Ping *ping)
{
	Fep__Pong pong = FEP__PONG__INIT;
	struct timeval tv;

	if (gettimeofday(&tv, NULL) == -1) {
		xsyslog(LOG_WARNING, "client[%p] gettimeofday() fail in pong: %s",
				(void*)c->cev, strerror(errno));
		return false;
	}

	pong.id = ping->id;
	pong.sec = ping->sec;
	pong.usec = ping->usec;
	pong.peer_sec = tv.tv_sec;
	pong.peer_usec = tv.tv_sec;

	if (!c->timed) {
		if (ping->sec > tv.tv_sec + 300) {
			if (ping->usec < tv.tv_usec) {
				ping->sec--;
				ping->usec += 1000u;
			}
			ping->sec = ping->sec - tv.tv_sec;
			ping->usec = ping->usec - tv.tv_usec;
			xsyslog(LOG_INFO,
					"client[%p] client lives in far future: "
					"%"PRIu64".%06"PRIu32"s offset",
					(void*)c->cev, ping->sec, ping->usec);
		} else if (ping->sec < tv.tv_sec - 300) {
			if (ping->usec > tv.tv_usec) {
				ping->sec++;
				ping->usec = ping->usec % 1000u;
			}
			ping->sec = tv.tv_sec - ping->sec;
			ping->usec = tv.tv_usec - ping->sec;
			xsyslog(LOG_INFO,
					"client[%p] client living in the past: "
					"%"PRIu64".%06"PRIu32"s offset",
					(void*)c->cev, ping->sec, ping->usec);
		}
		send_ping(c);
		c->timed = true;
	}

	return send_message(c->cev, FEP__TYPE__tPong, &pong);
}

bool
_handle_invalid(struct client *c, unsigned type, void *msg)
{
	send_error(c, 0, "Unknown packet", c->count_error);
	if (c->count_error <= 0)
		return false;
	else
		return true;
}

static struct handle handle[] =
{
	{0u, _handle_invalid, NULL, NULL}, /* 0 */
	TYPICAL_HANDLE_S(FEP__TYPE__tPing, ping), /* 1 */
	TYPICAL_HANDLE_S(FEP__TYPE__tPong, pong), /* 2 */
	RAW_P_HANDLE_S(FEP__TYPE__tError, error), /* 3 */
	RAW_P_HANDLE_S(FEP__TYPE__tOk, ok), /* 4 */
	RAW_P_HANDLE_S(FEP__TYPE__tPending, pending), /* 5 */
	INVALID_P_HANDLE_S(FEP__TYPE__tReqAuth, req_auth), /* 6 */
	TYPICAL_HANDLE_S(FEP__TYPE__tAuth, auth), /* 7 */
	TYPICAL_HANDLE_S(FEP__TYPE__txfer, xfer), /* 8 */
	TYPICAL_HANDLE_S(FEP__TYPE__tReadAsk, read_ask), /* 9 */
	TYPICAL_HANDLE_S(FEP__TYPE__tWriteAsk, write_ask), /* 10 */
	TYPICAL_HANDLE_S(FEP__TYPE__tEnd, end), /* 11 */
	TYPICAL_HANDLE_S(FEP__TYPE__tWriteOk, write_ok), /* 12 */
	TYPICAL_HANDLE_S(FEP__TYPE__tFileUpdate, file_update), /* 13 */
	TYPICAL_HANDLE_S(FEP__TYPE__tRenameChunk, rename_chunk) /* 14 */
};

bool
_send_message(struct sev_ctx *cev, unsigned type, void *msg, char *name)
{
	ssize_t lval;
	size_t len;
	unsigned char *buf;

	if (!type || type >= sizeof(handle) / sizeof(struct handle)) {
		xsyslog(LOG_ERR, "client[%p] invalid type %d in send_message(%s)",
				(void*)cev, type, name);
		return false;
	}

	if (!handle[type].f_sizeof || !handle[type].f_pack) {
		xsyslog(LOG_ERR, "client[%p] type %d (%s)"
				"has no sizeof and pack field",
				(void*)cev, type, name);

	}

	/* подготавливается заголовок */
	len = handle[type].f_sizeof(msg);
	buf = pack_header(type, &len);
	if (!buf) {
		xsyslog(LOG_WARNING, "client[%p] memory fail in %s: %s",
				(void*)cev, name, strerror(errno));
		return false;
	}

	/* уупаковывается сообщение */
	handle[type].f_pack(msg, &buf[HEADER_OFFSET]);
	if ((lval = sev_send(cev, buf, len)) != len) {
		xsyslog(LOG_WARNING, "client[%p] send fail in %s", (void*)cev, name);
	}
	free(buf);

	return (lval == len);
}

/* return offset */
unsigned char *
pack_header(unsigned type, size_t *len)
{
	unsigned char *buf = (unsigned char*)calloc(1, *len + HEADER_OFFSET);
	uint16_t typeBE = htons(type);
	uint32_t lenBE = htonl(*len);
	/* FIXME: ??? */
	if (buf) {
		lenBE = lenBE >> 8;
		memcpy(buf, &typeBE, 2);
		memcpy(&buf[2], &lenBE, 3);
#if 0
		xsyslog(LOG_DEBUG, "header[type: %u, len: %lu]: %02x %02x %02x %02x %02x %02x",
				type, *len, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
#endif
		*len += HEADER_OFFSET;
	}
	return buf;
}

/*-1 invalid message
 * 0 ok
 * 1 need more
 *
 * return special value (HEADER_MORE, HEADER_INVALID) or bytes
 *
 */
int
handle_header(unsigned char *buf, size_t size, struct client *c)
{
	if (!c->h_type) {
		if (size < HEADER_OFFSET) {
			return HEADER_MORE;
		} else {
			memcpy(&c->h_type, buf, 2);
			memcpy(&c->h_len, &buf[2], 3);
			c->h_type = ntohs(c->h_type);
			c->h_len = ntohl(c->h_len << 8);
#if DEEPDEBUG
			xsyslog(LOG_DEBUG, "client[%p] got header[type: %u, len: %u]: "
					"%02x %02x %02x %02x %02x %02x",
					(void*)c->cev, c->h_type, c->h_len,
					buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
#endif
			/* бесполезная проверка на длину пакета */
			if (c->h_len > 1 << 24) {
				xsyslog(LOG_WARNING, "client[%p] header[type: %u, len: %u]: "
						"length can't be great then %d",
						(void*)c->cev, c->h_type, c->h_len,
						1 << 24);
				c->h_type = 0u;
				return HEADER_INVALID;
			}
			/* проверка на тип */
			if (sizeof(handle) / sizeof(struct handle) <= c->h_type ||
					c->h_type == 0u) {
				xsyslog(LOG_WARNING, "client[%p] header[type: %u, len: %u]: "
						"invalid type",
						(void*)c->cev, c->h_type, c->h_len);
				c->h_type = 0u;
				/*
				 * отмену можно не делать, только выставить хандлер в ноль
				 * и известить в логе, в хандлере можно позвать начальника
				return HEADER_INVALID;
				*/
			}
		}
	}
	if (size - HEADER_OFFSET < c->h_len)
		return HEADER_MORE;
	/* извлечение пакета */
	{
		void *rawmsg = &buf[HEADER_OFFSET];
		void *msg;
		bool exit = false;
		if (!handle[c->h_type].f) {
			xsyslog(LOG_INFO, "client[%p] header[type: %u, len: %u]: "
					"message has no handle",
					(void*)c->cev, c->h_type, c->h_len);
		} else {
			/* не должно случаться такого, что бы небыло анпакера,
			 * но как-то вот
			 */
#if DEEPDEBUG
			xsyslog(LOG_DEBUG, "client[%p] in message: %u, len: %u",
					(void*)c->cev, (unsigned)c->h_type, c->h_len);
#endif
			if (!handle[c->h_type].p) {
				if (!handle[c->h_type].f(c, c->h_type, rawmsg))
					exit = true;
			} else {
				msg = handle[c->h_type].p(NULL, c->h_len, (uint8_t*)rawmsg);
				if (msg) {
					if (!handle[c->h_type].f(c, c->h_type, msg))
						exit = true;
					/* проверять заполненность структуры нужно в компилтайме,
					 * но раз такой возможности нет, то делаем это в рантайме
					 */
					if (!handle[c->h_type].e) {
						xsyslog(LOG_WARNING,
								"memory leak for message type #%u\n",
								c->h_type);
					} else {
						handle[c->h_type].e(msg, NULL);
					}
				} else {
					xsyslog(LOG_INFO,
							"client[%p] send malformed message type #%u",
							(void*)c->cev, c->h_type);
				}
			}
		}
		/* сброс типа сообщения */
		c->h_type = 0u;
		if (!exit)
			return (int)(c->h_len + HEADER_OFFSET);
		else
			return HEADER_STOP;
	}
	return HEADER_INVALID;
}

/*
 * подгрузка конфигурации пользователя после авторизации
 * TODO: заглушка
 */
bool
client_load(struct client *c)
{
	size_t len = strlen(c->name) + sizeof("user/");
	c->options.home = calloc(1, len + 1);
	if (!c->options.home)
		return false;
	snprintf(c->options.home, len, "user/%s", c->name);
	if (mkdir(c->options.home, S_IRWXU) == -1 && errno != EEXIST) {
		xsyslog(LOG_WARNING, "client[%p] mkdir(%s) in client_load() fail: %s",
				(void*)c->cev, c->options.home, strerror(errno));
		return false;
	}
	return true;
}

static inline void
client_destroy(struct client *c)
{
	struct wait_xfer *wx;
	struct wait_store *ws;
	if (!c)
		return;
	/* чистка очередей */
	while (c->mid) {
		if (c->mid->data);
			free(c->mid->data);
		c->mid = idlist_free(c->mid);
	}

	while (c->file_id) {
		if (c->file_id->data)
			free(c->file_id->data);
		c->file_id = idlist_free(c->file_id);
	}

	/* при чистке скопов нужно быть деликатнее */
	while (c->scope_id) {
		ws = c->scope_id->data;
		if (ws) {
			if ((wx = ws->data)) {
				if (wx->fd != -1)
					close(wx->fd);
				xsyslog(LOG_INFO, "client[%p] free xfer fd#%d, id %"PRIu64,
						(void*)c->cev, wx->fd, c->scope_id->id);
			}
			free(ws);
		}
		c->scope_id = idlist_free(c->scope_id);
	}
	/* буфера */
	if (c->buffer)
		free(c->buffer);
	if (c->options.home)
		free(c->options.home);
	free(c);
}

static inline struct client*
client_alloc(struct sev_ctx *cev)
{
	/* выделение памяти под структуру и инициализация
	 * TODO: вставить подтягивание конфига
	 */
	struct client *c;
	c = (struct client*)calloc(1, sizeof(struct client));
	if (!c) {
		xsyslog(LOG_WARNING, "client[%p] memory fail: %s",
				(void*)cev, strerror(errno));
		return NULL;
	}
	c->count_error = 3;
	c->cev = cev;
	return c;
}

/* вовзращает положительный результат, если требуется прервать io */
bool
client_iterate(struct sev_ctx *cev, bool last, void **p)
{
	struct client *c = (struct client *)*p;
	int lval = 0;
	/* подчищаем, если вдруг последний раз запускаемся */
	if (last) {
		client_destroy(c);
		*p = NULL;
		return true;
	} else if (p && !c) {
		c = client_alloc(cev);
		if (!(*p = (void*)c))
			return true;
	} else if (!p) {
		xsyslog(LOG_WARNING, "client[%p] field for structure not passed",
				(void*)cev);
		return true;
	}
	/* send helolo */
	if (c->state == CEV_FIRST) {
		wait_store_t *s;
		Fep__ReqAuth reqAuth = FEP__REQ_AUTH__INIT;
		reqAuth.id = generate_id(c);
		reqAuth.text = "hello kitty";

		if (send_message(c->cev, FEP__TYPE__tReqAuth, &reqAuth)) {
			c->state++;

			if ((s = calloc(1, sizeof (wait_store_t))) != NULL)
				s->cb = (c_cb_t)c_auth_cb;

			if (!s || !wait_id(c, C_MID, reqAuth.id, s)) {
				if (s) free(s);
				xsyslog(LOG_WARNING,
						"client[%p] can't set filter for id %"PRIu64,
						(void*)cev, reqAuth.id);
			}
		} else {
			xsyslog(LOG_WARNING, "client[%p] no hello with memory fail: %s",
					(void*)cev, strerror(errno));
		}
	}
	while (lval >= 0) {
		/* need realloc */
		if (c->blen + BUFFER_ALLOC > c->bsz) {
			void *tmp;
			tmp = realloc(c->buffer, c->bsz + BUFFER_ALLOC);
			if (!tmp) {
				xsyslog(LOG_WARNING, "client %p, grow from %lu to %lu fail: %s",
						(void*)cev, c->bsz, c->bsz + BUFFER_ALLOC,
						strerror(errno));
				/* если обвалились по памяти, то ждём следующей итерации,
				 * так как в процессе может что-то освободиться */
				break;
			}
			c->buffer = tmp;
			c->bsz += BUFFER_ALLOC;
		}
		/* wait data */
		lval = sev_recv(cev, &c->buffer[c->blen], c->bsz - c->blen);
		if (lval < 0) {
			xsyslog(LOG_WARNING, "client[%p] recv %d\n", (void*)cev, lval);
			break;
		} else if (lval == 0) {
			/* pass to cycle sanitize (check timeouts, etc) */
			break;
		}
		c->blen += lval;
		lval = handle_header(c->buffer, c->blen, c);
		/* смещаем хвост в начало буфера */
		if (lval > 0) {
			if (lval < c->blen) {
				/* если вдруг обвалится memove, то восстанавливать, вощем-то,
				 * нечего, потому просто валимся
				 */
				if (!memmove(c->buffer, &c->buffer[lval], c->blen - lval)) {
					xsyslog(LOG_WARNING, "client[%p] memmove() fail: %s",
							(void*)cev, strerror(errno));
					return true;
				}
				c->blen -= lval;
			} else {
				c->blen = 0u;
			}
		} else if (lval == HEADER_INVALID) {
			xsyslog(LOG_WARNING, "client[%p] mismatch protocol:"
					"%x %x %x %x %x %x", (void*)cev,
					c->buffer[0], c->buffer[1], c->buffer[2],
					c->buffer[3], c->buffer[4], c->buffer[5]);
			return true;
		} else if (lval == HEADER_STOP) {
			xsyslog(LOG_WARNING, "client[%p] stop chat with "
					"header[type: %u, len: %u]",
					(void*)cev, c->h_type, c->h_len);
		}
		if (c->count_error <= 0) {
			xsyslog(LOG_INFO, "client[%p] to many errors", (void*)cev);
			return true;
		}
	}
	return false;
}

