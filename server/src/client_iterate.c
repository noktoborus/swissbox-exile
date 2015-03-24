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

TYPICAL_HANDLE_F(Fep__Pong, pong, &c->mid)
TYPICAL_HANDLE_F(Fep__Auth, auth, &c->mid)
TYPICAL_HANDLE_F(Fep__Ok, ok, &c->mid)
TYPICAL_HANDLE_F(Fep__Error, error, &c->mid)
TYPICAL_HANDLE_F(Fep__Pending, pending, &c->mid)
TYPICAL_HANDLE_F(Fep__WriteOk, write_ok, &c->mid)

NOTIMP_HANDLE_F(Fep__RenameChunk, rename_chunk)
NOTIMP_HANDLE_F(Fep__ResultChunk, result_chunk)
NOTIMP_HANDLE_F(Fep__ResultRevision, result_revision)

static struct result_send*
rout_free(struct client *c)
{
	struct result_send *p;
	if ((p = c->rout) != NULL) {
		if (p->free) {
			p->free(&p->v);
		}
		c->rout = c->rout->next;
		free(p);
	}
	return c->rout;
}

static struct chunk_send*
cout_free(struct client *c)
{
	struct chunk_send *p;
	if ((p = c->cout) != NULL) {
		if (p->fd != -1) {
			close(p->fd);
		}
		c->cout = c->cout->next;
		free(p);
	}
	return c->cout;
}

static void
mid_free(void *data)
{
	free(data);
}

static void
fid_free(wait_store_t *ws)
{
	struct wait_file *wf;
	wf = ws->data;
	if (wf) {
		if (wf->enc_filename)
			free(wf->enc_filename);
		if (wf->hash_filename)
			free(wf->hash_filename);
		if (wf->key)
			free(wf->key);
	}
	free(ws);
}

static void
sid_free(wait_store_t *ws)
{
	struct wait_xfer *wx;
	wx = ws->data;
	if (wx->fd != -1) {
		xsyslog(LOG_DEBUG, "destroy xfer fd#%d", wx->fd);
		close(wx->fd);
	}
	free(ws);
}

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
_handle_query_revisions(struct client *c, unsigned type,
		Fep__QueryRevisions *msg)
{
	struct getRevisions gr;
	guid_t rootdir;
	guid_t file;

	struct result_send *rs;

	/* конвертация типов */
	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);

	memset(&gr, 0, sizeof(struct getRevisions));

	if (!spq_f_getRevisions(c->name, &rootdir, &file, msg->depth, &gr)) {
		return send_error(c, msg->id, "Internal error 100", -1);
	}

	/* выделяем память под список */
	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_f_getRevisions_free(&gr);
		return send_error(c, msg->id, "Internal error 111", -1);
	}
	memcpy(&rs->v.r, &gr, sizeof(struct getRevisions));
	rs->id = msg->id;
	rs->type = RESULT_REVISIONS;
	rs->free = (void(*)(void*))spq_f_getRevisions_free;
	rs->next = c->rout;
	c->rout = rs;
	return true;
}

bool
_handle_query_chunks(struct client *c, unsigned type, Fep__QueryChunks *msg)
{
	struct getChunks gc;
	guid_t rootdir;
	guid_t file;
	guid_t revision;

	struct result_send *rs;

	/* конвертим типы */
	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);
	string2guid(msg->revision_guid, strlen(msg->revision_guid), &revision);

	memset(&gc, 0, sizeof(struct getChunks));

	if (!spq_f_getChunks(c->name, &rootdir, &file, &revision, &gc)) {
		return send_error(c, msg->id, "Internal error 110", -1);
	}

	/* выделяем память под список */
	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_f_getChunks_free(&gc);
		return send_error(c, msg->id, "Internal error 111", -1);
	}
	memcpy(&rs->v.c, &gc, sizeof(struct getChunks));
	rs->id = msg->id;
	rs->type = RESULT_CHUNKS;
	rs->free = (void(*)(void*))spq_f_getChunks_free;
	rs->next = c->rout;
	c->rout = rs;
	return true;
}

bool
_handle_read_ask(struct client *c, unsigned type, Fep__ReadAsk *msg)
{
	/*
	 * 1. поиск файла в бд
	 * 2. формирование структуры для отправки файла или отсылка Error
	 */
	guid_t rootdir;
	guid_t file;
	guid_t chunk;
	int fd;
	char path[PATH_MAX];
	struct chunk_send *chs;
	struct stat st;

	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);
	string2guid(msg->chunk_guid, strlen(msg->chunk_guid), &chunk);

	if (!spq_f_getChunkPath(c->name, &rootdir, &file, &chunk,
				path, sizeof(path))) {
		return send_error(c, msg->id, "Internal error 120", -1);
	}

	if (stat(path, &st) == -1) {
		return send_error(c, msg->id, "Internal error 123", -1);
	}

	if ((fd = open(path, O_RDONLY)) == -1) {
		return send_error(c, msg->id, "Internal error 122", -1);
	}

	if (!(chs = calloc(1, sizeof(struct chunk_send)))) {
		close(fd);
		return send_error(c, msg->id, "Internal error 121", -1);
	}

	chs->fd = fd;
	chs->size = st.st_size;
	chs->next = c->cout;
	c->cout = chs;

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
	struct wait_file *wf;
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
		/* FIXME: на данный момент не понимаю как именно нужно сохранять
			файл и связывать его с бд, возможны нехорошие варианты,
			когда несколько клиентов начнут писать в один файл
		*/
		struct stat st;
		char chunk_hash[PATH_MAX];
		bin2hex(msg->chunk_hash.data, msg->chunk_hash.len,
				chunk_hash, sizeof(chunk_hash));
		snprintf(path, PATH_MAX, "%s/%s/%s",
				c->options.home, msg->rootdir_guid, chunk_hash);

		if (stat(path, &st) == -1 && errno != ENOENT) {
			errmsg = "Internal error: prepare space failed";
			xsyslog(LOG_WARNING, "client[%p] stat(%s) error: %s",
					(void*)c->cev, path, strerror(errno));
		} else if (errno != ENOENT) {
			if (unlink(path)) {
				xsyslog(LOG_WARNING, "client[%p] can't unlink %s: %s",
						(void*)c->cev, path, strerror(errno));
			}
		}
	}

	if (errmsg)
		return send_error(c, msg->id, errmsg, -1);

	{
		/* в этом блоке структура wx только настраивается,
			упаковка происходит дальше */
		bool fid_in; /* логический костыль */
		hash = guid2hash(msg->file_guid);
		fid_in = ((fid_ws = touch_id(c, &c->fid, hash)) != NULL);

		if (!fid_ws) {
			fid_ws = calloc(1, sizeof(struct wait_store)
					+ sizeof(struct wait_file));
			fid_ws->data = fid_ws + 1;
		}
		memset(&wx, 0, sizeof(struct wait_xfer));
		ws = calloc(1, sizeof(struct wait_store) + sizeof(struct wait_xfer));
		/* открытие/создание файла */
		wx.size = msg->size;
		wx.fd = open(path, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);
		if (wx.fd == -1 || !ws || !fid_ws) {
			errmsg = "Internal error: cache not available";
		}
		memcpy(wx.path, path, PATH_MAX);
		string2guid(msg->chunk_guid, strlen(msg->chunk_guid), &wx.chunk_guid);
		/* ссылаемся на wait_file и увеличиваем счётчик */
		wx.wf = fid_ws->data;
		wx.wf->ref++;
		wx.hash_len = msg->chunk_hash.len;
		memcpy(wx.hash, (void*)msg->chunk_hash.data, msg->chunk_hash.len);
		/* логический костыль */
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
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] fd#%d for %s [%"PRIu32"]",
			(void*)c->cev, wx.fd, wx.path, wrok.session_id);
#endif
	wait_id(c, &c->sid, wrok.session_id, ws);
	if (fid_ws) {
		wf = fid_ws->data;
		string2guid(msg->file_guid, strlen(msg->file_guid), &wf->file);
		string2guid(msg->revision_guid, strlen(msg->revision_guid),
				&wf->revision);
		string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid),
				&wf->rootdir);
		wf->id = hash;
		wait_id(c, &c->fid, hash, fid_ws);
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
	if (!wait_id(c, &c->mid, ping.id, s)) {
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
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] send error(%d): %s",
			(void*)c->cev, remain, message);
#endif
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

static inline const char *
list_name(struct client *c, struct listRoot *list)
{
	if (list == &c->mid)
		return "mid";
	else if(list == &c->sid)
		return "sid";
	else if(list == &c->fid)
		return "fid";
	else
		return "???";
}

bool
wait_id(struct client *c, struct listRoot *list, uint64_t id, wait_store_t *s)
{
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] list wait_id(%s, %"PRIu64")",
			(void*)c->cev, list_name(c, list), id);
#endif

	return list_alloc(list, id, s);
}

wait_store_t*
query_id(struct client *c, struct listRoot *list, uint64_t id)
{
	struct listNode *ln;
	wait_store_t *data;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] list query_id(%s, %"PRIu64")",
			(void*)c->cev, list_name(c, list), id);
#endif
	if (!(ln = list_find(list, id)))
		return NULL;

	data = (wait_store_t*)ln->data;

	/* удаление ненужной структуры */
	list_free_node(ln, NULL);
	return data;
}

wait_store_t*
touch_id(struct client *c, struct listRoot *list, uint64_t id)
{
	struct listNode *ln;
	ln = list_find(list, id);
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] list touch_id(%s, %"PRIu64") -> %s",
			(void*)c->cev, list_name(c, list), id, ln ? "found" : "not found");
#endif
	if (ln)
		return (wait_store_t*)ln->data;
	return NULL;
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

	ws = touch_id(c, &c->sid, xfer->session_id);
	if (!ws) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] xfer not found for id %"PRIu32,
				(void*)c->cev, xfer->session_id);
#endif
		return send_error(c, xfer->id, "Unexpected xfer message", -1);
	}
	wx = ws->data;

	if (xfer->data.len + xfer->offset > wx->size) {
		errmsg = "Owerdose input data";
	} else if (lseek(wx->fd, (off_t)xfer->offset, SEEK_SET) == (off_t)-1) {
		errmsg = "Can't set offset";
	} else if (write(wx->fd, xfer->data.data, xfer->data.len) != xfer->data.len) {
		errmsg = "Write fail";
	} else {
		wx->filling += xfer->data.len;
		return true;
	}
#if DEEPDEBUG
	if (errmsg) {
		xsyslog(LOG_DEBUG, "client[%p] got xfer fd#%d error: %s",
				(void*)c->cev, wx->fd, strerror(errno));
	} else {
		xsyslog(LOG_DEBUG, "client[%p] destroy xfer fd#%d because error",
				(void*)c->cev, wx->fd);
	}
#endif
	/* больше чанк нам не нужен, т.к. его должны переслать заного
	 * закрываем всякие ресурсы и уменьшаем счётчик ссылок
	 */
	wx->wf->ref--;
	close(wx->fd);
	unlink(wx->path);
	/* освобождение памяти в последнюю очередь,
	 * т.к. wx и ws выделяются в последнюю очередь
	 */
	if ((ws = query_id(c, &c->sid, xfer->session_id)) != NULL)
		free(ws);
	return send_error(c, xfer->id, errmsg, -1);
}

static void
_file_update_notify_free(struct fdb_fileUpdate *ffu)
{
	free(ffu);
}

static inline bool
_file_update_notify(struct client *c, struct wait_file *wf)
{
	struct fdb_fileUpdate *ffu;
	size_t hash_sz;
	size_t enc_sz;
	size_t key_sz;
	Fep__FileUpdate fu = FEP__FILE_UPDATE__INIT;
	hash_sz = wf->hash_filename ? strlen(wf->hash_filename) + 1 : 0u;
	enc_sz = wf->enc_filename ? strlen(wf->enc_filename) + 1 : 0u;
	key_sz = wf->key_len ? wf->key_len + 1 : 0u;
	ffu = calloc(1, sizeof(struct fdb_fileUpdate) + enc_sz + key_sz + hash_sz);
	if (!ffu)
		return false;
	ffu->head.type = C_FILEUPDATE;

	guid2string(&wf->rootdir, ffu->rootdir_guid, GUID_MAX);
	guid2string(&wf->file, ffu->file_guid, GUID_MAX);
	guid2string(&wf->revision, ffu->revision_guid, GUID_MAX);

	if (key_sz) {
		ffu->key = (char*)(ffu + 1);
		memcpy(ffu->key, wf->key, wf->key_len);
		fu.key.data = (uint8_t*)ffu->key;
		fu.key.len = wf->key_len;
		fu.has_key = true;
	}

	if (hash_sz) {
		ffu->hash_filename = ((char*)(ffu + 1)) + key_sz;
		memcpy(ffu->hash_filename, wf->hash_filename, hash_sz);
		fu.hash_filename = ffu->hash_filename;
	}

	if (enc_sz) {
		ffu->enc_filename = ((char*)(ffu + 1)) + key_sz + hash_sz;
		memcpy(ffu->enc_filename, wf->enc_filename, enc_sz);
		fu.enc_filename = ffu->enc_filename;
	}

	fu.rootdir_guid = ffu->rootdir_guid;
	fu.file_guid = ffu->file_guid;
	fu.revision_guid = ffu->revision_guid;
	fu.chunks = wf->chunks;

	memcpy(&ffu->msg, &fu, sizeof(Fep__FileUpdate));
	if (fdb_store(c->fdb, ffu, (void(*)(void*))_file_update_notify_free))
		return true;
	_file_update_notify_free(ffu);
	return false;
}

bool
file_check_update(struct client *c, struct wait_file *wf)
{
	void *d;
	/* TODO: разослать уведомление */
	if (wf->chunks == wf->chunks_ok) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] file fin: %u/%u[%u]",
				(void*)c->cev, (unsigned)wf->chunks_ok,
				(unsigned)wf->chunks, (unsigned)wf->chunks_fail);
#endif
		/* все чанки сошлись, теперь можно сделать запись в бд
		 * и разослать клиентам уведомления
		 */
		if (!wf->notified) {
			/* TODO */
			wf->notified = spq_f_chunkFile(c->name,
					&wf->rootdir, &wf->file, &wf->revision,
					&wf->parent_revision,
					wf->enc_filename, wf->hash_filename,
					wf->key, wf->key_len);
			_file_update_notify(c, wf);
		}
		/* ссылок больше нет, можно подчистить */
		if (!wf->ref) {
#if DEEPDEBUG
			xsyslog(LOG_DEBUG, "client[%p] file fully loaded, notify = %s",
					(void*)c->cev, wf->notified ? "true" : "false");
#endif
			if ((d = query_id(c, &c->fid, wf->id)) != NULL)
				fid_free(d);
		}		return true;
	}
	return false;
}

bool
_handle_file_update(struct client *c, unsigned type, Fep__FileUpdate *fu)
{
	uint64_t hash;
	wait_store_t *ws;
	struct wait_file *wf;
	bool ws_touched;

	hash = guid2hash(fu->file_guid);

	/* ws_touched нужен для избежания попадания второй записи об одном файле
	 * в список
	 */
	ws_touched = ((ws = touch_id(c, &c->fid, hash)) != NULL);
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
		/* file_guid используется как id, потому назначается сразу
		 * при создании структуры
		 */
		string2guid(fu->file_guid, strlen(fu->file_guid), &wf->file);
	} else {
		wf = ws->data;
	}
	if (fu->parent_revision_guid)
		string2guid(fu->parent_revision_guid, strlen(fu->parent_revision_guid),
				&wf->parent_revision);
	if (fu->enc_filename && !wf->enc_filename)
		wf->enc_filename = strdup(fu->enc_filename);
	if (fu->hash_filename && !wf->hash_filename)
		wf->hash_filename = strdup(fu->hash_filename);
	if (fu->key.len && !wf->key) {
		wf->key = calloc(1, fu->key.len);
		wf->key_len = fu->key.len;
		memcpy(wf->key, fu->key.data, wf->key_len);
	}
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "enc_filename: \"%s\", hash_filename: \"%s\", "
			"file_guid: \"%s\", revision_guid: \"%s\", key_len: %"PRIuPTR,
			fu->enc_filename, fu->hash_filename,
			fu->file_guid, fu->revision_guid, wf->key_len);
#endif
	wf->chunks = fu->chunks;
	if (!file_check_update(c, wf) && !ws_touched) {
		wait_id(c, &c->fid, hash, ws);
	}
	return send_ok(c, fu->id);
}

bool
_handle_end(struct client *c, unsigned type, Fep__End *end)
{
	struct wait_store *ws;
	struct wait_xfer wx;
	char chunk_hash[HASHHEX_MAX + 1];
	char *errmsg = NULL;

	ws = query_id(c, &c->sid, end->session_id);
	if (!ws) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] End not found for id %"PRIu32,
				(void*)c->cev, end->session_id);
#endif
		return send_error(c, end->id, "Unexpected End message", -1);
	}
	/* копия для удобства и освобождаем память от ненужной структуры */
	memcpy(&wx, ws->data, sizeof(struct wait_xfer));
	free(ws);
	/* закрываем всякий мусор и уменьшаем счётчик */
	wx.wf->ref--;
	close(wx.fd);
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] close fd#%d, id %"PRIu32,
			(void*)c->cev, wx.fd, end->session_id);
#endif
	/* размеры не совпали */
	if (wx.filling != wx.size) {
		errmsg = "Infernal sizes";
	}

	if (!errmsg) {
		/* чанк пришёл, теперь нужно обновить информацию в бд */
		bin2hex(wx.hash, wx.hash_len, chunk_hash, sizeof(chunk_hash));
		spq_f_chunkNew(c->name, chunk_hash, wx.path, &wx.wf->rootdir,
				&wx.wf->revision, &wx.chunk_guid, &wx.wf->file,
				end->offset, end->origin_len);
		/* заодно проверяем готовность файла */
		wx.wf->chunks_ok++;
		file_check_update(c, wx.wf);
		return send_ok(c, end->id);
	}
	/* чанк не нужен, клиент перетащит его заного */
	wx.wf->chunks_fail++;
	unlink(wx.path);
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
	TYPICAL_HANDLE_S(FEP__TYPE__tRenameChunk, rename_chunk), /* 14 */
	TYPICAL_HANDLE_S(FEP__TYPE__tQueryChunks, query_chunks), /* 15 */
	TYPICAL_HANDLE_S(FEP__TYPE__tResultChunk, result_chunk), /* 16 */
	TYPICAL_HANDLE_S(FEP__TYPE__tQueryRevisions, query_revisions), /* 17 */
	TYPICAL_HANDLE_S(FEP__TYPE__tResultRevision, result_revision), /* 18 */
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

#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] transmit header[type: %u, len: %"PRIuPTR"]",
			(void*)cev, type, len);
#endif
	/* упаковывается сообщение */
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
			/* два байта на тип */
			memcpy(&c->h_type, buf, 2);
			/* и три байта на длину */
			memcpy(&c->h_len, &buf[2], 3);
			/* привести к хостовому порядку байт */
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
	c->options.send_buffer = 9660;
	return true;
}

static inline void
client_destroy(struct client *c)
{
	if (!c)
		return;
	/* чистка очередей */
	do {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] remain %"PRIuPTR" mid",
				(void*)c, c->mid.count);
#endif
	} while (list_free_root(&c->mid, &mid_free));
	do {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] remain %"PRIuPTR" sid",
				(void*)c, c->sid.count);
#endif
	} while (list_free_root(&c->sid, (void(*)(void*))&sid_free));
	do {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] remain %"PRIuPTR" fid",
				(void*)c, c->fid.count);
#endif
	} while (list_free_root(&c->fid, (void(*)(void*))&fid_free));

	while (cout_free(c));
	while (rout_free(c));

	/* ? */
	fdb_uncursor(c->fdb);

	/* буфера */
	if (c->cout_buffer)
		free(c->cout_buffer);
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

bool static inline
_client_iterate_result(struct client *c)
{
	if (!c->rout)
		return true;
	/* обработка сообщений чанков */
	if (c->rout->type == RESULT_CHUNKS) {
		Fep__ResultChunk msg = FEP__RESULT_CHUNK__INIT;
		char guid[GUID_MAX + 1];
		char hash[HASH_MAX + 1];
		size_t hash_len;
		if (!spq_f_getChunks_it(&c->rout->v.c)) {
			/* итерироваться больше некуда, потому подчищаем */
			uint64_t id = c->rout->id;
			rout_free(c);
			return send_ok(c, id);
		}
		guid2string(&c->rout->v.c.chunk, guid, sizeof(guid));
		hash_len = hex2bin(c->rout->v.c.hash, strlen(c->rout->v.c.hash),
				hash, sizeof(hash));
		msg.id = c->rout->id;
		msg.chunk_guid = guid;
		msg.chunk_no = c->rout->v.c.row;
		msg.chunk_max = c->rout->v.c.max;
		msg.chunk_hash.data = (uint8_t*)hash;
		msg.chunk_hash.len = hash_len;
		return send_message(c->cev, FEP__TYPE__tResultChunk, &msg);
	} else if (c->rout->type == RESULT_REVISIONS) {
		Fep__ResultRevision msg = FEP__RESULT_REVISION__INIT;
		char guid[GUID_MAX + 1];
		char parent[GUID_MAX + 1];
		if (!spq_f_getRevisions_it(&c->rout->v.r)) {
			uint64_t id = c->rout->id;
			rout_free(c);
			return send_ok(c, id);
		}
		if (c->rout->v.r.parent.not_null) {
			guid2string(&c->rout->v.r.parent, parent, sizeof(guid));
			msg.parent_revision_guid = parent;
		}
		guid2string(&c->rout->v.r.revision, guid, sizeof(guid));
		msg.id = c->rout->id;
		msg.rev_no = c->rout->v.r.row;
		msg.rev_max = c->rout->v.r.max;
		msg.revision_guid = guid;
		return send_message(c->cev, FEP__TYPE__tResultRevision, &msg);
	}
	return true;
}

bool static inline
_client_iterate_chunk(struct client *c)
{
	Fep__Xfer xfer_msg = FEP__XFER__INIT;
	ssize_t transed;
	size_t readsz;

	/* выход если файлов нет */
	if (!c->cout)
		return true;
	/* проверка размера буфера отправки и попытки его выделить */
	if (!c->cout_buffer || c->cout_bfsz != c->options.send_buffer) {
		void *p = realloc(c->cout_buffer, c->options.send_buffer);
		if (!p) {
			xsyslog(LOG_INFO, "client[%p] realloc from "
					"%"PRIuPTR" to %"PRIuPTR": %s",
					(void*)c->cev, c->cout_bfsz, c->options.send_buffer,
					strerror(errno));
			if (!c->cout_bfsz)
				return true;
		} else {
			c->cout_bfsz = c->options.send_buffer;
		}
	}
	/* если прочитали всё что можно -- шлём End и деаллочимся */
	if (c->cout->sent == c->cout->size) {
		/* TODO: отослать End */
		cout_free(c);
	}
	/* чтение файла */
	readsz = MIN(c->cout_bfsz, c->cout->size - c->cout->sent);
	transed = read(c->cout->fd, c->cout_buffer, readsz);
	if (transed <= 0) {
		if (transed == -1) {
			xsyslog(LOG_INFO, "client[%p] read failed: %s",
					(void*)c->cev, strerror(errno));
		}
		cout_free(c);
		return true;
	}
	/* сохранение позиции,
	 * её нужно передать клиенту
	 * и обновляем данные
	 */
	readsz = c->cout->sent;
	c->cout->sent += (size_t)readsz;
	/* отправка чанкодаты */
	xfer_msg.id = generate_id(c);
	xfer_msg.session_id = c->cout->session_id;
	xfer_msg.offset = readsz;
	xfer_msg.data.data = (uint8_t*)c->cout_buffer;
	xfer_msg.data.len = transed;
	return send_message(c->cev, FEP__TYPE__txfer, &xfer_msg);
}

bool static inline
_client_iterate_read(struct client *c)
{
	register int lval;
	/* алоцируем буфер */
	if (c->blen + BUFFER_ALLOC > c->bsz) {
		void *tmp;
		tmp = realloc(c->buffer, c->bsz + BUFFER_ALLOC);
		if (!tmp) {
			xsyslog(LOG_WARNING, "client %p, grow from %lu to %lu fail: %s",
					(void*)c->cev, c->bsz, c->bsz + BUFFER_ALLOC,
					strerror(errno));
			/* если обвалились по памяти, то ждём следующей итерации,
			 * так как в процессе может что-то освободиться */
			return true;
		}
		c->buffer = tmp;
		c->bsz += BUFFER_ALLOC;
	}
	/* wait data */
	lval = sev_recv(c->cev, &c->buffer[c->blen], c->bsz - c->blen);
	if (lval < 0) {
		xsyslog(LOG_WARNING, "client[%p] recv %d\n", (void*)c->cev, lval);
		return false;
	} else if (lval == 0) {
		/* pass to cycle sanitize (check timeouts, etc) */
		return true;
	}
	c->blen += lval;
	return true;
}

static inline bool
_client_iterate_fdb(struct client *c)
{
	struct fdb_head *inm;
	while ((inm = fdb_walk(c->fdb)) != NULL) {
		if (inm->type != C_FILEUPDATE) {
			xsyslog(LOG_INFO, "client[%p] not file update", (void*)c->cev);
			return true;
		}
		{
			struct fdb_fileUpdate *ffu = (void*)inm;
			ffu->msg.id = generate_id(c);
			send_message(c->cev, FEP__TYPE__tFileUpdate, &ffu->msg);
		}
	}
	return true;
}

static inline bool
_client_iterate_handle(struct client *c)
{
	register int lval;
	lval = handle_header(c->buffer, c->blen, c);
	/* смещаем хвост в начало буфера */
	if (lval > 0) {
		if (lval < c->blen) {
			/* если вдруг обвалится memove, то восстанавливать, вощем-то,
			 * нечего, потому просто валимся
			 */
			if (!memmove(c->buffer, &c->buffer[lval], c->blen - lval)) {
				xsyslog(LOG_WARNING, "client[%p] memmove() fail: %s",
						(void*)c->cev, strerror(errno));
				return false;
			}
			c->blen -= lval;
		} else {
			c->blen = 0u;
		}
	} else if (lval == HEADER_INVALID) {
		xsyslog(LOG_WARNING, "client[%p] mismatch protocol:"
				"%x %x %x %x %x %x", (void*)c->cev,
				c->buffer[0], c->buffer[1], c->buffer[2],
				c->buffer[3], c->buffer[4], c->buffer[5]);
		return false;
	} else if (lval == HEADER_STOP) {
		xsyslog(LOG_WARNING, "client[%p] stop chat with "
				"header[type: %u, len: %u]",
				(void*)c->cev, c->h_type, c->h_len);
	} else if (lval == HEADER_MORE) {
		if (!_client_iterate_read(c))
			return false;
	}
	if (c->count_error <= 0) {
		xsyslog(LOG_INFO, "client[%p] to many errors", (void*)c->cev);
		return false;
	}
	return true;
}

/* вовзращает положительный результат, если требуется прервать io */
bool
client_iterate(struct sev_ctx *cev, bool last, void **p)
{
	struct client *c = (struct client *)*p;
	/* подчищаем, если вдруг последний раз запускаемся */
	if (last) {
		client_destroy(c);
		*p = NULL;
		return true;
	} else if (p && !c) {
		/* инициализация */
		c = client_alloc(cev);
		if (!(*p = (void*)c))
			return true;
		c->cev->recv_timeout = 2;
		c->fdb = fdb_cursor();
		if (!c->fdb) {
			xsyslog(LOG_WARNING, "client[%p] can't get fdb cursor",
					(void*)cev);
		}
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

			if (!s || !wait_id(c, &c->mid, reqAuth.id, s)) {
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

	if (c->state > CEV_AUTH) {
		/* всякая ерунда на отправку */
		if (!_client_iterate_fdb(c)) {
			return false;
		}
	}

	/* в первую помощь нужно отправить короткие сообщения из базы
	 * а потом можно слать куски файлов
	 */
	if (c->rout) {
		if (!_client_iterate_result(c))
			return false;
	} else {
		/* отправка куска чанка-файла клиенту, если такие есть в очереди */
		if (!_client_iterate_chunk(c))
			return false;
	}

	/* если обработка заголовка или чтение завалилось,
	 * то можно прерывать цикл
	 */
	if (!_client_iterate_handle(c)) {
		return false;
	}

	/* нужно выставить флаг быстрого пропуска,
	 * если есть файлы в очереди
	 */
	if (c->cout) {
		cev->action |= SEV_ACTION_FASTTEST;
	}
	/* переходим на следующую итерацию */
	return true;
}

