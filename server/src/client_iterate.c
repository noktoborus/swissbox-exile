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

NOTIMP_HANDLE_F(Fep__ResultChunk, result_chunk)
NOTIMP_HANDLE_F(Fep__ResultRevision, result_revision)

NOTIMP_HANDLE_F(Fep__FileMeta, file_meta)
NOTIMP_HANDLE_F(Fep__OkUpdate, ok_update)

struct client_cum {
	uint32_t namehash;
	pthread_mutex_t lock;
	unsigned ref; /* подсчёт ссылок */

	uint64_t new_checkpoint;

	/* к этим областям нужно обращаться только
	 * после блокировки корня (clients_cum.lock)
	 */
	struct client_cum *next;
	struct client_cum *prev;
};

static struct clients_cum {
	bool inited;
	struct client_cum *first;
	pthread_mutex_t lock;
} clients_cum;

static void
client_cum_free(struct client_cum *ccum)
{
	unsigned ref;
	if (!ccum)
		return;
	/* считаем ссылки */
	pthread_mutex_lock(&ccum->lock);
	ref = (--ccum->ref);
	pthread_mutex_unlock(&ccum->lock);

	/* не нужно ничего чистить, если на структуру ещё ссылаются */
	if (ref)
		return;

	pthread_mutex_lock(&clients_cum.lock);
	if (ccum == clients_cum.first)
		clients_cum.first = ccum->next ? ccum->next : ccum->prev;
	if (ccum->next)
		ccum->next = ccum->prev;
	if (ccum->prev)
		ccum->prev = ccum->next;
	pthread_mutex_unlock(&clients_cum.lock);

	pthread_mutex_destroy(&ccum->lock);
	free(ccum);
}

static struct client_cum*
client_cum_create(uint32_t namehash)
{
	struct client_cum *ccum = NULL;

	if (pthread_mutex_lock(&clients_cum.lock))
		return NULL;

	for (ccum = clients_cum.first; ccum; ccum = ccum->next) {
		if (ccum->namehash == namehash)
			break;
	}

	if (!ccum) {
		ccum = calloc(1, sizeof(struct client_cum));
		if (!ccum) {
			xsyslog(LOG_WARNING, "memory fail when communication with over");
		} else {
			pthread_mutex_init(&ccum->lock, NULL);
			ccum->namehash = namehash;
			if ((ccum->next = clients_cum.first) != NULL)
				ccum->next->prev = ccum;
			clients_cum.first = ccum;
		}
	}

	pthread_mutex_unlock(&clients_cum.lock);
	/* нужно отметиться */
	ccum->ref++;

	return ccum;
}

void
client_threads_bye()
{
	while (clients_cum.first)
		client_cum_free(clients_cum.first);

	pthread_mutex_destroy(&clients_cum.lock);
	clients_cum.inited = false;
}

void
client_threads_prealloc()
{
	pthread_mutex_init(&clients_cum.lock, NULL);
	clients_cum.inited = true;
}

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
_handle_directory_update(struct client *c, unsigned type,
		Fep__DirectoryUpdate *msg)
{
	/*
	 * тактика: отправить запись в бд
	 */
	return send_ok(c, msg->id, C_OK_SIMPLE);
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
	rs->id = msg->session_id;
	rs->type = RESULT_REVISIONS;
	rs->free = (void(*)(void*))spq_f_getRevisions_free;
	rs->next = c->rout;
	c->rout = rs;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] -> QueryRevisions id = %"PRIu64
			" sid = %"PRIu32,
			(void*)c->cev, msg->id, msg->session_id);
#endif
	return send_ok(c, msg->id, C_OK_SIMPLE);
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
	rs->id = msg->session_id;
	rs->type = RESULT_CHUNKS;
	rs->free = (void(*)(void*))spq_f_getChunks_free;
	rs->next = c->rout;
	c->rout = rs;
	return send_ok(c, msg->id, C_OK_SIMPLE);
}

/*
 * активация отправки лога клиенту
 * TODO: аргумнет slice -- отправлять ли лог или текущее состояние
 */
static inline bool
_active_sync(struct client *c, uint32_t session_id, bool slice)
{
	/* генерация списка последних обновлений директорий и файлов */
	struct logDirFile gs;
	struct result_send *rs;

	memset(&gs, 0, sizeof(struct logDirFile));
	if (!spq_f_logDirFile(c->name, c->checkpoint, c->device_id, &gs)) {
		return false;
	}

	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_f_logDirFile_free(&gs);
		return false;
	}
	memcpy(&rs->v, &gs, sizeof(struct logDirFile));
	rs->id = session_id;
	rs->type = RESULT_LOGDIRFILE;
	rs->free = (void(*)(void*))spq_f_logDirFile_free;
	rs->next = c->rout;
	c->rout = rs;

	return true;
}

bool
_handle_want_sync(struct client *c, unsigned type, Fep__WantSync *msg)
{
	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	/* после запроса состояния можно и запустить экспресс-нотификацию */
	if (!c->cum) {
		c->cum = client_cum_create(hash_pjw(c->name, strlen(c->name)));
	}

	c->checkpoint = msg->checkpoint;
	if (!_active_sync(c, msg->session_id, false)) {
		return send_error(c, msg->id, "Internal error 1653", -1);
	}

	return send_ok(c, msg->id, C_OK_SIMPLE);
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
	size_t offset;
	size_t origin;

	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);
	string2guid(msg->chunk_guid, strlen(msg->chunk_guid), &chunk);

	if (!spq_f_getChunkPath(c->name, &rootdir, &file, &chunk,
				path, sizeof(path), &offset, &origin)) {
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
	chs->session_id = msg->session_id;
	chs->size = st.st_size;
	chs->next = c->cout;
	chs->origin_len = origin;
	chs->file_offset = offset;
	c->cout = chs;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] -> ReadAsk id = %"PRIu64", sid = %"PRIu32,
			(void*)c->cev, msg->id, msg->session_id);
#endif

	return send_ok(c, msg->id, C_OK_SIMPLE);
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

	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

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
		hash = MAKE_FHASH(msg->rootdir_guid, msg->file_guid);
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
send_ok(struct client *c, uint64_t id, uint64_t checkpoint)
{
	if (checkpoint == C_OK_SIMPLE) {
		Fep__Ok ok = FEP__OK__INIT;

		ok.id = id;
		return send_message(c->cev, FEP__TYPE__tOk, &ok);
	} else {
		Fep__OkUpdate oku = FEP__OK_UPDATE__INIT;

		oku.id = id;
		oku.checkpoint = checkpoint;
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

bool
file_check_complete(struct client *c, struct wait_file *wf)
{
	void *d;
	bool retval = false;
	/* TODO: разослать уведомление */
	if (wf->chunks == wf->chunks_ok) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] file fin: %u/%u[%u]",
				(void*)c->cev, (unsigned)wf->chunks_ok,
				(unsigned)wf->chunks, (unsigned)wf->chunks_fail);
#endif
		/* все чанки сошлись, теперь можно разослать клиентам уведомления
		 */
		/* TODO: _file_update_notify(c, wf); */
		retval = true;
#if DEEPDEBUG
		if (wf->ref) {
			xsyslog(LOG_DEBUG, "client[%p] file has ref links: %u",
					(void*)c->cev, wf->ref);
		}
#endif
	}
	/* ссылок больше нет, можно подчистить */
	if (!wf->ref) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] file fully loaded",
				(void*)c->cev);
#endif
		if ((d = query_id(c, &c->fid, wf->id)) != NULL)
			fid_free(d);
	}

	return retval;
}

bool
_handle_file_update(struct client *c, unsigned type, Fep__FileUpdate *fu)
{
	/* TODO: удаление файлов */
	uint64_t hash;
	wait_store_t *ws;
	struct wait_file *wf;

	if (!c->status.auth_ok)
		return send_error(c, fu->id, "Unauthorized", -1);

	hash = MAKE_FHASH(fu->rootdir_guid, fu->file_guid);

	/* ws_touched нужен для избежания попадания второй записи об одном файле
	 * в список
	 */
	ws = touch_id(c, &c->fid, hash);
	/* если записи нет, нужно создать новую */

	if (!ws) {
		return send_error(c, fu->id, "Unexpected FileUpdate", -1);
	} else {
		wf = ws->data;
	}
	/*
	 * TODO: учесть что FileUpdate может прийти без ключей
	 * сейчас ключи добавляются к каждой новой записи файла,
	 * но все ревизии имеют один ключ, привязанный к файлу
	 * вынести в отдельную таблицу записи ключей для файлов нужно
	 *
	 */

#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "enc_filename: \"%s\", "
			"file_guid: \"%s\", revision_guid: \"%s\", key_len: %"PRIuPTR,
			fu->enc_filename, fu->file_guid, fu->revision_guid, fu->key.len);
#endif
	/* TODO */
	if (file_check_complete(c, wf)) {
		register size_t len;
		uint64_t checkpoint;
		guid_t dir;
		guid_t parent;
		len = fu->parent_revision_guid ? strlen(fu->parent_revision_guid) : 0u;
		string2guid(fu->directory_guid, strlen(fu->directory_guid), &dir);
		string2guid(fu->parent_revision_guid, len, &parent);
		checkpoint = spq_f_chunkFile(c->name, &wf->rootdir,
				&wf->file, &wf->revision, &parent, &dir, fu->enc_filename,
				c->device_id, fu->key.data, fu->key.len);
		return send_ok(c, fu->id, checkpoint);
	} else {
		return send_error(c, fu->id, "not enought chunks", -1);
	}
}

bool
_handle_rename_chunk(struct client *c, unsigned type, Fep__RenameChunk *msg)
{
	uint64_t hash;
	struct wait_store *ws;
	struct wait_file *wf;
	char *errmsg = NULL;
	guid_t rootdir;
	guid_t file;
	guid_t chunk;
	guid_t revision_new;
	guid_t chunk_new;

	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);
	string2guid(msg->chunk_guid, strlen(msg->chunk_guid), &chunk);
	string2guid(msg->to_revision_guid, strlen(msg->to_revision_guid),
			&revision_new);
	string2guid(msg->to_chunk_guid, strlen(msg->to_chunk_guid), &chunk_new);

	/* получение хеша и поиск структуры в списке */
	hash = MAKE_FHASH(msg->rootdir_guid, msg->file_guid);
	if ((ws = touch_id(c, &c->fid, hash)) != NULL) {
		return send_error(c, msg->id, "Unexpected chunk rename", -1);
	}
	wf = ws->data;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "rename chunk: rootdir: %s, file: %s, chunk %s -> "
			"chunk %s, rev %s", msg->rootdir_guid, msg->file_guid,
			msg->chunk_guid, msg->to_chunk_guid, msg->to_revision_guid);
#endif
	/* манипуляция данными в бд */
	if (!spq_f_chunkRename(c->name, &rootdir, &file, &chunk,
				&chunk_new, &revision_new)) {
		wf->chunks_fail++;
		errmsg = "Internal error 600";
	} else {
		wf->chunks_ok++;
	}

	if (errmsg)
		return send_error(c, msg->id, errmsg, -1);
	return send_ok(c, msg->id, C_OK_SIMPLE);
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
		file_check_complete(c, wx.wf);
		return send_ok(c, end->id, C_OK_SIMPLE);
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
	if (send_error(c, 0, "Unknown packet", c->count_error)
			|| c->count_error <= 0)
		return false;
	else
		return true;
}

static struct handle handle[] =
{
	{0u, "Invalid", _handle_invalid, NULL, NULL}, /* 0 */
	TYPICAL_HANDLE_S(FEP__TYPE__tPing, "Ping", ping), /* 1 */
	TYPICAL_HANDLE_S(FEP__TYPE__tPong, "Pong", pong), /* 2 */
	RAW_P_HANDLE_S(FEP__TYPE__tError, "Error", error), /* 3 */
	RAW_P_HANDLE_S(FEP__TYPE__tOk, "Ok", ok), /* 4 */
	RAW_P_HANDLE_S(FEP__TYPE__tPending, "Pending", pending), /* 5 */
	INVALID_P_HANDLE_S(FEP__TYPE__tReqAuth, "ReqAuth", req_auth), /* 6 */
	TYPICAL_HANDLE_S(FEP__TYPE__tAuth, "Auth", auth), /* 7 */
	TYPICAL_HANDLE_S(FEP__TYPE__txfer, "xfer", xfer), /* 8 */
	TYPICAL_HANDLE_S(FEP__TYPE__tReadAsk, "ReadAsk", read_ask), /* 9 */
	TYPICAL_HANDLE_S(FEP__TYPE__tWriteAsk, "WriteAsk", write_ask), /* 10 */
	TYPICAL_HANDLE_S(FEP__TYPE__tEnd, "End", end), /* 11 */
	TYPICAL_HANDLE_S(FEP__TYPE__tWriteOk, "WriteOk", write_ok), /* 12 */
	TYPICAL_HANDLE_S(FEP__TYPE__tFileUpdate, "FileUpdate",
			file_update), /* 13 */
	TYPICAL_HANDLE_S(FEP__TYPE__tRenameChunk, "RenameChunk",
			rename_chunk), /* 14 */
	TYPICAL_HANDLE_S(FEP__TYPE__tQueryChunks, "QueryChunks",
			query_chunks), /* 15 */
	TYPICAL_HANDLE_S(FEP__TYPE__tResultChunk, "ResultChunk",
			result_chunk), /* 16 */
	TYPICAL_HANDLE_S(FEP__TYPE__tQueryRevisions, "QueryRevisions",
			query_revisions), /* 17 */
	TYPICAL_HANDLE_S(FEP__TYPE__tResultRevision, "ResultRevision",
			result_revision), /* 18 */
	TYPICAL_HANDLE_S(FEP__TYPE__tDirectoryUpdate, "DirectoryUpdate",
			directory_update), /* 19 */
	TYPICAL_HANDLE_S(FEP__TYPE__tFileMeta, "FileMeta", file_meta), /* 20 */
	TYPICAL_HANDLE_S(FEP__TYPE__tWantSync, "WantSync", want_sync), /* 21 */
	TYPICAL_HANDLE_S(FEP__TYPE__tOkUpdate, "OkUpdate", ok_update), /* 22 */
};

const char*
Fepstr(unsigned type)
{
	if (type >= sizeof(handle) / sizeof(struct handle))
		type = 0;
	return handle[type].text;
}

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
			/* шестой байт должен быть нулём */
			if (buf[5] != '\0') {
				return HEADER_INVALID;
			}
			/* два байта на тип */
			memcpy(&c->h_type, buf, 2);
			/* и три байта на длину */
			memcpy(&c->h_len, &buf[2], 3);
			/* привести к хостовому порядку байт */
			c->h_type = ntohs(c->h_type);
			c->h_len = ntohl(c->h_len << 8);
#if DEEPDEBUG
			xsyslog(LOG_DEBUG, "client[%p] got header[type: %u, len: %u]: "
					"%02x %02x %02x %02x %02x %02x "
					"(in %"PRIuPTR" bytes)",
					(void*)c->cev, c->h_type, c->h_len,
					buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
					size);
#endif
			/* бесполезная проверка на длину пакета */
			if (c->h_len > 1 << 24 || c->h_len == 0) {
				xsyslog(LOG_WARNING, "client[%p] header[type: %u, len: %u]: "
						"length can't be great then %d and equal zero",
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
				c->h_len = 0u;
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
		/* сброс типа сообщения, если всё нормально
		 * иначе нужно прокинуть наверх на чём мы встали
		 */
		if (!exit) {
			c->h_type = 0u;
			return (int)(c->h_len + HEADER_OFFSET);
		} else
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
	return send_ping(c);
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

	client_cum_free(c->cum);

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
_client_iterate_result_logdf(struct client *c, struct logDirFile *ldf)
{
	if (!spq_f_logDirFile_it(ldf)) {
		rout_free(c);
		return true;
	}

	c->checkpoint = ldf->checkpoint;
	if (ldf->type == 'd') {
		Fep__DirectoryUpdate msg = FEP__DIRECTORY_UPDATE__INIT;
		char guid[GUID_MAX + 1];
		char rootdir[GUID_MAX + 1];

		msg.id = generate_id(c);

		guid2string(&c->rout->v.df.directory, guid, sizeof(guid));
		guid2string(&c->rout->v.df.rootdir, rootdir, sizeof(rootdir));
		msg.rootdir_guid = rootdir;
		msg.guid = guid;
		msg.checkpoint = c->rout->v.df.checkpoint;
		msg.no = c->rout->v.df.row;
		msg.max = c->rout->v.df.max;
		if (c->rout->id != C_NOSESSID)
			msg.session_id = c->rout->id;

		return send_message(c->cev, FEP__TYPE__tDirectoryUpdate, &msg);
	} else if (ldf->type == 'f') {
		Fep__FileUpdate msg = FEP__FILE_UPDATE__INIT;

		char rootdir[GUID_MAX + 1];
		char file[GUID_MAX + 1];
		char dir[GUID_MAX + 1];
		char revision[GUID_MAX + 1];
		char parent_rev[GUID_MAX + 1];

		msg.id = generate_id(c);
		msg.checkpoint = ldf->checkpoint;

		guid2string(&ldf->rootdir, rootdir, sizeof(rootdir));
		guid2string(&ldf->file, file, sizeof(file));
		guid2string(&ldf->directory, dir, sizeof(dir));
		guid2string(&ldf->revision, revision, sizeof(revision));
		guid2string(&ldf->parent, parent_rev, sizeof(parent_rev));

		msg.rootdir_guid = rootdir;
		msg.file_guid = file;
		msg.revision_guid = revision;
		msg.enc_filename = ldf->path;
		msg.has_key = true;
		msg.key.data = ldf->key;
		msg.key.len = ldf->key_len;
		msg.chunks = ldf->chunks;
		msg.no = ldf->row;
		msg.max = ldf->max;
		if (c->rout->id != C_NOSESSID)
			msg.session_id = c->rout->id;

		return send_message(c->cev, FEP__TYPE__tFileUpdate, &msg);
	} else {
		xsyslog(LOG_WARNING, "user '%s' with unknown log record '%c'",
				c->name, ldf->type);
	}
	return true;
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
		uint8_t hash[HASH_MAX + 1];
		size_t hash_len;
		if (!spq_f_getChunks_it(&c->rout->v.c)) {
			/* итерироваться больше некуда, потому подчищаем */
			rout_free(c);
			return true;
		}
		guid2string(&c->rout->v.c.chunk, guid, sizeof(guid));
		hash_len = hex2bin(c->rout->v.c.hash, strlen(c->rout->v.c.hash),
				hash, sizeof(hash));
		msg.id = generate_id(c);
		msg.session_id = c->rout->id;
		msg.chunk_guid = guid;
		msg.chunk_no = c->rout->v.c.row;
		msg.chunk_max = c->rout->v.c.max;
		msg.chunk_hash.data = (uint8_t*)hash;
		msg.chunk_hash.len = hash_len;
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] <- ResultChunk id = %"PRIu64
				" sid = %"PRIu32" #%"PRIu32"/%"PRIu32,
				(void*)c->cev, msg.id, msg.session_id,
				msg.chunk_no, msg.chunk_max);
#endif
		return send_message(c->cev, FEP__TYPE__tResultChunk, &msg);
	} else if (c->rout->type == RESULT_REVISIONS) {
		Fep__ResultRevision msg = FEP__RESULT_REVISION__INIT;
		char guid[GUID_MAX + 1];
		char parent[GUID_MAX + 1];
		if (!spq_f_getRevisions_it(&c->rout->v.r)) {
			rout_free(c);
			return true;
		}
		if (c->rout->v.r.parent.not_null) {
			guid2string(&c->rout->v.r.parent, parent, sizeof(guid));
			msg.parent_revision_guid = parent;
		}
		guid2string(&c->rout->v.r.revision, guid, sizeof(guid));
		msg.id = generate_id(c);
		msg.session_id = c->rout->id;
		msg.rev_no = c->rout->v.r.row;
		msg.rev_max = c->rout->v.r.max;
		msg.revision_guid = guid;
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] <- ResultRevision id = %"PRIu64
				" sid = %"PRIu32" #%"PRIu32"/%"PRIu32,
				(void*)c->cev, msg.id, msg.session_id,
				msg.rev_no, msg.rev_max);
#endif
		return send_message(c->cev, FEP__TYPE__tResultRevision, &msg);
	} else if (c->rout->type == RESULT_LOGDIRFILE) {
		return _client_iterate_result_logdf(c, &c->rout->v.df);
	} else {
		xsyslog(LOG_WARNING, "client[%p] unknown rout type: %d\n",
				(void*)c, c->rout->type);
		rout_free(c);
	}
	return true;
}

bool static inline
_client_iterate_chunk(struct client *c)
{
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
			c->cout_buffer = p;
		}
	}
	/* если прочитали всё что можно -- шлём End и деаллочимся */
	if (c->cout->sent == c->cout->size) {
		Fep__End msg = FEP__END__INIT;
		msg.id = generate_id(c);
		msg.session_id = c->cout->session_id;
		msg.offset = c->cout->file_offset;
		msg.origin_len = c->cout->origin_len;
		cout_free(c);
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%p] <- End id = %"PRIu64" sid = %"PRIu32,
				(void*)c->cev, msg.id, msg.session_id);
#endif
		return send_message(c->cev, FEP__TYPE__tEnd, &msg);
	} else {
		/* чтение файла */
		readsz = MIN(c->cout_bfsz, c->cout->size - c->cout->sent);
		transed = read(c->cout->fd, c->cout_buffer, readsz);
		if (transed <= 0) {
			if (transed == -1) {
				xsyslog(LOG_INFO, "client[%p] read failed: %s",
						(void*)c->cev, strerror(errno));
			} else {
				xsyslog(LOG_INFO, "client[%p] read wtf: %s",
						(void*)c->cev, strerror(errno));
			}
		} else {
			Fep__Xfer xfer_msg = FEP__XFER__INIT;
			/* отправка чанкодаты */
			xfer_msg.id = generate_id(c);
			xfer_msg.session_id = c->cout->session_id;
			xfer_msg.offset = c->cout->sent;
			xfer_msg.data.data = (uint8_t*)c->cout_buffer;
			xfer_msg.data.len = transed;
			/* сохранение позиции,
			 * её нужно передать клиенту
			 * и обновляем данные
			 */
			c->cout->sent += (size_t)readsz;
#if DEEPDEBUG
			xsyslog(LOG_DEBUG, "client[%p] <- xfer id = %"PRIu64
					" sid = %"PRIu32", offset=%"PRIu64", len = %"PRIu64,
					(void*)c->cev, xfer_msg.id, xfer_msg.session_id,
					xfer_msg.offset, xfer_msg.data.len);
#endif
			return send_message(c->cev, FEP__TYPE__txfer, &xfer_msg);
		}
	}
	return true;
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
	register size_t blen;

	if ((blen = c->blen) == 0u) {
		/* предварительное чтение из сокета, если данных в буфере нет */
		if (!_client_iterate_read(c)) {
			return false;
		} else if (c->blen == blen) {
			/* если размер буфера не изменился, то смысла выполнять весь
			 * следующий код нет, выходим заранее
			 */
			return true;
		}
	}

	lval = handle_header(c->buffer, c->blen, c);
	/* смещаем хвост в начало буфера */
	if (lval > 0) {
		if (lval < c->blen) {
			/* если вдруг обвалится memove, то восстанавливать, вощем-то,
			 * нечего, потому просто валимся
			 * FIXME: и снова ring buffer
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
				"%02x %02x %02x %02x %02x %02x", (void*)c->cev,
				c->buffer[0], c->buffer[1], c->buffer[2],
				c->buffer[3], c->buffer[4], c->buffer[5]);
		return false;
	} else if (lval == HEADER_STOP) {
		/* словили остановку -- сообщаем в лог и выходим */
		xsyslog(LOG_WARNING, "client[%p] stop chat with "
				"header[type: %u, len: %u]",
				(void*)c->cev, c->h_type, c->h_len);
		return false;
	} else if (lval == HEADER_MORE) {
		/* если просит больше, нужно взять */
		if (!_client_iterate_read(c))
			return false;
	}
	if (c->count_error <= 0) {
		/* слишком много странного произошло в сессию, дропаем подключение */
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
	 * если есть файлы в очереди или необработанная дата
	 */
	if (c->cout || c->rout || c->blen) {
		cev->action |= SEV_ACTION_FASTTEST;
	} else if (c->cum && c->status.log_active) {
		/* если нет никаких "срочных" действий, можно проверить сообщения
		 * от других тредов
		 */
		pthread_mutex_lock(&c->cum->lock);
		/* если чекпоинт "уехал", то нам тоже нужно двигаться вперёд */
		if (c->cum->new_checkpoint > c->checkpoint) {
			_active_sync(c, C_NOSESSID, false);
		}
		pthread_mutex_unlock(&c->cum->lock);
	}
	/* переходим на следующую итерацию */
	return true;
}

