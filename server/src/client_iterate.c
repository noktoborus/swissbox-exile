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

#include "packet.h"

TYPICAL_HANDLE_F(Fep__Pong, pong, &c->mid)
TYPICAL_HANDLE_F(Fep__Auth, auth, &c->mid)
TYPICAL_HANDLE_F(Fep__Ok, ok, &c->mid)
TYPICAL_HANDLE_F(Fep__Error, error, &c->mid)
TYPICAL_HANDLE_F(Fep__Pending, pending, &c->mid)

void
client_threads_bye()
{
	client_cum_destroy();
}

void
client_threads_prealloc()
{
	client_cum_init();
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
		if (fcac_opened(&p->p)) {
			fcac_close(&p->p);
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
	if ((wx = ws->data) != NULL) {
		if (wx->wf) {
			wx->wf->ref--;
		}
		if (fcac_opened(&wx->p)) {
			xsyslog(LOG_DEBUG, "destroy xfer fd#%"PRIu64, wx->p.id);
			fcac_close(&wx->p);
		}
#if !POLARSSL_LESS_138
		sha256_free(&wx->sha256);
#endif
	}
	free(ws);
}

static void
client_share_checkpoint(struct client *c, guid_t *rootdir, uint64_t checkpoint)
{
	uint32_t hash = hash_pjw((void*)rootdir, sizeof(guid_t));
	struct listNode *rp = NULL;
	struct rootdir_g *rg = NULL;
	struct listPtr lp = {0};

	if (!c->cum || !rootdir || !rootdir->not_null)
		return;

	pthread_mutex_lock(&c->cum->lock);
	list_ptr(&c->cum->rootdir, &lp);
	/* проверка наличия информации о директории в нотификациях */
	rp = list_find(&lp, hash);

	/* если rootdir ещё не в списке, то её нужно добавить */
	if (!rp) {
		rg = calloc(1, sizeof(struct rootdir_g));
		if (rg) {
			memcpy(&rg->rootdir, rootdir, sizeof(guid_t));
			rg->hash = hash;
			rg->checkpoint = checkpoint;
			rg->device_id = c->device_id;
			if (list_alloc(&c->cum->rootdir, hash, rg)) {
#if DEEPDEBUG
				char _rootdir[GUID_MAX + 1];
				guid2string(rootdir, PSIZE(_rootdir));
				xsyslog(LOG_DEBUG,
						"client[%"SEV_LOG"]"
						" add share rootdir '%s' checkpoint: %"PRIu64
						" (%s:%"PRIX64")",
						c->cev->serial,
						_rootdir, checkpoint, c->name, c->device_id);
#endif
			} else {
				xsyslog(LOG_WARNING,
						"client[%"SEV_LOG"] can't alloc root node",
						c->cev->serial);
			}
		}
	} else if ((rg = rp->data)->checkpoint < checkpoint) {
#if DEEPDEBUG
		{
			char _rootdir[GUID_MAX + 1];
			guid2string(rootdir, PSIZE(_rootdir));
			xsyslog(LOG_DEBUG,
					"client[%"SEV_LOG"]"
					" update share rootdir '%s' checkpoint: %"PRIu64
					" -> %"PRIu64" (%s:%"PRIX64")",
					c->cev->serial, _rootdir, rg->checkpoint, checkpoint,
					c->name, c->device_id);
		}
#endif
		rg->checkpoint = checkpoint;
		rg->device_id = c->device_id;

	}

	pthread_mutex_unlock(&c->cum->lock);
}

/* добавление rootdir в список активных rootdir или обновление чекпоинта */
static void
client_local_rootdir(struct client *c, guid_t *rootdir, uint64_t checkpoint)
{
	unsigned i;
	void *p;
	uint32_t hash = hash_pjw((void*)rootdir, sizeof(guid_t));
	/* поиск уже существующей записи */
	for (i = 0u; i < c->rootdir.c && c->rootdir.g[i].hash != hash; i++);
	/* если дошли до конца списка, то записи нет и нужно её создать */
	if (i == c->rootdir.c) {
		p = realloc(c->rootdir.g, (i + 1) * sizeof(struct rootdir_g));
		if (p) {
			c->rootdir.g = p;
			memset(&c->rootdir.g[i], 0u, sizeof(struct rootdir_g));
			memcpy(&c->rootdir.g[i].rootdir, rootdir, sizeof(guid_t));
			c->rootdir.g[i].hash = hash;
			c->rootdir.c++;
		} else {
			xsyslog(LOG_WARNING,
					"client[%"SEV_LOG"] can't add rootdir in list: %s",
					c->cev->serial, strerror(errno));
			return;
		}
	}

#if DEEPDEBUG
	{
		char _rootdir[GUID_MAX + 1];
		guid2string(&c->rootdir.g[i].rootdir, PSIZE(_rootdir));
		if (checkpoint != C_ROOTDIR_ACTIVATE) {
			xsyslog(LOG_DEBUG,
					"client[%"SEV_LOG"]"
					" change checkpoint (%s): %"PRIu64" -> %"PRIu64
					" (%s:%"PRIX64") [%u]",
					c->cev->serial, _rootdir,
					c->rootdir.g[i].checkpoint, checkpoint,
					c->name, c->device_id, i);
		} else {
			xsyslog(LOG_DEBUG,
					"client[%"SEV_LOG"]"
					" Set sync active (%s): at checkpoint %"PRIu64
					" (%s:%"PRIX64") [%u]",
					c->cev->serial, _rootdir,
					c->rootdir.g[i].checkpoint,
					c->name, c->device_id, i);
		}
	}
#endif
	if (checkpoint != C_ROOTDIR_ACTIVATE)
		c->rootdir.g[i].checkpoint = checkpoint;
	else
		c->rootdir.g[i].active = true;
}

/*
 * активация отправки лога клиенту
 * аргумент locked указывает предварительную
 * блокировку c->cum->lock
 */
static inline bool
_active_sync(struct client *c, guid_t *rootdir, uint64_t checkpoint,
		uint32_t session_id, uint64_t to_checkpoint)
{
	/* генерация списка последних обновлений директорий и файлов */
	struct result_send *rs;
#if DEEPDEBUG
	{
		char _rootdir[GUID_MAX + 1];
		guid2string(rootdir, PSIZE(_rootdir));
		xsyslog(LOG_DEBUG,
				"client[%"SEV_LOG"] activate sync from checkpoint=%"PRIu64
				" for device=%"PRIX64" in '%s'",
				c->cev->serial, c->checkpoint, c->device_id, _rootdir);
	}
#endif

	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		return false;
	}

	/* TODO: NULL для листинга rootdir,
	 * с указанием rootdir_guid - для файлов/дир
	 */
	if (!spq_f_logDirFile(c->name, rootdir, checkpoint, c->device_id,
				&rs->v.df)) {
		free(rs);
		return false;
	}

	/* если результат пустой,то нужно обновить текущий чекпоинт
	 * до последнего, что бы не шумел
	 */
	if (!rs->v.df.max && to_checkpoint && rootdir) {
		client_local_rootdir(c, rootdir, to_checkpoint);
	}

	if (rootdir)
		memcpy(&rs->rootdir, rootdir, sizeof(guid_t));

	rs->id = session_id;
	rs->type = RESULT_LOGDIRFILE;
	rs->free = (void(*)(void*))spq_f_logDirFile_free;
	rs->next = c->rout;
	c->rout = rs;

	return true;
}

#if DEEPDEBUG
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
#endif

bool
wait_id(struct client *c, struct listRoot *list, uint64_t id, wait_store_t *s)
{
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] list wait_id(%s, %"PRIu64")",
			c->cev->serial, list_name(c, list), id);
#endif

	return list_alloc(list, id, s);
}

wait_store_t*
query_id(struct client *c, struct listRoot *list, uint64_t id)
{
	struct listNode *ln;
	struct listPtr lp = {0};
	wait_store_t *data;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] list query_id(%s, %"PRIu64")",
			c->cev->serial, list_name(c, list), id);
#endif
	list_ptr(list, &lp);
	if (!(ln = list_find(&lp, id)))
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
	struct listPtr lp = {0};
	list_ptr(list, &lp);
	ln = list_find(&lp, id);
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] list touch_id(%s, %"PRIu64") -> %s",
			c->cev->serial, list_name(c, list), id, ln ? "found" : "not found");
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

uint32_t
generate_sid(struct client *c)
{
	return ++c->gensid;
}

#include "src/client/include/send.c"
#include "src/client/include/handle.c"
static struct handle handle[FEP__TYPE__t_max] =
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
	INVALID_P_HANDLE_S(FEP__TYPE__tOkWrite, "OkWrite", ok_write), /* 12 */
	TYPICAL_HANDLE_S(FEP__TYPE__tFileUpdate, "FileUpdate",
			file_update), /* 13 */
	TYPICAL_HANDLE_S(FEP__TYPE__tRenameChunk, "RenameChunk",
			rename_chunk), /* 14 */
	TYPICAL_HANDLE_S(FEP__TYPE__tQueryChunks, "QueryChunks",
			query_chunks), /* 15 */
	INVALID_P_HANDLE_S(FEP__TYPE__tResultChunk, "ResultChunk",
			result_chunk), /* 16 */
	TYPICAL_HANDLE_S(FEP__TYPE__tQueryRevisions, "QueryRevisions",
			query_revisions), /* 17 */
	INVALID_P_HANDLE_S(FEP__TYPE__tResultRevision, "ResultRevision",
			result_revision), /* 18 */
	TYPICAL_HANDLE_S(FEP__TYPE__tDirectoryUpdate, "DirectoryUpdate",
			directory_update), /* 19 */
	TYPICAL_HANDLE_S(FEP__TYPE__tFileMeta, "FileMeta", file_meta), /* 20 */
	TYPICAL_HANDLE_S(FEP__TYPE__tWantSync, "WantSync", want_sync), /* 21 */
	INVALID_P_HANDLE_S(FEP__TYPE__tOkUpdate, "OkUpdate", ok_update), /* 22 */
	INVALID_P_HANDLE_S(FEP__TYPE__tRootdirUpdate, "RootdirUpdate",
			rootdir_update), /* 23 */
	INVALID_P_HANDLE_S(FEP__TYPE__tOkWrite, "OkRead", ok_read), /* 24 */
	TYPICAL_HANDLE_S(FEP__TYPE__tChat, "Chat", chat), /* 25 */
	INVALID_P_HANDLE_S(FEP__TYPE__tState, "State", state), /* 26 */
	TYPICAL_HANDLE_S(FEP__TYPE__tQueryDevices, "QueryDevices", query_devices), /* 27 */
	INVALID_P_HANDLE_S(FEP__TYPE__tResultDevice, "ResultDevice", result_device), /* 28 */
	TYPICAL_HANDLE_S(FEP__TYPE__tStoreSave, "StoreSave", store_load), /* 29 */
	TYPICAL_HANDLE_S(FEP__TYPE__tStoreLoad, "StoreLoad", store_save), /* 30 */
	INVALID_P_HANDLE_S(FEP__TYPE__tStoreValue, "StoreValue", store_value), /* 31 */
	INVALID_P_HANDLE_S(FEP__TYPE__tSatisfied, "Satisfied", satisfied), /* 32 */
};

const char*
Fepstr(unsigned type)
{
	if (type >= sizeof(handle) / sizeof(struct handle))
		type = 0;
	return handle[type].text;
}

bool
send_message(struct sev_ctx *cev, unsigned type, void *msg)
{
	ssize_t lval;
	size_t len = 0u;
	unsigned char *buf;

	if (!type || type >= sizeof(handle) / sizeof(struct handle)) {
		xsyslog(LOG_ERR,
				"client[%"SEV_LOG"] invalid type %d in send_message(%s)",
				cev->serial, type, Fepstr(type));
		return false;
	}

	if (!handle[type].f_sizeof || !handle[type].f_pack) {
		xsyslog(LOG_ERR, "client[%"SEV_LOG"] type %d (%s)"
				"has no sizeof and pack field",
				cev->serial, type, Fepstr(type));

	}

	/* подготавливается заголовок */
	if (handle[type].f_sizeof)
		len = handle[type].f_sizeof(msg);
	buf = pack_header(type, &len);
	if (!buf) {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] memory fail in %s: %s",
				cev->serial, Fepstr(type), strerror(errno));
		return false;
	}

#if DEEPDEBUG
	xsyslog(LOG_DEBUG,
			"client[%"SEV_LOG"] transmit header[type: %s (%u), len: %"PRIuPTR"]",
			cev->serial, Fepstr(type), type, len);
#endif
	/* упаковывается сообщение */
	handle[type].f_pack(msg, &buf[HEADER_OFFSET]);
	if ((lval = sev_send(cev, buf, len)) != len) {
		xsyslog(LOG_WARNING,
				"client[%"SEV_LOG"] send fail in %s",
				cev->serial, Fepstr(type));
	}
	free(buf);

	{
		char _header[96] = {0};
		snprintf(_header, sizeof(_header),
				"client[%"SEV_LOG"] TX %"PRIdPTR" >> ",
				cev->serial, lval);
		packet2syslog(_header, type, msg);
	}

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
		xsyslog(LOG_DEBUG,
				"header[type: %s (%u), len: %lu]: "
				"%02x %02x %02x %02x %02x %02x",
				Fepstr(type), type, *len,
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
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
			xsyslog(LOG_DEBUG,
					"client[%"SEV_LOG"] got header[type: %s (%u), len: %u]: "
					"%02x %02x %02x %02x %02x %02x "
					"(in %"PRIuPTR" bytes)",
					c->cev->serial, Fepstr(c->h_type), c->h_type, c->h_len,
					buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
					size);
#endif
			/* бесполезная проверка на длину пакета */
			if (c->h_len > 1 << 24 || c->h_len == 0) {
				xsyslog(LOG_WARNING,
						"client[%"SEV_LOG"] header[type: %s (%u), len: %u]: "
						"length can't be great then %d and equal zero",
						c->cev->serial, Fepstr(c->h_type), c->h_type, c->h_len,
						1 << 24);
				c->h_type = 0u;
				return HEADER_INVALID;
			}
			/* проверка на тип */
			if (sizeof(handle) / sizeof(struct handle) <= c->h_type ||
					c->h_type == 0u) {
				xsyslog(LOG_WARNING,
						"client[%"SEV_LOG"] header[type: %s (%u), len: %u]: "
						"invalid type",
						c->cev->serial, Fepstr(c->h_type), c->h_type, c->h_len);
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
			xsyslog(LOG_INFO, "client[%"SEV_LOG"] header[type: %s (%u), len: %u]: "
					"message has no handle",
					c->cev->serial, Fepstr(c->h_type), c->h_type, c->h_len);
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
					/* передача пакета обработчику */
					/* TODO: печать сообщения в лог */
					{
						char _header[96] = {0};
						snprintf(_header, sizeof(_header),
								"client[%"SEV_LOG"] RX %"PRIu32" << ",
								c->cev->serial, c->h_len);
						packet2syslog(_header, c->h_type, msg);
					}
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
					char _errormsg[1024];
					snprintf(_errormsg, sizeof(_errormsg),
							"malformed message type %s (%u), len %u",
							Fepstr(c->h_type), c->h_type, c->h_len);
					xsyslog(LOG_INFO,
							"client[%"SEV_LOG"] %s",
							c->cev->serial, _errormsg);
					send_error(c, 0, _errormsg, -1);
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
 * дёргается при первом запуске треда и запросу от родителя
 */
bool
client_load(struct client *c)
{
	if (c->options.home) {
		free(c->options.home);
		c->options.home = NULL;
	}
	/* + sizeof('/') + sizeof('\0') */
	size_t len = strlen(c->name) + strlen(c->cev->pain->options.cache_dir) + 2;
	c->options.home = calloc(1, len + 1);
	if (!c->options.home)
		return false;
	snprintf(c->options.home, len, "%s/%s",
			c->cev->pain->options.cache_dir, c->name);
	if (mkdir(c->options.home, S_IRWXU) == -1 && errno != EEXIST) {
		xsyslog(LOG_WARNING,
				"client[%"SEV_LOG"] mkdir(%s) in client_load() fail: %s",
				c->cev->serial, c->options.home, strerror(errno));
		return false;
	}
	/* копирование конфигурации у родителя */
	c->options.send_buffer = 9660;

	c->options.unique_device_id = (bool)c->cev->pain->options.unique_device_id;

	c->options.limit_global_sql_queries =
		c->cev->pain->options.limit_global_sql_queries;
	c->options.limit_global_fd_queries =
		c->cev->pain->options.limit_global_fd_queries;
	c->options.limit_local_sql_queries =
		c->cev->pain->options.limit_local_sql_queries;
	c->options.limit_local_fd_queries =
		c->cev->pain->options.limit_local_fd_queries;
	/* FIXME: при массовой перезагрузке конфига можно опрокинуться */
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
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] remain %"PRIuPTR" mid",
				c->cev->serial, c->mid.count);
#endif
	} while (list_free_root(&c->mid, &mid_free));
	do {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] remain %"PRIuPTR" sid",
				c->cev->serial, c->sid.count);
#endif
	} while (list_free_root(&c->sid, (void(*)(void*))&sid_free));
	do {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] remain %"PRIuPTR" fid",
				c->cev->serial, c->fid.count);
#endif
	} while (list_free_root(&c->fid, (void(*)(void*))&fid_free));

	/* убираем себя из списка подключённых */
	if (c->cum) {
		struct listPtr _lp = {0};
		pthread_mutex_lock(&c->cum->lock);
		list_ptr(&c->cum->devices, &_lp);
		list_free_node(list_find(&_lp, c->device_id), NULL);
		pthread_mutex_unlock(&c->cum->lock);
	}

	while (cout_free(c));
	while (rout_free(c));

	/* отписываемся от рассылки сообщений */
	squeue_unsubscribe(&c->broadcast_c);

	/* ? */
	client_cum_free(c->cum);

	/* буфера */
	if (c->cout_buffer)
		free(c->cout_buffer);
	if (c->buffer)
		free(c->buffer);
	if (c->options.home)
		free(c->options.home);

	/* список активных rootdir */
	free(c->rootdir.g);

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
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] memory fail: %s",
				cev->serial, strerror(errno));
		return NULL;
	}
	c->count_error = 3;
	c->cev = cev;
	return c;
}

bool static inline
_client_iterate_result_logdf(struct client *c, struct logDirFile *ldf)
{
	char rootdir[GUID_MAX + 1];

	if (!spq_f_logDirFile_it(ldf)) {
		uint32_t sessid = c->rout->id;
		uint32_t packets = c->rout->packets;
		if (sessid != C_NOSESSID) {
			/* активируем отправку лога в этой рутдире */
			if (c->rout->rootdir.not_null)
				client_local_rootdir(c, &c->rout->rootdir, C_ROOTDIR_ACTIVATE);
			rout_free(c);
			return send_end(c, sessid, packets);
		} else {
			rout_free(c);
			return true;
		}
	}

	guid2string(&ldf->rootdir, rootdir, sizeof(rootdir));

	/* обновляем чекпоинт в рутдире */
	client_local_rootdir(c, &ldf->rootdir, ldf->checkpoint);

	/* отсылка данных */
	if (ldf->type == 'd') {
		Fep__DirectoryUpdate msg = FEP__DIRECTORY_UPDATE__INIT;
		char guid[GUID_MAX + 1];

		msg.id = generate_id(c);

		guid2string(&ldf->directory, guid, sizeof(guid));
		msg.rootdir_guid = rootdir;
		msg.directory_guid = guid;
		msg.checkpoint = ldf->checkpoint;

		if (*ldf->path)
			msg.path = ldf->path;

		msg.no = ldf->row;
		msg.max = ldf->max;

		msg.has_checkpoint = true;
		msg.has_no = true;
		msg.has_max = true;

		if (c->rout->id != C_NOSESSID) {
			msg.session_id = c->rout->id;
			msg.has_session_id = true;
		}

		c->rout->packets++;
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] log(%"PRIu64") "
				"DirectoryUpdate id = %"PRIu64
				" sid = %"PRIu32" #%"PRIu32"/%"PRIu32" -> root: %s, dir: %s",
				c->cev->serial, msg.checkpoint, msg.id, msg.session_id,
				msg.no, msg.max,
				rootdir, guid);
#endif
		return send_message(c->cev, FEP__TYPE__tDirectoryUpdate, &msg);
	} else if (ldf->type == 'f') {
		Fep__FileUpdate msg = FEP__FILE_UPDATE__INIT;

		char file[GUID_MAX + 1];
		char dir[GUID_MAX + 1];
		char rev[GUID_MAX + 1];

		msg.id = generate_id(c);
		msg.checkpoint = ldf->checkpoint;

		guid2string(&ldf->file, file, sizeof(file));
		guid2string(&ldf->directory, dir, sizeof(dir));
		guid2string(&ldf->revision, rev, sizeof(rev));

		msg.rootdir_guid = rootdir;
		msg.file_guid = file;

		if (*ldf->path)
			msg.enc_filename = ldf->path;
		if (ldf->directory.not_null)
			msg.directory_guid = dir;
		if (ldf->revision.not_null)
			msg.revision_guid = rev;

		msg.no = ldf->row;
		msg.max = ldf->max;

		msg.has_checkpoint = true;
		msg.has_no = true;
		msg.has_max = true;

		if (c->rout->id != C_NOSESSID) {
			msg.has_session_id = true;
			msg.session_id = c->rout->id;
		}

		c->rout->packets++;
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] log(%"PRIu64") FileUpdate id = %"PRIu64
				" sid = %"PRIu32" #%"PRIu32"/%"PRIu32" -> "
				"root: %s, dir: %s, file: %s, rev: %s",
				c->cev->serial, msg.checkpoint, msg.id, msg.session_id,
				msg.no, msg.max,
				rootdir, dir, file, rev);
#endif
		return send_message(c->cev, FEP__TYPE__tFileUpdate, &msg);
	} else if (ldf->type == 'r') {
		Fep__RootdirUpdate msg = FEP__ROOTDIR_UPDATE__INIT;

		msg.name = ldf->path;

		msg.id = generate_id(c);
		msg.checkpoint = ldf->checkpoint;
		msg.rootdir_guid = rootdir;

		msg.no = ldf->row;
		msg.max = ldf->max;

		msg.has_checkpoint = true;
		msg.has_no = true;
		msg.has_max = true;

		if (c->rout->id != C_NOSESSID) {
			msg.session_id = c->rout->id;
			msg.has_session_id = true;
		}

		/* обновление чекпоинта клиента для rootdir */
		c->checkpoint = ldf->checkpoint;

		c->rout->packets++;
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] log(%"PRIu64") "
				"RootdirUpdate id = %"PRIu64
				" sid = %"PRIu32" #%"PRIu32"/%"PRIu32" -> "
				"root: %s",
				c->cev->serial, msg.checkpoint, msg.id, msg.session_id,
				msg.no, msg.max, rootdir);
#endif
		return send_message(c->cev, FEP__TYPE__tRootdirUpdate, &msg);
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
		if (!spq_getChunks_it(&c->rout->v.c)) {
			/* итерироваться больше некуда, потому отправляем end и чистим
			 *
			 * если сообщение не отправится, то очередь подчиститься при
			 * общем выходе из треда
			 */
			return send_end(c, c->rout->id, c->rout->packets) &&
				(rout_free(c) || true);
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
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] <- ResultChunk id = %"PRIu64
				" sid = %"PRIu32" #%"PRIu32"/%"PRIu32,
				c->cev->serial, msg.id, msg.session_id,
				msg.chunk_no, msg.chunk_max);
#endif
		c->rout->packets++;
		return send_message(c->cev, FEP__TYPE__tResultChunk, &msg);
	} else if (c->rout->type == RESULT_REVISIONS) {
		Fep__ResultRevision msg = FEP__RESULT_REVISION__INIT;
		char guid[GUID_MAX + 1];
		char parent[GUID_MAX + 1];
		if (!spq_getRevisions_it(&c->rout->v.r)) {
			return send_end(c, c->rout->id, c->rout->packets) &&
				(rout_free(c) || true);
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
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] <- ResultRevision id = %"PRIu64
				" sid = %"PRIu32" #%"PRIu32"/%"PRIu32,
				c->cev->serial, msg.id, msg.session_id,
				msg.rev_no, msg.rev_max);
#endif
		c->rout->packets++;
		return send_message(c->cev, FEP__TYPE__tResultRevision, &msg);
	} else if (c->rout->type == RESULT_LOGDIRFILE) {
		return _client_iterate_result_logdf(c, &c->rout->v.df);
	} else if (c->rout->type == RESULT_DEVICES) {
		Fep__ResultDevice msg = FEP__RESULT_DEVICE__INIT;
		if (!spq_getDevices_it(&c->rout->v.d)) {
			return send_end(c, c->rout->id, c->rout->packets) &&
				(rout_free(c) || true);
		}

		msg.id = generate_id(c);
		msg.session_id = c->rout->id;
		msg.dev_no = c->rout->v.d.row;
		msg.dev_max = c->rout->v.d.max;

		msg.device_id = c->rout->v.d.device_id;
		msg.last_auth_time = (char*)c->rout->v.d.last_auth_time;
		/* TODO: проверять статус подключения/отключения
		 * по значениям в БД (добавить процедуру на отключения устройства)
		 */
		if (msg.device_id == c->device_id)
			msg.is_online = true;
		else
			msg.is_online = false;
		c->rout->packets++;
		return send_message(c->cev, FEP__TYPE__tResultDevice, &msg);
	} else {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] unknown rout type: %d\n",
				c->cev->serial, c->rout->type);
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
			xsyslog(LOG_INFO, "client[%"SEV_LOG"] realloc from "
					"%"PRIuPTR" to %"PRIuPTR": %s",
					c->cev->serial, c->cout_bfsz, c->options.send_buffer,
					strerror(errno));
			if (!c->cout_bfsz)
				return true;
		} else {
			c->cout_bfsz = c->options.send_buffer;
			c->cout_buffer = p;
		}
	}
	/* если прочитали всё что можно -- шлём End и деаллочимся */
	if (c->cout->sent == c->cout->size || c->cout->corrupt) {
		uint32_t _sessid = c->cout->session_id;
		uint32_t _packets = c->cout->packets;
		bool _corrupt = c->cout->corrupt;
		cout_free(c);
		if (!send_end(c, _sessid, _packets))
			return false;
		if (_corrupt)
			return send_error(c, 0, "Unknown error while read chunk", -1);
		else
			return true;
	} else {
		/* чтение файла */
		readsz = MIN(c->cout_bfsz, c->cout->size - c->cout->sent);
		transed = fcac_read(&c->cout->p, (uint8_t*)c->cout_buffer, readsz);
		if (transed <= 0) {
			if (transed == -1) {
				xsyslog(LOG_INFO, "client[%"SEV_LOG"] read error: %s",
						c->cev->serial, strerror(errno));
			} else {
				xsyslog(LOG_INFO, "client[%"SEV_LOG"] read wtf: %s",
						c->cev->serial, strerror(errno));
			}
			c->cout->corrupt = true;
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
			xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] <- xfer id = %"PRIu64
					" sid = %"PRIu32", offset=%"PRIu64", len = %"PRIu64,
					c->cev->serial, xfer_msg.id, xfer_msg.session_id,
					xfer_msg.offset, xfer_msg.data.len);
#endif
			c->cout->packets++;
			return send_message(c->cev, FEP__TYPE__txfer, &xfer_msg);
		}
	}
	return true;
}

static inline bool
_client_iterate_broadcast(struct client *c)
{
	struct chat_store *rs;
	/* если новых сообщений нет, то можно не волноваться */
	if (!squeue_has_new(&c->broadcast_c))
		return true;
	/* случается что из очереди выходит пустота */
	if (!(rs = squeue_query(&c->broadcast_c)))
		return true;
	/* наже же сообщение */
	if (c->cev->serial == rs->serial_from && !strcmp(c->name, rs->name_from))
		return true;
	/* или сообщение адресовалось не нам */
	if (rs->unicast && rs->device_id_to != c->device_id)
		return true;

	{
		Fep__Chat msg = FEP__CHAT__INIT;
		msg.id = generate_id(c);
		/* заполняем все поля, что бы клиент не запаниковал */
		msg.device_id_from = rs->device_id_from;
		msg.user_from = rs->name_from;
		if (rs->unicast) {
			msg.has_device_id_to = true;
			msg.device_id_to = c->device_id;
		}
		msg.user_to = c->name;
		msg.message.data = rs->buffer;
		msg.message.len = rs->len;

		return send_message(c->cev, FEP__TYPE__tChat, &msg);
	}

	return false;
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
			xsyslog(LOG_WARNING,
					"client[%"SEV_LOG"], grow from %lu to %lu fail: %s",
					c->cev->serial, c->bsz, c->bsz + BUFFER_ALLOC,
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
		xsyslog(LOG_WARNING,
				"client[%"SEV_LOG"] recv %d\n", c->cev->serial, lval);
		return false;
	} else if (lval == 0) {
		/* pass to cycle sanitize (check timeouts, etc) */
		return true;
	}
	c->blen += lval;
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
				xsyslog(LOG_WARNING, "client[%"SEV_LOG"] memmove() fail: %s",
						c->cev->serial, strerror(errno));
				return false;
			}
			c->blen -= lval;
		} else {
			c->blen = 0u;
		}
	} else if (lval == HEADER_INVALID) {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] mismatch protocol:"
				"%02x %02x %02x %02x %02x %02x", c->cev->serial,
				c->buffer[0], c->buffer[1], c->buffer[2],
				c->buffer[3], c->buffer[4], c->buffer[5]);
		return false;
	} else if (lval == HEADER_STOP) {
		/* словили остановку -- сообщаем в лог и выходим */
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] stop chat with "
				"header[type: %s (%u), len: %u]",
				c->cev->serial, Fepstr(c->h_type), c->h_type, c->h_len);
		return false;
	} else if (lval == HEADER_MORE) {
		/* если просит больше, нужно взять */
		if (!_client_iterate_read(c))
			return false;
	}
	if (c->count_error <= 0) {
		/* слишком много странного произошло в сессию, дропаем подключение */
		xsyslog(LOG_INFO, "client[%"SEV_LOG"] to many errors", c->cev->serial);
		return false;
	}
	return true;
}

void *
client_begin(struct sev_ctx *cev)
{
	struct client *c = client_alloc(cev);
	if (c) {
		c->cev->recv_timeout = 2;
	}
	return (void*)c;
}

void
client_end(struct sev_ctx *cev, void *p)
{
	client_destroy((struct client*)p);
}

static bool
send_hello(struct sev_ctx *cev, struct client *c)
{
	struct spq_InitialUser _ui;
	struct spq_hint _hint;
	uint8_t _guid_net[16];
	wait_store_t *s;
	Fep__ReqAuth reqAuth = FEP__REQ_AUTH__INIT;

	memset(&_ui, 0u, sizeof(_ui));
	memset(&_hint, 0u, sizeof(_hint));
	if (!spq_initial_user(&_ui, &_hint)) {
		if (*_hint.message) {
			send_error(c, 0, _hint.message, -1);
		} else send_error(c, 0, "Internal error 1199", -1);
		return false;
	}
	guid2net(&_ui.mark, _guid_net);
	reqAuth.id = generate_id(c);
	reqAuth.text = (char*)sev_version_string();
	reqAuth.epoch_guid.data = _guid_net;
	reqAuth.epoch_guid.len = sizeof(_guid_net);

	if (send_message(c->cev, FEP__TYPE__tReqAuth, &reqAuth)) {
		c->state++;

		if ((s = calloc(1, sizeof (wait_store_t))) != NULL)
			s->cb = (c_cb_t)c_auth_cb;

		if (!s || !wait_id(c, &c->mid, reqAuth.id, s)) {
			if (s) free(s);
			xsyslog(LOG_WARNING,
					"client[%"SEV_LOG"] can't set filter for id %"PRIu64,
					cev->serial, reqAuth.id);
		}
	} else {
		xsyslog(LOG_WARNING,
				"client[%"SEV_LOG"] no hello with memory fail: %s",
				cev->serial, strerror(errno));
		return false;
	}
	return true;
}

/* вовзращает положительный результат, если требуется прервать io */
bool
client_iterate(struct sev_ctx *cev, void *p)
{
	struct client *c = (struct client *)p;
	/* подчищаем, если вдруг последний раз запускаемся */

	if (!p) {
		xsyslog(LOG_WARNING,
				"client[%"SEV_LOG"] field for structure not passed",
				cev->serial);
		return true;
	}
	/* проверяем состояние буфера отправки,
	 * если отправить что-либо нет возможности
	 * то пропускаем цикл
	 */
	if (!sev_perhaps(cev, SEV_ACTION_WRITE)) {
		return true;
	}
	/* send helolo */
	if (c->state == CEV_FIRST) {
		if (!send_hello(cev, p))
			return false;
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
		/* и проверяем новые сообщения */
		if (!_client_iterate_broadcast(c))
			return false;
	}

	/* если обработка заголовка или чтение завалилось,
	 * то можно прерывать цикл
	 */
	if (!_client_iterate_handle(c)) {
		return false;
	}

	/*
	 * если есть файлы в очереди или необработанная дата
	 * то быстренько пропускаем таймауты
	 */
	if (c->cout || c->rout || c->blen || sev_perhaps(cev, SEV_ACTION_READ)) {
		sev_continue(cev);
	} else if (c->cum && c->status.log_active) {
		struct listNode *_ln;
		struct listPtr _lp = {0};
		struct rootdir_g *_rg;
		uint32_t hash;
		/* если нет никаких "срочных" действий, можно проверить сообщения
		 * от других тредов
		 *
		 * проверяем следующим образом: итерируемся по локальному списку,
		 * сравниваем со значением из глобального списка
		 *
		 * лочим сразу весь список, что бы не долбиться в кучу мелкил локов
		 */
		pthread_mutex_lock(&c->cum->lock);
		for (unsigned i = 0; i < c->rootdir.c; i++) {
			/* пропускаем не активные рутдиры */
			if (!c->rootdir.g[i].active)
				continue;
			hash = hash_pjw((void*)&c->rootdir.g[i].rootdir, sizeof(guid_t));
			list_ptr(&c->cum->rootdir, &_lp);
			/* если не найдена директория в разделяемом списке,
			 * то можно не волноваться, обновлений в ней не было
			 */
			if ((_ln = list_find(&_lp, hash)) != NULL) {
				_rg = _ln->data;
				/* когда чекпоинт в общей директории моложе
				 * локального, то пришло время обновиться
				 */
				if (_rg->checkpoint > c->rootdir.g[i].checkpoint) {
					_active_sync(c, &c->rootdir.g[i].rootdir,
							c->rootdir.g[i].checkpoint,
							C_NOSESSID,
							_rg->checkpoint);
				}
			}

		}
		pthread_mutex_unlock(&c->cum->lock);
	}
	/* проверка таймаутов */
	/* TODO */

	/* переходим на следующую итерацию */
	return true;
}

void
client_bus_input(struct sev_ctx *cev, void *p)
{
	/* TODO */
}

