/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client/include/handle.c
 */


/* не совсем очевидно что внутри может быть выход, но фиг с ним */
#define REQS_SK_ACQ(c, reqs, sk, type, msg) \
{\
	bool __w_q = client_reqs_acquire(c, reqs);\
	if (__w_q) {\
		/* if (sk) {\ */\
			if (!(__w_q = (sk = spq_vote(c->name, c->device_id)) != NULL)) {\
				client_reqs_release(c, reqs);\
			}\
		/* } \*/\
		/* кладём в очередь и выходим */\
	}\
	if (!__w_q) {\
		if (send_pending(c, msg->id)) {\
			return client_reqs_queue(c, reqs, type, msg);\
		} else {\
			return false;\
		}\
	}\
}

#define REQS_SK_REL(c, reqs, sk) \
{\
	if (sk) {\
		spq_devote(sk);\
		sk = NULL;\
	}\
	if (reqs) client_reqs_release(c, reqs);\
}

static inline struct wait_file *
_wait_file(struct client *c,
		guid_t *rootdir, guid_t *file, guid_t *revision)
{
	register bool exists = false;
	uint64_t hash = 0u;
	struct wait_store *ws = NULL;
	struct wait_file *wf = NULL;
	guid_t hash_s[2];

	const int wssize = sizeof(struct wait_store) + sizeof(struct wait_file);

	memcpy(hash_s, revision, sizeof(*revision));
	memcpy(hash_s + 1, file, sizeof(*file));
	/*memcpy(hash_s + 2, rootdir, sizeof(rootdir));*/

	hash = ((uint64_t)hash_pjw((char*)hash_s, sizeof(guid_t) * 2)) << 32;
	hash |= (uint64_t)hash_pjw((char*)revision, sizeof(*revision));

	if (!hash) {
		char _rootdir[GUID_MAX + 1] = {0};
		char _file[GUID_MAX + 1] = {0};
		guid2string(rootdir, PSIZE(_rootdir));
		guid2string(file, PSIZE(_file));
		xsyslog(LOG_WARNING,
				"client[%"SEV_LOG"] "
				"wait_file error: zero hash: rootdir(%s), file(%s)",
				c->cev->serial, _rootdir, _file);
		return NULL;
	}

	exists = ((ws = touch_id(c, &c->fid, hash)) != NULL);
	if (ws == NULL) {
		/* отсутствует запись, нужно создать */
		ws = calloc(1, wssize);

		if (!ws) {
			xsyslog(LOG_WARNING,
					"client[%"SEV_LOG"] "
					"wait_file error: calloc(%d) -> %s",
					c->cev->serial, wssize, strerror(errno));
			return NULL;
		}
		ws->data = ws + 1;
	}
	wf = ws->data;

	wf->id = hash;
	if (!wf->rootdir.not_null)
		memcpy(&wf->rootdir, rootdir, sizeof(*rootdir));
	if (!wf->file.not_null)
		memcpy(&wf->file, file, sizeof(*file));
	if (revision) {
		/* проверка на вшивость, не может загружаться
		 * больше одной ревизии к файлу
		 */
		if (!wf->revision.not_null) {
			memcpy(&wf->revision, revision, sizeof(*revision));
		} else if(memcmp(&wf->revision, revision, sizeof(*revision))) {
			/* если клиент пытается впихнуть новую ревизию,
			 * не закончив работу со старой
			 * FIXME: потенциальная проблема
			 * старая ревизия может "повиснуть" пока клиент не переподключится
			 */
			char _file[GUID_MAX + 1];
			char _rev_exists[GUID_MAX + 1];
			char _rev_overlay[GUID_MAX + 1];
			guid2string(file, PSIZE(_file));
			guid2string(&wf->revision, PSIZE(_rev_exists));
			guid2string(revision, PSIZE(_rev_overlay));
			xsyslog(LOG_WARNING, "client[%"SEV_LOG"] "
					"attempt to make chaos in file '%s': "
					"work with rev'%s', new rev'%s'",
					c->cev->serial, _file, _rev_exists, _rev_overlay);
			return NULL;
		}
	}

	/* добавляем в очередь, если нет ещё */
	if (!exists) {
		if (!wait_id(c, &c->fid, hash, ws)) {
			free(ws);
			return NULL;
		}
	}
	return wf;
}

/* подгрузка имеющейся информации о файле */
static bool
_file_load(struct client *c, struct spq_key *sk, struct wait_file *wf)
{
	struct spq_FileMeta fmeta;
	memset(&fmeta, 0u, sizeof(struct spq_FileMeta));

	if (spq_getFileMeta(sk,
				&wf->rootdir, &wf->file, &wf->revision,
				true, &fmeta, NULL)) {
		/*  в другом случае нужно заполнить поля в wait_file */
		if (!fmeta.empty) {
			wf->chunks = fmeta.chunks;
			wf->chunks_ok = fmeta.stored_chunks;

			if (fmeta.rev)
				string2guid(PSLEN(fmeta.rev), &wf->revision);
			if (fmeta.dir)
				string2guid(PSLEN(fmeta.dir), &wf->dir);
			if (fmeta.parent_rev)
				string2guid(PSLEN(fmeta.parent_rev), &wf->parent);

			if (fmeta.key_len)
				memcpy(wf->key, fmeta.key, fmeta.key_len);

			if (fmeta.enc_filename)
				strncpy(wf->enc_filename, fmeta.enc_filename, PATH_MAX);
			spq_getFileMeta_free(&fmeta);
		}
	}

	return true;
}

/* эту ерунду нужно вызывать в самом конце, после работы с wait_file,
 * т.е. при положительном результате wait_file будет освобождён
 * возвращает состояние линии
 */
static bool
_file_complete(struct spq_key *sk,
		struct client *c, struct wait_file *wf, bool prepare)
{
	uint64_t checkpoint = 0u;
	struct spq_hint hint;
	bool retval = true;
	bool _com = wf->complete;
	/* если файл не завершён, пытаемся сделать предварительную запись
	 * предварительная запись происходит в случае, если
	 * FileMeta приходит раньше чанков
	 *
	 * имеет смысл делать prepare только для chunks > 0
	 */
	if (!_com && wf->chunks && prepare) {
		size_t pkeysize = wf->key_len * 2 + 1;
		char *pkeyhex = alloca(pkeysize);
		memset(&hint, 0, sizeof(struct spq_hint));
		bin2hex(wf->key, wf->key_len, pkeyhex, pkeysize);
		spq_insert_revision(sk,
				&wf->rootdir, &wf->file, &wf->revision, &wf->parent,
				wf->enc_filename, pkeyhex, &wf->dir, wf->chunks, true,
				&_com,
				&hint);
		/* выход */
		if (hint.level == SPQ_ERR) {
			/* если произошла ошибка, то нужно выйти и убрать запись из
			 * очереди
			 */
			if (!wf->ref) {
				void *d;
				if ((d = query_id(c, &c->fid, wf->id)) != NULL)
					fid_free(d);
			}
			if (*hint.message)
				return send_error(c, wf->msg_id, hint.message, -1);
			return send_error(c, wf->msg_id, "Internal error 934", -1);
		}
	}
	/* если файл не завершён, то смысла продолжать нет */
	if (!_com) {
		return true;
	} else {
		/* кладём статус в струтуру */
		wf->complete = true;
	}
	/* файл собрался */
	{
		size_t pkeysize = wf->key_len * 2 + 1;
		char *pkeyhex = NULL;
		memset(&hint, 0, sizeof(struct spq_hint));
		if (wf->key_len) {
			pkeyhex = alloca(pkeysize);
			memset(pkeyhex, 0, pkeysize);
			bin2hex(wf->key, wf->key_len, pkeyhex, pkeysize);
		}
		/* нужно получить чекпоинт */
		checkpoint = spq_insert_revision(sk,
				&wf->rootdir, &wf->file, &wf->revision, &wf->parent,
				wf->enc_filename, pkeyhex, &wf->dir, wf->chunks, false,
				&_com,
				&hint);
	}
	if (!checkpoint) {
		if (*hint.message)
			retval = send_error(c, wf->msg_id, hint.message, -1);
		else
			retval = send_error(c, wf->msg_id, "Internal error 1785", -1);
	} else {
		/* рассылаем приглашение обновиться соседям */
		client_share_checkpoint(c, &wf->rootdir, checkpoint);

		if (*hint.message)
			retval = send_ok(c, wf->msg_id, checkpoint, hint.message);
		else
			retval = send_ok(c, wf->msg_id, checkpoint, NULL);
	}
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] file complete with ref=%u, "
				" chunks=%u/%u (chunks_fail=%u) and status=%s",
				c->cev->serial, wf->ref,
				wf->chunks_ok, wf->chunks, wf->chunks_fail,
				retval ? "Ok" : "Error");
#endif
	/* чистка */
	if (!wf->ref) {
		void *d;
		if ((d = query_id(c, &c->fid, wf->id)) != NULL)
			fid_free(d);
	}

	return retval;
}

bool
_handle_file_meta(struct client *c, unsigned type, Fep__FileMeta *msg)
{
	struct wait_file *wf;
	struct spq_FileMeta fmeta;

	guid_t rootdir;
	guid_t file;
	guid_t revision;

	char *enc_filename;
	uint8_t *key;
	size_t key_len;

	bool need_clear = false;

	struct spq_key *sk = NULL;

	string2guid(PSLEN(msg->rootdir_guid), &rootdir);
	string2guid(PSLEN(msg->file_guid), &file);
	string2guid(PSLEN(msg->revision_guid), &revision);

	memset(&fmeta, 0u, sizeof(struct spq_FileMeta));
	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	REQS_SK_ACQ(c, H_REQS_SQL, sk, type, msg);

	/* FIXME: ересь, прибраться после починки таблиц
	 * если в FileMeta не указаны enc_filename и key,
	 * нужно подгребсти их из таблицы
	 * по нормальному, нужно делать связь между таблицами по REFERENCES
	 */
	enc_filename = msg->enc_filename;
	key = msg->key.data;
	key_len = msg->key.len;
	if (!msg->enc_filename || !msg->key.len) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] "
				"FileMeta Prepare: enc_filename: \"%s\", "
				"file_guid: \"%s\", revision_guid: \"%s\", key_len: %"PRIuPTR,
				c->cev->serial,
				msg->enc_filename, msg->file_guid, msg->revision_guid,
				msg->key.len);
#endif
		if (!spq_getFileMeta(sk,
					&rootdir, &file, NULL, false, &fmeta, NULL)) {
			REQS_SK_REL(c, H_REQS_SQL, sk);
			return send_error(c, msg->id, "Internal error 1759", -1);
		}
		if (fmeta.empty) {
			REQS_SK_REL(c, H_REQS_SQL, sk);
			return send_error(c, msg->id, "no origin file meta in db", -1);
		}
		need_clear = true;
		if (!enc_filename) {
			enc_filename = fmeta.enc_filename;
		}
		if (!key_len) {
			key = fmeta.key;
			key_len  = fmeta.key_len;
		}
	}

	wf = _wait_file(c, &rootdir, &file, &revision);
	if (!wf) {
		spq_getFileMeta_free(&fmeta);
		REQS_SK_REL(c, H_REQS_SQL, sk);
		return send_error(c, msg->id, "Internal error 1860", -1);
	}

	/* заполнение оставшихся полей */
	if (!wf->msg_id)
		wf->msg_id = msg->id;

	if (!wf->parent.not_null && msg->parent_revision_guid)
		string2guid(PSLEN(msg->parent_revision_guid), &wf->parent);
	if (!wf->dir.not_null)
		string2guid(PSLEN(msg->directory_guid), &wf->dir);
	/* вообще их обрезать нельзя и нужно выдавать ошибку типа
	 * strlen(enc_filename) > PATH_MAX
	 * TODO: добавить обработку размера ключа и имени файла
	 */
	strncpy(wf->enc_filename, enc_filename,
			MIN(PATH_MAX, strlen(enc_filename)));
	memcpy(wf->key, key, key_len);
	wf->key_len = key_len;

	wf->chunks = msg->chunks;

	if (need_clear)
		spq_getFileMeta_free(&fmeta);
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] FileMeta: enc_filename: \"%s\", "
			"file_guid: \"%s\", revision_guid: \"%s\", key_len: %"PRIuPTR,
			c->cev->serial,
			enc_filename, msg->file_guid, msg->revision_guid, key_len);
#endif
	/* если чанков нет, то собирать нечего, потому сразу выставляем
	 * флаг готовности
	 */
	if (!wf->chunks) {
		wf->complete = true;
	}
	{
		bool _r = _file_complete(sk, c, wf, true);
		REQS_SK_REL(c, H_REQS_SQL, sk);
		return _r;
	}
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

bool
_handle_end(struct client *c, unsigned type, Fep__End *end)
{
	struct wait_store *ws;
	struct wait_xfer *wx;
	struct wait_file *wf;
	char chunk_hash[HASHHEX_MAX + 1];
	char errmsg[1024] = {0};
	bool _com = false;
	struct spq_key *sk = NULL;


	ws = query_id(c, &c->sid, end->session_id);
	if (!ws) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] End not found for id %"PRIu32,
				c->cev->serial, end->session_id);
#endif
		return send_error(c, end->id, "Unexpected End message", -1);
	}
	if (!(wx = ws->data) || !(wf = wx->wf)) {
		snprintf(errmsg, sizeof(errmsg), "Internal error 1928 wx=%c, wf=%c",
				wx ? 'y' : 'n', wx ? 'y' : 'n');
		sid_free(ws->data);
		return send_error(c, end->id, "Internal error 1928", -1);
	}
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] close fd#%"PRIu64", id %"PRIu32" "
			"file meta hash: %"PRIu64,
			c->cev->serial, wx->p.id, end->session_id, wf->id);
#endif
	/* размеры не совпали */
	if (wx->filling != wx->size) {
		snprintf(errmsg, sizeof(errmsg),
				"Infernal sizes. received: %"PRIu64", expected: %"PRIu64,
				wx->filling, wx->size);
	}

	REQS_SK_ACQ(c, H_REQS_SQL, sk, type, end);

	if (!*errmsg) {
		struct spq_hint hint;
		unsigned char sha256_o[SHA256_MAX];
		char sha256_hex[SHA256HEX_MAX + 1];
		memset(&hint, 0u, sizeof(struct spq_hint));
		sha256_finish(&wx->sha256, sha256_o);
		bin2hex(wx->hash, wx->hash_len, chunk_hash, sizeof(chunk_hash));
		if (wx->hash_len != SHA256_MAX
				|| memcmp(sha256_o, wx->hash, SHA256_MAX)) {
			bin2hex(sha256_o, SHA256_MAX, sha256_hex, sizeof(sha256_hex));
			snprintf(errmsg, sizeof(errmsg),
					"invalid chunk hash: %s, expect: %s",
					sha256_hex, chunk_hash);
		} else if (!fcac_set_ready(&wx->p)) {
			snprintf(errmsg, sizeof(errmsg), "Internal error 1137");
		/* чанк пришёл, теперь нужно попробовать обновить информацию в бд */
		} else if (!spq_insert_chunk(sk,
					&wf->rootdir, &wf->file, &wf->revision,
					&wx->chunk_guid, chunk_hash,
					wx->size, wx->offset, "xxx", &_com, &hint)) {
			/* запись чанка не удалась */
			if (*hint.message)
				snprintf(errmsg, sizeof(errmsg), hint.message);
			else
				snprintf(errmsg, sizeof(errmsg), "Internal error 2023");
		}
	}

	/* если собралась ревизия, то нужно пометить */
	if (_com) {
		wf->complete = true;
	}

	sid_free(ws);
	if (!*errmsg) {
		/* нет смысла пытаться отправить "Ok" клиенту, если
		 * соеденение отвалилось при отправке OkUpdate
		 */
		{
			bool _r = _file_complete(sk, c, wf, false);
			REQS_SK_REL(c, H_REQS_SQL, sk);
			if (!_r)
				return false;
		}
		return send_ok(c, end->id, C_OK_SIMPLE, NULL);
	} else {
		/* чанк не нужен, клиент перетащит его заного */
		return send_error(c, end->id, errmsg, -1);
	}
}

bool
_handle_ping(struct client *c, unsigned type, Fep__Ping *ping)
{
	Fep__Pong pong = FEP__PONG__INIT;
	struct timeval tv;

	if (gettimeofday(&tv, NULL) == -1) {
		xsyslog(LOG_WARNING, "client[%"SEV_LOG"] gettimeofday() fail in pong: %s",
				c->cev->serial, strerror(errno));
		return false;
	}

	pong.id = ping->id;
	pong.sec = ping->sec;
	pong.usec = ping->usec;
	pong.peer_sec = tv.tv_sec;
	pong.peer_usec = tv.tv_usec;

	if (!c->timed) {
		if (ping->sec > tv.tv_sec + 300) {
			if (ping->usec < tv.tv_usec) {
				ping->sec--;
				ping->usec += 1000u;
			}
			ping->sec = ping->sec - tv.tv_sec;
			ping->usec = ping->usec - tv.tv_usec;
			xsyslog(LOG_INFO,
					"client[%"SEV_LOG"] client lives in far future: "
					"%"PRIu64".%06"PRIu32"s offset",
					c->cev->serial, ping->sec, ping->usec);
		} else if (ping->sec < tv.tv_sec - 300) {
			if (ping->usec > tv.tv_usec) {
				ping->sec++;
				ping->usec = ping->usec % 1000u;
			}
			ping->sec = tv.tv_sec - ping->sec;
			ping->usec = tv.tv_usec - ping->sec;
			xsyslog(LOG_INFO,
					"client[%"SEV_LOG"] client living in the past: "
					"%"PRIu64".%06"PRIu32"s offset",
					c->cev->serial, ping->sec, ping->usec);
		}
		send_ping(c);
		c->timed = true;
	}

	return send_message(c->cev, FEP__TYPE__tPong, &pong);
}

bool
_handle_want_sync(struct client *c, unsigned type, Fep__WantSync *msg)
{
	guid_t rootdir;
	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	/* после запроса состояния можно и запустить экспресс-нотификацию
	 * если этого не было раньше (например, в auth_cb)
	 */
	if (!c->cum) {
		c->cum = client_cum_create(hash_pjw(c->name, strlen(c->name)));
	}

	if (msg->rootdir_guid) {
		string2guid(PSLEN(msg->rootdir_guid), &rootdir);
		/* добавление rootdir в список клиента */
		client_local_rootdir(c, &rootdir, msg->checkpoint);
	} else {
		string2guid(NULL, 0, &rootdir);
	}

	/* освобождать ресурсы нужно в конце итерации */
	if (!client_reqs_acquire(c, H_REQS_SQL)) {
		if (!send_pending(c, msg->id))
			return false;
		return client_reqs_queue(c, H_REQS_SQL, type, msg);
	}

	/* FIXME: костыль на то, что внутри _active_sync
	 * тоже происходит захват нужных ресурсов
	 */
	client_reqs_release(c, H_REQS_SQL);

	if (!_active_sync(c, rootdir.not_null ? &rootdir : NULL, msg->checkpoint,
				msg->session_id, 0lu)) {
		return send_error(c, msg->id, "Internal error 1653", -1);
	}
	c->status.log_active = true;
	return send_ok(c, msg->id, C_OK_SIMPLE, NULL);
}

struct _bus_data {
	struct main *pain;
	uint64_t msgid;
	/* указатель на клиента, использовать прямую ссылку
	 * нельзя, потому что клиент может откинуться до того
	 * как прийдёт ответ
	 */
	size_t client_serial;
};

static inline bool
_read_ask__from_driver(struct client *c, Fep__ReadAsk *msg,
		struct getChunkInfo *ci)
{
	char buf[96] = {0};
	/*
	 * 1. проверяем наличие в кеше
	 * 2. пишем в канал что хотим информацию по файлу
	 * 3. ставим в локальную очередь на ожидание ответа
	 */
	bool r = true;
	struct almsg_parser alm;
	/*
	 * альтернативный способ: глобальный массив,
	 * синхронизация не нужна, т.к. всё выполняется синхронно в libev
	 */
	struct _bus_data *bd = calloc(1, sizeof(struct _bus_data));
	almsg_init(&alm);

	/* сразу освобождаем ресурс FD, т.к. его фактический захват нужно
	 * проводить после получения ответа от драйвера
	 */
	client_reqs_release(c, H_REQS_FD);

	bd->pain = c->cev->pain;
	bd->msgid = msg->id;
	bd->client_serial = c->cev->serial;

	snprintf(buf, sizeof(buf), "%"PRIu64, ci->group);

	almsg_insert(&alm, PSLEN_S("action"), PSLEN_S("query-driver"));
	/*almsg_insert(&alm, PSLEN_S("query"), PSLEN_S("read-data"));*/
	almsg_append(&alm, PSLEN_S("owner"), PSLEN(c->name));
	almsg_append(&alm, PSLEN_S("address"), PSLEN(ci->address));
	almsg_append(&alm, PSLEN_S("driver"), PSLEN(ci->driver));

	r = bus_query(c->cev, &alm, bd);
	almsg_destroy(&alm);
	return r;
}

static inline bool
_read_ask__from_cache(struct client *c, Fep__ReadAsk *msg,
		struct getChunkInfo *ci)
{
	/*
	 * 1. открываем файл
	 * 2. генерируем структуру
	 * 3. уходим
	 */
	struct chunk_send *chs;

	if (!(chs = calloc(1, sizeof(struct chunk_send)))) {
		client_reqs_release(c, H_REQS_FD);
		return send_error(c, msg->id, "Internal error 121", -1);
	}

	if (!fcac_open(&c->cev->pain->fcac, ci->group, &chs->p, 0)) {
		free(chs);
		client_reqs_release(c, H_REQS_FD);
		return send_error(c, msg->id, "Internal error 1149", -1);
	}

	chs->session_id = generate_sid(c);
	chs->size = ci->size;
	chs->next = c->cout;
	chs->chunk_size = chs->size;
	chs->file_offset = ci->offset;
	chs->reqs = H_REQS_FD;
	c->cout = chs;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] -> ReadAsk id = %"PRIu64,
			c->cev->serial, msg->id);
#endif
	{
		Fep__OkRead rdok = FEP__OK_READ__INIT;
		rdok.id = msg->id;
		rdok.session_id = chs->session_id;
		rdok.size = ci->size;
		rdok.offset = ci->offset;

		return send_message(c->cev, FEP__TYPE__tOkRead, &rdok);
	}
}

bool
_handle_read_ask(struct client *c, unsigned type, Fep__ReadAsk *msg)
{
	/*
	 * 1. Отдача через драйвер
	 * 1.1. получение информации из БД
	 * 1.2. обращение к драйверу, если присутсвует
	 * 1.3. ожидание ответа
	 * 1.4. (при затянувшемся ожидании ответ Pendgin клиенту)
	 * 1.5. ответ клиенту
	 * 2. Отдача из входящего кэша
	 * 2.1. получение информации из БД
	 * 2.2. обращение к файловой системе
	 * 2.3. ответ клиенту
	 */
	guid_t rootdir;
	guid_t file;
	guid_t chunk;

	struct spq_key *sk = NULL;
	struct spq_hint hint;
	struct getChunkInfo cnfo;

	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);
	string2guid(msg->chunk_guid, strlen(msg->chunk_guid), &chunk);
	memset(&hint, 0, sizeof(struct spq_hint));
	memset(&cnfo, 0, sizeof(struct getChunkInfo));

	REQS_SK_ACQ(c, H_REQS_SQL | H_REQS_FD, sk, type, msg);

	if (!spq_getChunkInfo(sk, &rootdir, &file, &chunk,
				&cnfo, &hint)) {
		REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
		if (*hint.message)
			return send_error(c, msg->id, hint.message, -1);
		return send_error(c, msg->id, "Internal error 120", -1);
	}

	if (!cnfo.address || !*cnfo.address) {
		spq_getChunkInfo_free(&cnfo);
		REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
		return send_error(c, msg->id, "chunk has null address", -1);
	}

	{
		bool _r;
		if (!cnfo.driver) {
			/* чтение из кэша */
			_r =  _read_ask__from_cache(c, msg, &cnfo);
		} else {
			/* запрос через драйвер */
			_r = _read_ask__from_driver(c, msg, &cnfo);
		}

		spq_getChunkInfo_free(&cnfo);
		if (!_r) {
			REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
		} else {
			/* TODO: не понятно что освобождать (только SQL или SQL|FD) при
			 * запросе через драйвер.
			 * Фактически ресурс не нужен до получения файла
			 * + непонятно когда он освободится, ведь скачивание может
			 * продолжаться слишком долго
			 */
			REQS_SK_REL(c, H_REQS_SQL, sk);
		}
		return _r;
	}
}

bool
_handle_write_ask(struct client *c, unsigned type, Fep__WriteAsk *msg)
{
	/* FIXME: говнище, переработать */
	char *errmsg = NULL;
	struct wait_store *ws;
	struct wait_xfer *wx;

	guid_t rootdir;
	guid_t file;
	guid_t chunk;
	guid_t revision;

	struct spq_key *sk = NULL;
	struct getChunkInfo _ci = {0};
	struct spq_hint _hint;
	char chunk_hash[PATH_MAX];

	uint64_t chunk_id = 0;
	struct wait_file *wf;
	Fep__OkWrite wrok = FEP__OK_WRITE__INIT;

	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	if (msg->size == 0u) {
		errmsg = "Zero-size chunk? PFF";
	}

	if (!*msg->rootdir_guid || !*msg->file_guid\
			|| !*msg->chunk_guid) {
		errmsg = "Chunk without guids? No way";
	}

	if (!string2guid(PSLEN(msg->rootdir_guid), &rootdir))
		errmsg = "illegal guid: rootdir_guid";
	if (!string2guid(PSLEN(msg->file_guid), &file))
		errmsg = "illegal guid: file_guid";
	if (!string2guid(PSLEN(msg->chunk_guid), &chunk))
		errmsg = "illegal guid: chunk_guid";
	if (!string2guid(PSLEN(msg->revision_guid), &revision))
		errmsg = "illegal guid: revision_guid";
	if (!msg->chunk_hash.len)
		errmsg = "Chunk hash is empty";

	if (errmsg)
		return send_error(c, msg->id, errmsg, -1);

	/* захват ресурса, освобождение должно происходить в
	 */
	REQS_SK_ACQ(c, H_REQS_SQL | H_REQS_FD, sk, type, msg);

	{
		/* проверка доступного пространства
		 * FIXME: слишком жирно, нужно избавиться от запроса к БД
		 * и просчитывать его самостоятельно (запрос к базе можно делать
		 * один раз при подключении, остальное время выщитывать по ивентам)
		 */
		struct spq_QuotaInfo _qi;
		struct spq_hint _hint;
		memset(&_qi, 0u, sizeof(struct spq_QuotaInfo));
		memset(&_hint, 0u, sizeof(struct spq_hint));
		spq_get_quota(sk, &rootdir, &_qi, &_hint);
		if (_hint.level == SPQ_ERR) {
			REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
			if (*_hint.message)
				return send_error(c, msg->id, _hint.message, -1);
			return send_error(c, msg->id, "Internal error 977", -1);
		}
		if (_qi.quota) {
			if (_qi.used + msg->size > _qi.quota) {
				REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
				return send_error(c, msg->id, "No enough space", -1);
			}
		}
	}

	bin2hex(msg->chunk_hash.data, msg->chunk_hash.len, PSIZE(chunk_hash));
	/* получение id чанка и запись в кеш */
	memset(&_ci, 0u, sizeof(_ci));
	memset(&_hint, 0u, sizeof(_hint));

	if (!spq_chunk_prepare(sk, &rootdir,
			chunk_hash, msg->size, &_ci, &_hint)) {
		REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
		if (*_hint.message)
			return send_error(c, msg->id, _hint.message, -1);
		return send_error(c, msg->id, "Internal error 1175", -1);
	}

	/* структура файла нам нужна в любом случае */
	if (!(wf = _wait_file(c, &rootdir, &file, &revision))) {
		REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
		return send_error(c, msg->id, "Internal error 1321", -1);
	}

	if (_ci.address || _ci.driver) {
		struct spq_hint hint;
		bool _com = false;
		memset(&hint, 0u, sizeof(hint));
		/*
		 * если _prepare() вернул адрес и драйвер, то отослать satisfied
		 */

		if (!spq_insert_chunk(sk,
					&rootdir, &file, &revision, &chunk,
					chunk_hash, msg->size, msg->offset, _ci.address,
					&_com, &hint)) {
			REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
			spq_getChunkInfo_free(&_ci);
			if (*hint.message)
				return send_error(c, msg->id, hint.message, -1);
			else
				return send_error(c, msg->id, "Internal error 1240", -1);
		}
		spq_getChunkInfo_free(&_ci);
		/* если сборка завершена, то выставляем соотвествующий флаг */
		if (_com) {
			register bool ___ra = true;
			wf->complete = true;
			/* и вызываем сценарий финализации */
			___ra = _file_complete(sk, c, wf, false);
			REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
			if (!___ra)
				return false;
		} else {
			/* освобождаем оба ресурса, т.к. End не прийдёт */
			REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
		}
		return send_satisfied(c, msg->id);
	}
	chunk_id = _ci.group;
	spq_getChunkInfo_free(&_ci);

	{
		/* в этом блоке структура wx только настраивается,
			упаковка происходит дальше */
		ws = calloc(1, sizeof(struct wait_store) + sizeof(struct wait_xfer));
		if (!ws) {
			errmsg = "Internal error 1315";
		} else {
			/* лёгкого вида костыль, что бы не потеряться в *_free */
			ws->c = c;
			ws->reqs = H_REQS_FD;
			wx = (ws->data = ws + 1);
			/* открытие/создание файла */
			wx->size = msg->size;
			if (chunk_id == 0) {
				xsyslog(LOG_WARNING, "XXX");
			}
			if (!fcac_open(&c->cev->pain->fcac,
						chunk_id, &wx->p, FCAC_PREFERRED_FILE)) {
				errmsg = "Internal error: cache not available";
			}

			if (fcac_is_ready(&wx->p) != FCAC_NO_READY) {
				errmsg = "Cache damaged";
			}

			string2guid(msg->chunk_guid, strlen(msg->chunk_guid),
					&wx->chunk_guid);
			/* ссылаемся на wait_file и увеличиваем счётчик */
			wx->wf = wf;
			wx->wf->ref++;
			wx->hash_len = msg->chunk_hash.len;
			memcpy(wx->hash, (void*)msg->chunk_hash.data, msg->chunk_hash.len);
			wx->offset = msg->offset;
		}
	}

	if (errmsg) {
		fcac_close(&wx->p);
		if (ws)
			free(ws);
		xsyslog(LOG_WARNING,
				"client[%"SEV_LOG"] open(%"PRIu64") failed: %s",
				c->cev->serial, chunk_id, errmsg);
		/* ошибка, End не прийдёт */
		REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
		return send_error(c, msg->id, errmsg, -1);
	}
	/* инициализируем polarssl */
#if !POLARSSL_LESS_138
	sha256_init(&wx->sha256);
#endif
	sha256_starts(&wx->sha256, 0);

	/* пакуем структуры */
	wrok.id = msg->id;
	wrok.session_id = generate_sid(c);

#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] fd#%"PRIu64" for [%"PRIu32"]",
			c->cev->serial, wx->p.id, wrok.session_id);
#endif
	/* добавление в очередь на ожидание */
	if (!wait_id(c, &c->sid, wrok.session_id, ws)) {
		fcac_close(&wx->p);
		free(ws);
		REQS_SK_REL(c, H_REQS_SQL | H_REQS_FD, sk);
		return send_error(c, msg->id, "Internal error 1358", -1);
	}

	/* если запрос завершился неудачно, то файла, вероятнее всего нет
	 * не помню зачем это нужно, какой-то костыль
	 */
	_file_load(c, sk, wf);

	/* в случае успеха освобождаем только ресурс SQL, но оставляем
	 * захваченным fd, его нужно освободить только после прихода End
	 */
	REQS_SK_REL(c, H_REQS_SQL, sk);
	return send_message(c->cev, FEP__TYPE__tOkWrite, &wrok);
}

bool
_handle_chat(struct client *c, unsigned type, Fep__Chat *msg)
{
	struct chat_store *rs;
	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	if (msg->user_to) {
		return send_error(c, msg->id, "send to user not allowed", -1);
	}

	/* если из подписчиков только один клиент */
	if (squeue_count_subscribers_c(&c->broadcast_c) == 1) {
		return send_error(c, msg->id, "No listeners", -1);
	}

	rs = calloc(1, sizeof(struct chat_store) + msg->message.len);
	if (!rs) {
		return send_error(c, msg->id, "Internal error 2230", -1);
	}

	/* копирование сообщения */
	rs->len = msg->message.len;
	memcpy(rs->buffer, msg->message.data, msg->message.len);

	/* копирование имени отправителя
	 * (в сообщениях в пределах одной учётки не нужен)
	 */
	strncpy(rs->name_from, c->name, C_NAMELEN);

	/* отметка что бы не было эха */
	rs->serial_from = c->cev->serial;
	/* и id устройства-отправителя */
	rs->device_id_from = c->device_id;

	if (msg->has_device_id_to) {
		rs->unicast = true;
		rs->device_id_to = msg->device_id_to;
	}

	if (!squeue_put(&c->broadcast_c, (void*)rs, free)) {
		free(rs);
		return send_error(c, msg->id, "No listeners", -1);
	} else {
		return send_ok(c, msg->id, C_OK_SIMPLE, NULL);
	}
}

/* переименование/перемещение или удаление файла */
bool
_handle_file_update(struct client *c, unsigned type, Fep__FileUpdate *msg)
{
	uint64_t checkpoint;
	guid_t rootdir;
	guid_t file;
	struct spq_hint hint;

	guid_t directory;
	char enc_filename[PATH_MAX];
	struct spq_key *sk = NULL;

	memset(enc_filename, 0u, PATH_MAX);
	if (msg->enc_filename) {
		register size_t _len = strlen(msg->enc_filename);
		if (_len >= PATH_MAX)
			return send_error(c, msg->id, "enc_filename too long", -1);
		strncpy(enc_filename, msg->enc_filename, _len);
	}

	REQS_SK_ACQ(c, H_REQS_SQL, sk, type, msg);

	string2guid(PSLEN(msg->rootdir_guid), &rootdir);
	string2guid(PSLEN(msg->file_guid), &file);
	string2guid(PSLEN(msg->directory_guid), &directory);

	memset(&hint, 0u, sizeof(struct spq_hint));
	checkpoint = spq_update_file(sk, &rootdir, &file,
			&directory, *enc_filename ? enc_filename : NULL, &hint);

	if (!checkpoint) {
		REQS_SK_REL(c, H_REQS_SQL, sk);
		if (*hint.message)
			return send_error(c, msg->id, hint.message, -1);
		return send_error(c, msg->id, "Internal error 1913", -1);
	}

	client_share_checkpoint(c, &rootdir, checkpoint);

	REQS_SK_REL(c, H_REQS_SQL, sk);

	return send_ok(c, msg->id, checkpoint, NULL);
}


bool
_handle_directory_update(struct client *c, unsigned type,
		Fep__DirectoryUpdate *msg)
{
	guid_t rootdir;
	guid_t directory;
	uint64_t checkpoint;
	struct spq_hint hint;
	struct spq_key *sk = NULL;

	string2guid(PSLEN(msg->rootdir_guid), &rootdir);
	string2guid(PSLEN(msg->directory_guid), &directory);

	REQS_SK_ACQ(c, H_REQS_SQL, sk, type, msg);

	memset(&hint, 0u, sizeof(struct spq_hint));
	checkpoint = spq_directory_create(sk,
			&rootdir, &directory, msg->path, &hint);

	REQS_SK_REL(c, H_REQS_SQL, sk);

	if (!checkpoint) {
		if (*hint.message) {
			return send_error(c, msg->id, hint.message, -1);
		} else
			return send_error(c, msg->id, "Internal error 1839", -1);
	}

	client_share_checkpoint(c, &rootdir, checkpoint);

	if (*hint.message)
		return send_ok(c, msg->id, checkpoint, hint.message);
	return send_ok(c, msg->id, checkpoint, NULL);
}

bool
_handle_query_revisions(struct client *c, unsigned type,
		Fep__QueryRevisions *msg)
{
	struct getRevisions gr;
	guid_t rootdir;
	guid_t file;

	struct result_send *rs;
	struct spq_key *sk = NULL;

	/* конвертация типов */
	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);

	memset(&gr, 0, sizeof(struct getRevisions));

	/* освобождать ресурсы нужно в конце итерации (rout_free) */
	REQS_SK_ACQ(c, H_REQS_SQL, sk, type, msg);

	if (!spq_getRevisions(sk,
				&rootdir, &file, msg->depth, &gr)) {
		REQS_SK_REL(c, H_REQS_SQL, sk);
		return send_error(c, msg->id, "Internal error 100", -1);
	}

	/* выделяем память под список */
	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_getRevisions_free(&gr);
		REQS_SK_REL(c, H_REQS_SQL, sk);
		return send_error(c, msg->id, "Internal error 111", -1);
	}
	memcpy(&rs->v.r, &gr, sizeof(struct getRevisions));
	rs->sk = sk;
	rs->reqs = H_REQS_SQL;
	rs->id = msg->session_id;
	rs->type = RESULT_REVISIONS;
	rs->free = (void(*)(void*))spq_getRevisions_free;
	rs->next = c->rout;
	c->rout = rs;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] -> QueryRevisions id = %"PRIu64
			" sid = %"PRIu32,
			c->cev->serial, msg->id, msg->session_id);
#endif
	return send_ok(c, msg->id, C_OK_SIMPLE, NULL);
}

bool
_handle_query_devices(struct client *c, unsigned type, Fep__QueryDevices *msg)
{
	struct result_send *rs;
	struct spq_hint hint;

	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		xsyslog(LOG_WARNING, "_handle_query_devices error: %s",
				strerror(errno));
		return send_error(c, msg->id, "Internal error 995", -1);
	}

	/* освобождается в client_iterate */
	if (!client_reqs_acquire(c, H_REQS_SQL)) {
		if (!send_pending(c, msg->id))
			return false;
		return client_reqs_queue(c, H_REQS_SQL, type, msg);
	}

	memset(&hint, 0u, sizeof(hint));
	/* сейчас это один из немногих вызовов, которые не требуют spq_key */
	if (!spq_getDevices(c->name, c->device_id, &rs->v.d, &hint)) {
		free(rs);
		client_reqs_release(c, H_REQS_SQL);
		return send_error(c, msg->id, "Internal error 1010", -1);
	}

	/* освобождение SQL произойдёт в rout_free() */
	rs->reqs = H_REQS_SQL;
	rs->id = msg->session_id;
	rs->type = RESULT_DEVICES;
	rs->free = (void(*)(void*))spq_getDevices_free;
	rs->next = c->rout;
	c->rout = rs;

#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] -> QueryDevices id = %"PRIu64
			" sid = %"PRIu32,
			c->cev->serial, msg->id, msg->session_id);
#endif
	return send_ok(c, msg->id, C_OK_SIMPLE, NULL);
}

bool
_handle_query_chunks(struct client *c, unsigned type, Fep__QueryChunks *msg)
{
	Fep__FileMeta meta = FEP__FILE_META__INIT;
	struct getChunks gc;
	guid_t rootdir;
	guid_t file;
	guid_t revision;

	struct result_send *rs;
	struct spq_FileMeta fmeta;

	struct spq_key *sk = NULL;

	/* конвертим типы */
	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);
	string2guid(msg->revision_guid, strlen(msg->revision_guid), &revision);

	memset(&gc, 0, sizeof(struct getChunks));

	REQS_SK_ACQ(c, H_REQS_SQL, sk, type, msg);

	if (!spq_getChunks(sk,
				&rootdir, &file, &revision, &gc)) {
		REQS_SK_REL(c, H_REQS_SQL, sk);
		return send_error(c, msg->id, "Internal error 110", -1);
	}

	/* выделяем память под список */
	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_getChunks_free(&gc);
		REQS_SK_REL(c, H_REQS_SQL, sk);
		return send_error(c, msg->id, "Internal error 111", -1);
	}

	/* отправка подтверждения, что всё ок */
	{
		struct spq_hint _hint;
		memset(&fmeta, 0u, sizeof(struct spq_FileMeta));
		memset(&_hint, 0u, sizeof(struct spq_hint));
		if (!spq_getFileMeta(sk,
					&rootdir, &file, &revision, false, &fmeta, &_hint)) {
			free(rs);
			REQS_SK_REL(c, H_REQS_SQL, sk);
			if (*_hint.message)
				return send_error(c, msg->id, _hint.message, -1);
			return send_error(c, msg->id, "Internal error 112", -1);
		}
		if (fmeta.empty) {
			free(rs);
			REQS_SK_REL(c, H_REQS_SQL, sk);
			return send_error(c, msg->id, "Invalid file request", -1);
		}
	}
	meta.id = generate_id(c);

	meta.rootdir_guid = msg->rootdir_guid;
	meta.file_guid = msg->file_guid;
	meta.revision_guid = msg->revision_guid;
	meta.directory_guid = fmeta.dir;
	if (fmeta.parent_rev)
		meta.parent_revision_guid = fmeta.parent_rev;

	meta.chunks = fmeta.chunks;
	meta.enc_filename = fmeta.enc_filename;
	meta.has_key = true;
	meta.key.data = fmeta.key;
	meta.key.len = fmeta.key_len;

	/* заполнение списка, добавление в очередь */
	memcpy(&rs->v.c, &gc, sizeof(struct getChunks));
	rs->sk = sk;
	rs->reqs = H_REQS_SQL;
	rs->id = msg->session_id;
	rs->type = RESULT_CHUNKS;
	rs->free = (void(*)(void*))spq_getChunks_free;
	rs->next = c->rout;
	c->rout = rs;
	/* отправка сообщение, чистка результатов запроса, выход */
	{
		bool retval;
		retval = send_message(c->cev, FEP__TYPE__tFileMeta, &meta);
		spq_getFileMeta_free(&fmeta);
		return retval;
	}
}

bool
_handle_xfer(struct client *c, unsigned type, Fep__Xfer *xfer)
{
	/* делать захват ресурса (client_reqs_acquire()) не нужно
	 * т.к. он захватывается в write_ask
	 */
	struct wait_store *ws;
	struct wait_xfer *wx;
	char *errmsg = NULL;
	enum fcac_ready ready = 0;

	ws = touch_id(c, &c->sid, xfer->session_id);
	if (!ws) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] xfer not found for id %"PRIu32,
				c->cev->serial, xfer->session_id);
#endif
		return send_error(c, xfer->id, "Unexpected xfer message", -1);
	}
	wx = ws->data;

	/* FIXME: сойдёт и так, но всё же нужно слать Satisfied по WriteAsk */
	ready = fcac_is_ready(&wx->p);
	if (ready == FCAC_CLOSED) {
		errmsg = "Cache closed, try again";
	} else if (ready == FCAC_READY
			|| xfer->data.len + xfer->offset > wx->size) {
		errmsg = "Owerdose input data";
	} else if ((ready != FCAC_READY &&
		fcac_write(&wx->p, xfer->data.data, xfer->data.len) !=
			xfer->data.len)) {
		errmsg = "Write fail";
	} else {
		wx->filling += xfer->data.len;
		sha256_update(&wx->sha256, xfer->data.data, xfer->data.len);
		return true;
	}
#if DEEPDEBUG
	if (errmsg) {
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] got xfer fd#%"PRIu64" error: %s",
				c->cev->serial, wx->p.id, strerror(errno));
	} else {
		xsyslog(LOG_DEBUG,
				"client[%"SEV_LOG"] destroy xfer fd#%"PRIu64" because error",
				c->cev->serial, wx->p.id);
	}
#endif
	/* освобождение памяти в последнюю очередь,
	 * т.к. wx и ws выделяются в последнюю очередь
	 */
	if ((ws = query_id(c, &c->sid, xfer->session_id)) != NULL)
		sid_free(ws);
	return send_error(c, xfer->id, errmsg, -1);
}

bool
_handle_store_save(struct client *c, unsigned type, Fep__StoreSave *msg)
{
	struct spq_hint hint;
	memset(&hint, 0, sizeof(hint));
	struct spq_key *sk = NULL;

	REQS_SK_ACQ(c, H_REQS_SQL, sk, type, msg);

	if (!spq_store_save(sk,
				msg->shared, msg->offset, msg->length,
				msg->store.data, msg->store.len,
				&hint)) {
		if (hint.level != SPQ_OK) {

			REQS_SK_REL(c, H_REQS_SQL, sk);

			if (*hint.message)
				return send_error(c, msg->id, hint.message, -1);
			return send_error(c, msg->id, "Internal error 1140", -1);
		}
	}

	REQS_SK_REL(c, H_REQS_SQL, sk);

	return send_ok(c, msg->id, C_OK_SIMPLE, NULL);
}

bool
_handle_store_load(struct client *c, unsigned type, Fep__StoreLoad *msg)
{
	Fep__StoreValue rmsg = FEP__STORE_VALUE__INIT;
	struct spq_hint hint;
	struct spq_StoreData sd;
	bool rval = true;
	struct spq_key *sk = NULL;
	memset(&hint, 0, sizeof(hint));
	memset(&sd, 0, sizeof(sd));

	REQS_SK_ACQ(c, H_REQS_SQL, sk, type, msg);

	if (!spq_store_load(sk,
				msg->shared, msg->offset, msg->length,
				&sd, &hint)) {
		if (hint.level != SPQ_OK) {

			REQS_SK_REL(c, H_REQS_SQL, sk);

			if (*hint.message)
				return send_error(c, msg->id, hint.message, -1);
			return send_error(c, msg->id, "Internal error 1148", -1);
		}
	}

	rmsg.size = sd.length;
	rmsg.store.data = sd.store;
	rmsg.store.len = sd.store_len;

	rval = send_message(c->cev, FEP__TYPE__tStoreValue, &rmsg);

	spq_store_load_free(&sd);

	REQS_SK_REL(c, H_REQS_SQL, sk);

	return rval;
}

