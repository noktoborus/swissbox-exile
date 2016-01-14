/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client/include/handle.c
 */

/* подгрузка имеющейся информации о файле */
static bool
_file_load(struct client *c, struct wait_file *wf)
{
	struct spq_FileMeta fmeta;
	memset(&fmeta, 0u, sizeof(struct spq_FileMeta));

	if (spq_getFileMeta(c->name, c->device_id,
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
		}
		spq_getFileMeta_free(&fmeta);
	}

	return true;
}

/* эту ерунду нужно вызывать в самом конце, после работы с wait_file,
 * т.е. при положительном результате wait_file будет освобождён
 * возвращает состояние линии
 */
static bool
_file_complete(struct client *c, struct wait_file *wf, bool prepare)
{
	uint64_t checkpoint;
	struct spq_hint hint;
	bool retval = true;
	if (wf->chunks != wf->chunks_ok) {
		if (prepare) {
			size_t pkeysize = wf->key_len * 2 + 1;
			char *pkeyhex = alloca(pkeysize);
			memset(&hint, 0, sizeof(struct spq_hint));
			bin2hex(wf->key, wf->key_len, pkeyhex, pkeysize);
			spq_insert_revision(c->name, c->device_id,
					&wf->rootdir, &wf->file, &wf->revision, &wf->parent,
					wf->enc_filename, pkeyhex, &wf->dir, wf->chunks, true,
					&hint);
			/* если произошла ошибка, то нужно выйти */
			if (hint.level != SPQ_OK) {
				if (*hint.message)
					return send_error(c, wf->msg_id, hint.message, -1);
				return send_error(c, wf->msg_id, "Internal error 934", -1);
			}
		}
		return true;
	}
	/* файл собрался */
	{
		size_t pkeysize = wf->key_len * 2 + 1;
		char *pkeyhex = alloca(pkeysize);
		memset(&hint, 0, sizeof(struct spq_hint));
		bin2hex(wf->key, wf->key_len, pkeyhex, pkeysize);
		checkpoint = spq_insert_revision(c->name, c->device_id,
				&wf->rootdir, &wf->file, &wf->revision, &wf->parent,
				wf->enc_filename, pkeyhex, &wf->dir, wf->chunks, false,
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
	/* TODO: удаление файлов */
	uint64_t hash;
	wait_store_t *ws;
	struct wait_file *wf;
	struct spq_FileMeta fmeta;

	char *enc_filename;
	uint8_t *key;
	size_t key_len;

	bool need_clear = false;

	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	hash = MAKE_FHASH(msg->rootdir_guid, msg->file_guid);

	/* FIXME: ересь, прибраться после починки таблиц
	 * если в FileMeta не указаны enc_filename и key,
	 * нужно подгребсти их из таблицы
	 * по нормальному, нужно делать связь между таблицами по REFERENCES
	 */
	enc_filename = msg->enc_filename;
	key = msg->key.data;
	key_len = msg->key.len;
	if (!msg->enc_filename || !msg->key.len) {
		guid_t _rootdir;
		guid_t _file;
		guid_t _rev;
		string2guid(PSLEN(msg->rootdir_guid), &_rootdir);
		string2guid(PSLEN(msg->file_guid), &_file);
		string2guid(PSLEN(msg->revision_guid), &_rev);
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "client[%"SEV_LOG"] "
				"FileMeta Prepare: enc_filename: \"%s\", "
				"file_guid: \"%s\", revision_guid: \"%s\", key_len: %"PRIuPTR,
				c->cev->serial,
				msg->enc_filename, msg->file_guid, msg->revision_guid,
				msg->key.len);
#endif
		memset(&fmeta, 0u, sizeof(struct spq_FileMeta));
		if (!spq_getFileMeta(c->name, c->device_id,
					&_rootdir, &_file, NULL, false, &fmeta, NULL)) {
			return send_error(c, msg->id, "Internal error 1759", -1);
		}
		if (fmeta.empty) {
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

	/* ws_touched нужен для избежания попадания второй записи об одном файле
	 * в список
	 */
	ws = touch_id(c, &c->fid, hash);
	if (!ws) {
		/* если записи нет, нужно создать новую */
		ws = calloc(1, sizeof(struct wait_store) + sizeof(struct wait_file));
		if (!ws) {
			if (need_clear)
				spq_getFileMeta_free(&fmeta);
			return send_error(c, msg->id, "Internal error 1860", -1);
		}
		wf = ws->data = ws + 1;
		wf->id = hash;
		wait_id(c, &c->fid, hash, ws);
	} else {
		wf = ws->data;
	}

	/* заполнение всех полей */
	wf->msg_id = msg->id;
	if (!wf->rootdir.not_null)
		string2guid(PSLEN(msg->rootdir_guid), &wf->rootdir);
	if (!wf->file.not_null)
		string2guid(PSLEN(msg->file_guid), &wf->file);
	if (!wf->revision.not_null)
		string2guid(PSLEN(msg->revision_guid), &wf->revision);
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
			"file_guid: \"%s\", revision_guid: \"%s\", key_len: %"PRIuPTR" "
			"hash: %"PRIu64,
			c->cev->serial,
			enc_filename, msg->file_guid, msg->revision_guid, key_len,
			hash);
#endif
	return _file_complete(c, wf, true);
}

bool
_handle_rename_chunk(struct client *c, unsigned type, Fep__RenameChunk *msg)
{
	uint64_t hash;
	struct wait_store *ws;
	struct wait_file *wf;
	char *errmsg = NULL;
	struct spq_hint hint;

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
	if ((ws = touch_id(c, &c->fid, hash)) == NULL) {
		/* создание нового wait_file */
		ws = calloc(1, sizeof(struct wait_store) + sizeof(struct wait_file));
		if (!ws)
			return send_error(c, msg->id, "Internal error 1725", -1);
		wf = (ws->data = ws + 1);
		memcpy(&wf->file, &file, sizeof(guid_t));
		memcpy(&wf->revision, &revision_new, sizeof(guid_t));
		memcpy(&wf->rootdir, &rootdir, sizeof(guid_t));
		wf->id = hash;
		_file_load(c, wf);
		wait_id(c, &c->fid, hash, ws);
	} else {
		wf = ws->data;
	}
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "rename chunk: rootdir: %s, file: %s, chunk %s -> "
			"chunk %s, rev %s", msg->rootdir_guid, msg->file_guid,
			msg->chunk_guid, msg->to_chunk_guid, msg->to_revision_guid);
#endif
	memset(&hint, 0, sizeof(struct spq_hint));
	/* манипуляция данными в бд */
	if (!spq_link_chunk(c->name, c->device_id, &rootdir, &file, &chunk,
				&chunk_new, &revision_new, &hint)) {
		wf->chunks_fail++;
		errmsg = "Internal error 2054";
	} else {
		wf->chunks_ok++;
	}

	if (errmsg) {
		if (*hint.message)
			return send_error(c, msg->id, hint.message, -1);
		else
			return send_error(c, msg->id, errmsg, -1);
	}
	return send_ok(c, msg->id, C_OK_SIMPLE, NULL);
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
		} else if (!spq_insert_chunk(c->name, c->device_id,
					&wf->rootdir, &wf->file, &wf->revision,
					&wx->chunk_guid, chunk_hash,
					wx->size, wx->offset, "xxx", &hint)) {
			/* запись чанка не удалась */
			if (*hint.message)
				snprintf(errmsg, sizeof(errmsg), hint.message);
			else
				snprintf(errmsg, sizeof(errmsg), "Internal error 2023");
		}
	}

	sid_free(ws);
	/* освобождаем захваченный в handle_write_ask() ресурс */
	client_reqs_release(c, H_REQS_FD);
	if (!*errmsg) {
		wf->chunks_ok++;
		/* нет смысла пытаться отправить "Ok" клиенту, если
		 * соеденение отвалилось при отправке OkUpdate
		 */
		if (!_file_complete(c, wf, false))
			return false;
		return send_ok(c, end->id, C_OK_SIMPLE, NULL);
	} else {
		/* чанк не нужен, клиент перетащит его заного */
		wf->chunks_fail++;
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

	c->checkpoint = msg->checkpoint;
	if (!_active_sync(c, rootdir.not_null ? &rootdir : NULL, msg->checkpoint,
				msg->session_id, 0lu)) {
		client_reqs_release(c, H_REQS_SQL);
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
		return send_error(c, msg->id, "Internal error 121", -1);
	}

	if (!fcac_open(&c->cev->pain->fcac, ci->group, &chs->p, 0)) {
		free(chs);
		return send_error(c, msg->id, "Internal error 1149", -1);
	}

	chs->session_id = generate_sid(c);
	chs->size = ci->size;
	chs->next = c->cout;
	chs->chunk_size = chs->size;
	chs->file_offset = ci->offset;
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
	return true;
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

	struct spq_hint hint;
	struct getChunkInfo cnfo;

	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);
	string2guid(msg->chunk_guid, strlen(msg->chunk_guid), &chunk);
	memset(&hint, 0, sizeof(struct spq_hint));
	memset(&cnfo, 0, sizeof(struct getChunkInfo));

	/* особождение ресурса по окончанию итерации в iterate_chunk() */
	if (!client_reqs_acquire(c, H_REQS_SQL | H_REQS_FD)) {
		if (!send_pending(c, msg->id))
			return false;
		return client_reqs_queue(c, H_REQS_SQL | H_REQS_FD, type, msg);
	}

	if (!spq_getChunkInfo(c->name, c->device_id, &rootdir, &file, &chunk,
				&cnfo, &hint)) {
		client_reqs_release(c, H_REQS_SQL | H_REQS_FD);
		if (*hint.message)
			return send_error(c, msg->id, hint.message, -1);
		return send_error(c, msg->id, "Internal error 120", -1);
	}

	if (!cnfo.address || !*cnfo.address) {
		spq_getChunkInfo_free(&cnfo);
		client_reqs_release(c, H_REQS_SQL | H_REQS_FD);
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

	struct getChunkInfo _ci = {0};
	struct spq_hint _hint;
	char chunk_hash[PATH_MAX];

	uint64_t hash = 0;
	uint64_t chunk_id = 0;
	struct wait_store *fid_ws;
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
	if (!client_reqs_acquire(c, H_REQS_SQL | H_REQS_FD)) {
		if (!send_pending(c, msg->id)) {
			return false;
		}
		/* кладём в очередь и выходим */
		return client_reqs_queue(c, H_REQS_SQL | H_REQS_FD, type, msg);
	}

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
		spq_get_quota(c->name, c->device_id, &rootdir, &_qi, &_hint);
		if (_hint.level == SPQ_ERR) {
			client_reqs_release(c, H_REQS_SQL | H_REQS_FD);
			if (*_hint.message)
				return send_error(c, msg->id, _hint.message, -1);
			return send_error(c, msg->id, "Internal error 977", -1);
		}
		if (_qi.quota) {
			if (_qi.used + msg->size > _qi.quota) {
				client_reqs_release(c, H_REQS_SQL | H_REQS_FD);
				return send_error(c, msg->id, "No enough space", -1);
			}
		}
	}

	bin2hex(msg->chunk_hash.data, msg->chunk_hash.len, PSIZE(chunk_hash));
	/* получение id чанка и запись в кеш */
	memset(&_ci, 0u, sizeof(_ci));
	memset(&_hint, 0u, sizeof(_hint));

	if (!spq_chunk_prepare(c->name, c->device_id, &rootdir,
			chunk_hash, msg->size, &_ci, &_hint)) {
		client_reqs_release(c, H_REQS_SQL | H_REQS_FD);
		if (*_hint.message)
			return send_error(c, msg->id, _hint.message, -1);
		return send_error(c, msg->id, "Internal error 1175", -1);
	}

	if (_ci.address || _ci.driver) {
		struct spq_hint hint;
		memset(&hint, 0u, sizeof(hint));
		/*
		 * если _prepare() вернул адрес и драйвер, то отослать satisfied
		 */

		if (!spq_insert_chunk(c->name, c->device_id,
					&rootdir, &file, &revision, &chunk,
					chunk_hash, msg->size, msg->offset, _ci.address, &hint)) {
			spq_getChunkInfo_free(&_ci);
			if (*hint.message)
				return send_error(c, msg->id, hint.message, -1);
			else
				return send_error(c, msg->id, "Internal error 1240", -1);
		}
		spq_getChunkInfo_free(&_ci);
		/* освобождаем оба ресурса, т.к. End не прийдёт */
		client_reqs_release(c, H_REQS_SQL | H_REQS_FD);
		return send_satisfied(c, msg->id);
	}
	chunk_id = _ci.group;
	spq_getChunkInfo_free(&_ci);

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
		ws = calloc(1, sizeof(struct wait_store) + sizeof(struct wait_xfer));
		if (!ws || !fid_ws) {
			errmsg = "";
		} else {
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

			string2guid(msg->chunk_guid, strlen(msg->chunk_guid),
					&wx->chunk_guid);
			/* ссылаемся на wait_file и увеличиваем счётчик */
			wx->wf = fid_ws->data;
			wx->wf->ref++;
			wx->hash_len = msg->chunk_hash.len;
			memcpy(wx->hash, (void*)msg->chunk_hash.data, msg->chunk_hash.len);
			wx->offset = msg->offset;
		}
		/* логический костыль */
		if (fid_in)
			fid_ws = NULL;
	}

	if (errmsg) {
		fcac_close(&wx->p);
		if (ws)
			free(ws);
		if (fid_ws)
			free(fid_ws);
		xsyslog(LOG_WARNING,
				"client[%"SEV_LOG"] open(%"PRIu64") failed: %s",
				c->cev->serial, chunk_id, strerror(errno));
		/* ошибка, End не прийдёт */
		client_reqs_release(c, H_REQS_SQL | H_REQS_FD);
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
	/* инициализаци полей wait_file */
	wait_id(c, &c->sid, wrok.session_id, ws);
	if (fid_ws) {
		wf = fid_ws->data;

		memcpy(&wf->rootdir, &rootdir, sizeof(rootdir));
		memcpy(&wf->file, &file, sizeof(file));
		memcpy(&wf->revision, &revision, sizeof(revision));

		/* если запрос завершился неудачно, то файла, вероятнее всего нет */
		_file_load(c, wf);

		wf->id = hash;
		wait_id(c, &c->fid, hash, fid_ws);
	}

	/* в случае успеха освобождаем только ресурс SQL, но оставляем
	 * захваченным fd, его нужно освободить только после прихода End
	 */
	client_reqs_release(c, H_REQS_SQL);
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

	memset(enc_filename, 0u, PATH_MAX);
	if (msg->enc_filename) {
		register size_t _len = strlen(msg->enc_filename);
		if (_len >= PATH_MAX)
			return send_error(c, msg->id, "enc_filename too long", -1);
		strncpy(enc_filename, msg->enc_filename, _len);
	}

	string2guid(PSLEN(msg->rootdir_guid), &rootdir);
	string2guid(PSLEN(msg->file_guid), &file);
	string2guid(PSLEN(msg->directory_guid), &directory);

	memset(&hint, 0u, sizeof(struct spq_hint));
	checkpoint = spq_update_file(c->name, c->device_id, &rootdir, &file,
			&directory, *enc_filename ? enc_filename : NULL, &hint);

	if (!checkpoint) {
		if (*hint.message)
			return send_error(c, msg->id, hint.message, -1);
		return send_error(c, msg->id, "Internal error 1913", -1);
	}

	client_share_checkpoint(c, &rootdir, checkpoint);

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

	string2guid(PSLEN(msg->rootdir_guid), &rootdir);
	string2guid(PSLEN(msg->directory_guid), &directory);

	memset(&hint, 0u, sizeof(struct spq_hint));
	checkpoint = spq_directory_create(c->name, c->device_id,
			&rootdir, &directory, msg->path, &hint);
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

	/* конвертация типов */
	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);

	memset(&gr, 0, sizeof(struct getRevisions));

	/* освобождать ресурсы нужно в конце итерации */
	if (!client_reqs_acquire(c, H_REQS_SQL)) {
		if (!send_pending(c, msg->id))
			return false;
		return client_reqs_queue(c, H_REQS_SQL, type, msg);
	}

	if (!spq_getRevisions(c->name, c->device_id,
				&rootdir, &file, msg->depth, &gr)) {
		client_reqs_release(c, H_REQS_SQL);
		return send_error(c, msg->id, "Internal error 100", -1);
	}

	/* выделяем память под список */
	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_getRevisions_free(&gr);
		client_reqs_release(c, H_REQS_SQL);
		return send_error(c, msg->id, "Internal error 111", -1);
	}
	memcpy(&rs->v.r, &gr, sizeof(struct getRevisions));
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

	rs = calloc(1, sizeof(*rs));
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
	if (!spq_getDevices(c->name, c->device_id, &rs->v.d, &hint)) {
		free(rs);
		client_reqs_release(c, H_REQS_SQL);
		return send_error(c, msg->id, "Internal error 1010", -1);
	}

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

	/* конвертим типы */
	string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid), &rootdir);
	string2guid(msg->file_guid, strlen(msg->file_guid), &file);
	string2guid(msg->revision_guid, strlen(msg->revision_guid), &revision);

	memset(&gc, 0, sizeof(struct getChunks));

	/* освобождается в client_iterate */
	if (!client_reqs_acquire(c, H_REQS_SQL)) {
		if (!send_pending(c, msg->id))
			return false;
		return client_reqs_queue(c, H_REQS_SQL, type, msg);
	}

	if (!spq_getChunks(c->name, c->device_id,
				&rootdir, &file, &revision, &gc)) {
		client_reqs_release(c, H_REQS_SQL);
		return send_error(c, msg->id, "Internal error 110", -1);
	}

	/* выделяем память под список */
	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_getChunks_free(&gc);
		client_reqs_release(c, H_REQS_SQL);
		return send_error(c, msg->id, "Internal error 111", -1);
	}

	/* отправка подтверждения, что всё ок */
	{
		struct spq_hint _hint;
		memset(&fmeta, 0u, sizeof(struct spq_FileMeta));
		memset(&_hint, 0u, sizeof(struct spq_hint));
		if (!spq_getFileMeta(c->name, c->device_id,
					&rootdir, &file, &revision, false, &fmeta, &_hint)) {
			free(rs);
			client_reqs_release(c, H_REQS_SQL);
			if (*_hint.message)
				return send_error(c, msg->id, _hint.message, -1);
			return send_error(c, msg->id, "Internal error 112", -1);
		}
		if (fmeta.empty) {
			free(rs);
			client_reqs_release(c, H_REQS_SQL);
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
	} else if (xfer->data.len + xfer->offset > wx->size) {
		errmsg = "Owerdose input data";
	} else if ((ready != FCAC_READY &&
		fcac_write(&wx->p, xfer->data.data, xfer->data.len) !=
			xfer->data.len)) {
		errmsg = "Write fail";
	} else {
		/* потенциально проблемное место при ready == FCAC_READY */
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

	if (!spq_store_save(c->name, c->device_id,
				msg->shared, msg->offset, msg->length,
				msg->store.data, msg->store.len,
				&hint)) {
		if (hint.level != SPQ_OK) {
			if (*hint.message)
				return send_error(c, msg->id, hint.message, -1);
			return send_error(c, msg->id, "Internal error 1140", -1);
		}
	}
	return send_ok(c, msg->id, C_OK_SIMPLE, NULL);
}

bool
_handle_store_load(struct client *c, unsigned type, Fep__StoreLoad *msg)
{
	Fep__StoreValue rmsg;
	struct spq_hint hint;
	struct spq_StoreData sd;
	bool rval = true;
	memset(&hint, 0, sizeof(hint));
	memset(&sd, 0, sizeof(sd));
	memset(&rmsg, 0, sizeof(rmsg));

	if (!spq_store_load(c->name, c->device_id,
				msg->shared, msg->offset, msg->length,
				&sd, &hint)) {
		if (hint.level != SPQ_OK) {
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
	return rval;
}

