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
		xsyslog(LOG_DEBUG, "client[%p] file complete with ref=%u, "
				" chunks=%u/%u (chunks_fail=%u) and status=%s",
				(void*)c->cev, wf->ref,
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
		xsyslog(LOG_DEBUG, "client[%p] "
				"FileMeta Prepare: enc_filename: \"%s\", "
				"file_guid: \"%s\", revision_guid: \"%s\", key_len: %"PRIuPTR,
				(void*)c->cev,
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
	xsyslog(LOG_DEBUG, "client[%p] FileMeta: enc_filename: \"%s\", "
			"file_guid: \"%s\", revision_guid: \"%s\", key_len: %"PRIuPTR" "
			"hash: %"PRIu64,
			(void*)c->cev,
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
		xsyslog(LOG_DEBUG, "client[%p] End not found for id %"PRIu32,
				(void*)c->cev, end->session_id);
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
	xsyslog(LOG_DEBUG, "client[%p] close fd#%d, id %"PRIu32" "
			"file meta hash: %"PRIu64,
			(void*)c->cev, wx->fd, end->session_id, wf->id);
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
		/* чанк пришёл, теперь нужно попробовать обновить информацию в бд */
		} else if (!spq_insert_chunk(c->name, c->device_id, &wf->rootdir, &wf->file,
					&wf->revision, &wx->chunk_guid, chunk_hash,
					wx->size, wx->offset, wx->path, &hint)) {
			/* запись чанка не удалась */
			if (*hint.message)
				snprintf(errmsg, sizeof(errmsg), hint.message);
			else
				snprintf(errmsg, sizeof(errmsg), "Internal error 2023");
		}
	}
	if (!*errmsg) {
		sid_free(ws);
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
		unlink(wx->path);
		/* чиститься нужно после unlink
		 * потому что в sid_free вычещается и ws->dat
		 */
		sid_free(ws);
		return send_error(c, end->id, errmsg, -1);
	}
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
_handle_want_sync(struct client *c, unsigned type, Fep__WantSync *msg)
{
	guid_t rootdir;
	if (!c->status.auth_ok)
		return send_error(c, msg->id, "Unauthorized", -1);

	/* после запроса состояния можно и запустить экспресс-нотификацию */
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

	c->checkpoint = msg->checkpoint;
	if (!_active_sync(c, rootdir.not_null ? &rootdir : NULL, msg->checkpoint,
				msg->session_id, 0lu)) {
		return send_error(c, msg->id, "Internal error 1653", -1);
	}
	c->status.log_active = true;
	return send_ok(c, msg->id, C_OK_SIMPLE, NULL);
}

struct _bus_data {
	uint64_t msgid;
	struct client *c;
};

static void
_bus_result_driver(struct almsg_parser *a, struct _bus_data *bd)
{
	/* сразу получаем значения и высвобождаем кусочек памяти */
	uint64_t msgid = bd->msgid;
	struct client *c = bd->c;
	free(bd);

	if (!a) {
		/* если a == NULL, значит запрос выпал
		 * нужно сообщить клиенту ошибочку
		 */
		send_error(c, msgid, "timeout", -1);
		return;
	}

	/* формируем запрос к файлу через драйвер и ответ клиенту */



	/* TODO */
}

static inline bool
_read_ask__from_driver(struct client *c, Fep__ReadAsk *msg,
		struct getChunkInfo *ci)
{
	bool r = true;
	struct almsg_parser alm;
	/* FIXME: нужно больше фрагментации!
	 * альтернативный способ: глобальный массив,
	 * синхронизация не нужна, т.к. всё выполняется синхронно в libev
	 */
	struct _bus_data *bd = calloc(1, sizeof(struct _bus_data));
	almsg_init(&alm);

	almsg_insert(&alm, PSLEN_S("action"), PSLEN_S("query-driver"));
	/*almsg_insert(&alm, PSLEN_S("query"), PSLEN_S("read-data"));*/
	almsg_append(&alm, PSLEN_S("owner"), PSLEN(c->name));
	almsg_append(&alm, PSLEN_S("address"), PSLEN(ci->address));
	almsg_append(&alm, PSLEN_S("driver"), PSLEN(ci->driver));

	r = bus_query(c->cev, &alm,
			(bus_result_cb)_bus_result_driver, (void*)bd);
	almsg_destroy(&alm);
	return r;
	/*return send_error(c, msg->id, "Not implement", -1);
	 */
	/*return true;
	 */
}

static inline bool
_read_ask__from_cache(struct client *c, Fep__ReadAsk *msg,
		struct getChunkInfo *ci)
{
	struct stat st;
	struct chunk_send *chs;
	int fd;

	/* информация о файле (нужно узнать размер) */
	if (stat(ci->address, &st) == -1) {
		return send_error(c, msg->id, "Internal error 123", -1);
	}

	/* открытие файла */
	if ((fd = open(ci->address, O_RDONLY)) == -1) {
		return send_error(c, msg->id, "Internal error 122", -1);
	}

	if (!(chs = calloc(1, sizeof(struct chunk_send)))) {
		close(fd);
		return send_error(c, msg->id, "Internal error 121", -1);
	}

	chs->fd = fd;
	chs->session_id = generate_sid(c);
	chs->size = st.st_size;
	chs->next = c->cout;
	chs->chunk_size = chs->size;
	chs->file_offset = ci->offset;
	c->cout = chs;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] -> ReadAsk id = %"PRIu64,
			(void*)c->cev, msg->id);
#endif
	{
		Fep__OkRead rdok = FEP__OK_READ__INIT;
		rdok.id = msg->id;
		rdok.session_id = chs->session_id;
		rdok.size = st.st_size;
		rdok.offset = ci->offset;

		return send_message(c->cev, FEP__TYPE__tOkRead, &rdok);
	}
	return true;
}

bool
_handle_read_ask(struct client *c, unsigned type, Fep__ReadAsk *msg)
{
	/*
	 * 1. поиск файла в бд
	 * 2. формирование структуры для отправки файла или отсылка Error
	 */
	/*
	 * 1. Отдача через драйвер
	 * 1.1. получение информации из БД
	 * 1.2. обращение к драйверу, если присутсвует
	 * 1.3. ожидание ответа
	 * 1.4. (при затянувшемся ожидании ответ Pendgin клиенту)
	 * 1.5. ответ клиенту
	 * 2. Отдача из кэша
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

	if (!spq_getChunkInfo(c->name, c->device_id, &rootdir, &file, &chunk,
				&cnfo, &hint)) {
		if (*hint.message)
			return send_error(c, msg->id, hint.message, -1);
		return send_error(c, msg->id, "Internal error 120", -1);
	}

	if (!cnfo.address || !*cnfo.address) {
		spq_getChunkInfo_free(&cnfo);
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
	char *errmsg = NULL;
	char path[PATH_MAX];
	struct wait_store *ws;
	struct wait_xfer wx;

	guid_t rootdir;
	guid_t file;
	guid_t chunk;

	uint64_t hash;
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
	if (!msg->chunk_hash.len)
		errmsg = "Chunk hash is empty";

	if (errmsg)
		return send_error(c, msg->id, errmsg, -1);

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
			if (*_hint.message)
				return send_error(c, msg->id, _hint.message, -1);
			return send_error(c, msg->id, "Internal error 977", -1);
		}
		if (_qi.quota) {
			if (_qi.used + msg->size > _qi.quota) {
				return send_error(c, msg->id, "No enough space", -1);
			}
		}
	}

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
		wx.offset = msg->offset;
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
	/* инициализируем polarssl */
#if !POLARSSL_LESS_138
	sha256_init(&wx.sha256);
#endif
	sha256_starts(&wx.sha256, 0);

	/* пакуем структуры */
	wrok.id = msg->id;
	wrok.session_id = generate_sid(c);

	ws->data = ws + 1;
	memcpy(ws->data, &wx, sizeof(struct wait_xfer));
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] fd#%d for %s [%"PRIu32"]",
			(void*)c->cev, wx.fd, wx.path, wrok.session_id);
#endif
	/* инициализаци полей wait_file */
	wait_id(c, &c->sid, wrok.session_id, ws);
	if (fid_ws) {
		wf = fid_ws->data;
		string2guid(msg->rootdir_guid, strlen(msg->rootdir_guid),
				&wf->rootdir);
		string2guid(msg->file_guid, strlen(msg->file_guid), &wf->file);
		string2guid(msg->revision_guid, strlen(msg->revision_guid),
				&wf->revision);

		/* если запрос завершился неудачно, то файла, вероятнее всего нет */
		_file_load(c, wf);

		wf->id = hash;
		wait_id(c, &c->fid, hash, fid_ws);
	}

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

	if (!spq_getRevisions(c->name, c->device_id,
				&rootdir, &file, msg->depth, &gr)) {
		return send_error(c, msg->id, "Internal error 100", -1);
	}

	/* выделяем память под список */
	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_getRevisions_free(&gr);
		return send_error(c, msg->id, "Internal error 111", -1);
	}
	memcpy(&rs->v.r, &gr, sizeof(struct getRevisions));
	rs->id = msg->session_id;
	rs->type = RESULT_REVISIONS;
	rs->free = (void(*)(void*))spq_getRevisions_free;
	rs->next = c->rout;
	c->rout = rs;
#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] -> QueryRevisions id = %"PRIu64
			" sid = %"PRIu32,
			(void*)c->cev, msg->id, msg->session_id);
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

	memset(&hint, 0u, sizeof(hint));
	if (!spq_getDevices(c->name, c->device_id, &rs->v.d, &hint)) {
		free(rs);
		return send_error(c, msg->id, "Internal error 1010", -1);
	}

	rs->id = msg->session_id;
	rs->type = RESULT_DEVICES;
	rs->free = (void(*)(void*))spq_getDevices_free;
	rs->next = c->rout;
	c->rout = rs;

#if DEEPDEBUG
	xsyslog(LOG_DEBUG, "client[%p] -> QueryDevices id = %"PRIu64
			" sid = %"PRIu32,
			(void*)c->cev, msg->id, msg->session_id);
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

	if (!spq_getChunks(c->name, c->device_id,
				&rootdir, &file, &revision, &gc)) {
		return send_error(c, msg->id, "Internal error 110", -1);
	}

	/* выделяем память под список */
	rs = calloc(1, sizeof(struct result_send));
	if (!rs) {
		spq_getChunks_free(&gc);
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
			if (*_hint.message)
				return send_error(c, msg->id, _hint.message, -1);
			return send_error(c, msg->id, "Internal error 112", -1);
		}
		if (fmeta.empty) {
			free(rs);
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
		sha256_update(&wx->sha256, xfer->data.data, xfer->data.len);
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
	/*
	 * закрываем всякие ресурсы и уменьшаем счётчик ссылок
	 */
	unlink(wx->path);
	/* освобождение памяти в последнюю очередь,
	 * т.к. wx и ws выделяются в последнюю очередь
	 */
	if ((ws = query_id(c, &c->sid, xfer->session_id)) != NULL)
		sid_free(ws);
	return send_error(c, xfer->id, errmsg, -1);
}

