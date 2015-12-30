/* vim: ft=c ff=unix fenc=utf-8
 * file: src/packet.c
 */

#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "junk/guid.h"
#include "junk/utils.h"
#include "junk/xsyslog.h"
#include "proto/fep.pb-c.h"
#include "packet.h"

#define _value_or_null(s, result, fmt, field, begin, len) \
{\
	if (len > 0u && s->has_##field) {\
		begin +=\
			snprintf(result + begin, (len -= begin),\
				", "#field"="fmt, s->field);\
	}\
}

#define _value_or_nullS(s, result, field, begin, len) \
{\
	if (len > 0u && s->field)\
		begin += snprintf(result + begin, (len -= begin),\
			", "#field"=\"%s\"", s->field);\
}

#define _value_or_nullB(s, result, field, Xbegin, Xlen) \
{\
	if (Xlen > 0u && s->has_##field) {\
		if (s->field.len) {\
			size_t ___l = s->field.len * 2;\
			char *___e = calloc(1, ___l + 1);\
			bin2hex(s->field.data, s->field.len, ___e, ___l);\
			Xbegin += snprintf(result + Xbegin, (Xlen -= Xbegin),\
					", "#field"=\"%s\"", ___e);\
			free(___e);\
		} else {\
			Xbegin += snprintf(result + Xbegin, (Xlen -= Xbegin),\
					", "#field"=?");\
		}\
	}\
}

static enum packet_verbose _packet_verbose[FEP__TYPE__t_max];

#define PACKET_NAME_LEN 16 /* размер строки с именем */
#define PACKET_FULL_LEN 64 /* размер строки с именем и флагами */

static struct packet_info {
	char name[PACKET_NAME_LEN];
	char name_lower[PACKET_NAME_LEN];
	uint64_t name_hash;
	unsigned type;
} _packet_info[FEP__TYPE__t_max] = {
	{.name = "?"},
	{.name = "Ping"},
	{.name = "Pong"},
	{.name = "Error"},
	{.name = "Ok"},
	{.name = "Pending"},
	{.name = "ReqAuth"},
	{.name = "Auth"},
	{.name = "xfer"},
	{.name = "ReadAsk"},
	{.name = "WriteAsk"},
	{.name = "End"},
	{.name = "OkWrite"},
	{.name = "FileUpdate"},
	{.name = "RenameChunk"},
	{.name = "QueryChunks"},
	{.name = "ResultChunk"},
	{.name = "QueryRevisions"},
	{.name = "ResultRevision"},
	{.name = "DirectoryUpdate"},
	{.name = "FileMeta"},
	{.name = "WantSync"},
	{.name = "OkUpdate"},
	{.name = "RootdirUpdate"},
	{.name = "OkRead"},
	{.name = "Chat"},
	{.name = "State"},
	{.name = "QueryDevices"},
	{.name = "ResultDevice"},
	{.name = "StoreSave"},
	{.name = "StoreLoad"},
	{.name = "StoreValue"},
	{.name = "Satisfied"}
};

static inline void
_packet_info_init(struct packet_info i[FEP__TYPE__t_max])
{
	register size_t c = 0u;
	register size_t l = 0u;
	if(i[0].name_hash)
		return;

	for(c = 0u; c < FEP__TYPE__t_max; c++) {
		memcpy(i[c].name_lower, i[c].name, sizeof(i[c].name_lower));
		l = tolower_s(i[c].name_lower, 0u);
		i[c].name_hash = hash_pjw(i[c].name_lower, l);
		i[c].type = c;
	}
}

const char *
packet_type_to_name(unsigned type)
{
	_packet_info_init(_packet_info);
	if (type >= FEP__TYPE__t_max) {
		type = 0u;
	}
	return _packet_info[type].name;
}

bool
packet_name_to_type(char *in, unsigned *type, enum packet_verbose *flags)
{
	char *e = in;
	char _name_lower[PACKET_NAME_LEN + 1] = {0};
	size_t len = 0u;
	uint64_t hash;

	_packet_info_init(_packet_info);

	*flags = PACKET_NONE;
	memset(_name_lower, 0u, sizeof(_name_lower));

	if ((e = strchr(e, ':')) == NULL) {
		strncpy(_name_lower, in, sizeof(_name_lower));
	} else {
		memcpy(_name_lower, in, MIN(e - in, PACKET_NAME_LEN));
		/* разбор флагов */
		do {
			if (!strncmp(e, PSIZE(":hex"))) {
				*flags |= PACKET_HEX;
			} else if (!strncmp(e, PSLEN_S(":field"))) {
				*flags |= PACKET_FIELD;
			} else if (!strncmp(e, PSLEN_S(":discard"))) {
				*flags |= PACKET_DISCARD;
			}
			e++;
		} while((e = strchr(e, ':')) != NULL);
	}

	/* тип пакета */
	len = tolower_s(_name_lower, 0u);
	hash = hash_pjw(_name_lower, len);

	for (size_t _c = 0u; _c < FEP__TYPE__t_max; _c++) {
		if (_packet_info[_c].name_hash == hash) {
			*type = _packet_info[_c].type;
			return true;
		}
	}

	return false;
}

void
packet_verbose(const char *packet_string)
{
	const char *b = packet_string;
	char *c = NULL;
	size_t len;

	char _string[PACKET_FULL_LEN];
	unsigned type = 0u;
	enum packet_verbose flags = PACKET_NONE;
	char format[80];

	/* обработка всего массива */
	do {
		/* получение длины */
		if ((c = strchr(b, ',')) == NULL) {
			len = strlen(b);
		} else {
			len = c - b;
		}
		memset(format, 0, sizeof(format));
		memset(_string, 0, sizeof(_string));
		memcpy(_string, b, len);
		if (!packet_name_to_type(_string, &type, &flags)) {
			continue;
		}
		if (!flags) {
			/* базовое значение */
			flags = PACKET_FIELD;
		} if (flags & PACKET_DISCARD) {
			/* сам флаг PACKET_DISCARD не используется */
			flags = PACKET_NONE;
		}

		/* простая замена значения */
		_packet_verbose[type] = flags;

		/* форматирование строки */
		if (!_packet_verbose[type]) {
			xsyslog(LOG_DEBUG,
					"packet2syslog: unset %s", packet_type_to_name(type));
		} else {
			if (_packet_verbose[type] & PACKET_FIELD) {
				strncat(format, ":field", sizeof(format) - strlen(format));
			}
			if (_packet_verbose[type] & PACKET_HEX) {
				strncat(format, ":hex", sizeof(format) - strlen(format));
			}
			/* и печать в лог */
			xsyslog(LOG_DEBUG, "packet2syslog: set %s to %s",
					packet_type_to_name(type), format);
		}

	} while ((b = strchr(b, ',')) != NULL && *++b);

}


void
packet2syslog(const char *head,
		unsigned type, const void *msg)
{
	char result[4096];
	size_t _l = 0u;
	size_t _e = sizeof(result);

	if (type >= FEP__TYPE__t_max || !(_packet_verbose[type] & PACKET_FIELD))
		return;

	switch (type) {
	case FEP__TYPE__tReqAuth:
		{
			Fep__ReqAuth *_m = (void*)msg;
			char _epoch[GUID_MAX + 1];
			bin2hex(_m->epoch_guid.data, _m->epoch_guid.len, PSIZE(_epoch));
			_l = snprintf(result, _e, "id=%"PRIu64", epoch_guid=%s",
					_m->id, _epoch);
			_value_or_nullS(_m, result, text, _l, _e);
			break;

		}
	case FEP__TYPE__tAuth:
		{
			Fep__Auth *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", device_id=%"PRIX64", domain=%s, authType=%s"
					", authToken=%s, password=%s, key=%s",
					_m->id, _m->device_id, _m->domain,
					(_m->authtype == FEP__REQ_AUTH_TYPE__tHash
					 ? "Hash" :
					 (_m->authtype == FEP__REQ_AUTH_TYPE__tUserPassword
					  ? "UserPassword" :
					  (_m->authtype == FEP__REQ_AUTH_TYPE__tUserToken
					   ? "UserToken" :
					   (_m->authtype == FEP__REQ_AUTH_TYPE__tKey
						? "Key": "Unknown")))),
					(_m->authtoken ? "yes" : "no"),
					(_m->password ? "yes" : "no"),
					(_m->has_key ? "yes" : "no")
					);
			_value_or_nullS(_m, result, username, _l, _e);
			break;
		}
	case FEP__TYPE__tWriteAsk:
		{
			Fep__WriteAsk *_m = (void*)msg;
			char _hash[HASHHEX_MAX + 1];
			memset(_hash, 0u, sizeof(_hash));
			bin2hex(_m->chunk_hash.data, _m->chunk_hash.len,
					_hash, sizeof(_hash));
			snprintf(result, _e,
					"id=%"PRIu64
					", rootdir_guid=%s, file_guid=%s, chunk_guid=%s"
					", revision_guid=%s, chunk_hash=%s"
					", size=%"PRIu32", offset=%"PRIu32,
					_m->id, _m->rootdir_guid, _m->file_guid, _m->chunk_guid,
					_m->revision_guid, _hash, _m->size, _m->offset);
			break;
		}
	case FEP__TYPE__tOk:
		{
			Fep__Ok *_m = (void*)msg;
			_l = snprintf(result, _e, "id=%"PRIu64, _m->id);
			_value_or_nullS(_m, result, message, _l, _e);
			break;
		}
	case FEP__TYPE__tFileMeta:
		{
			Fep__FileMeta *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64
					", rootdir_guid=%s, file_guid=%s, revision_guid=%s"
					", directory_guid=%s, chunks=%"PRIu32,
					_m->id, _m->rootdir_guid, _m->file_guid, _m->revision_guid,
					_m->directory_guid, _m->chunks);
			_value_or_nullS(_m, result, parent_revision_guid, _l, _e);
			_value_or_nullS(_m, result, enc_filename, _l, _e);
			_value_or_nullB(_m, result, key, _l, _e);
			break;
		}
	case FEP__TYPE__tPing:
		{
			Fep__Ping *_m = (void*)msg;
			snprintf(result, _e, "id=%"PRIu64", sec=%"PRIu64", usec=%"PRIu32,
					_m->id, _m->sec, _m->usec);
			break;
		}
	case FEP__TYPE__tPong:
		{
			Fep__Pong *_m = (void*)msg;
			snprintf(result, _e, "id=%"PRIu64", sec=%"PRIu64", usec=%"PRIu32
					", peer_sec=%"PRIu64", peer_usec=%"PRIu32,
					_m->id, _m->sec, _m->usec, _m->peer_sec, _m->peer_usec);
			break;
		}
	case FEP__TYPE__tError:
		{
			Fep__Error *_m = (void*)msg;
			char _r[64] = {0};
			snprintf(_r, sizeof(_r), "%"PRIu32, _m->remain);
			snprintf(result, sizeof(result),
					"id=%"PRIu64", message=\"%s\", remain=%s",
					_m->id,
					_m->message,
					(_m->has_remain ? _r : NULL));
			break;
		}
	case FEP__TYPE__tRootdirUpdate:
		{
			Fep__RootdirUpdate *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", rootdir_guid=%s",
					_m->id, _m->rootdir_guid);
			_value_or_null(_m, result, "%"PRIu64, checkpoint, _l, _e);
			_value_or_nullS(_m, result, name, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, session_id, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, no, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, max, _l, _e);
			break;
		}
	case FEP__TYPE__tDirectoryUpdate:
		{
			Fep__DirectoryUpdate *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", rootdir_guid=%s, directory_guid=%s",
					_m->id, _m->rootdir_guid, _m->directory_guid);
			_value_or_null(_m, result, "%"PRIu64, checkpoint, _l, _e);
			_value_or_nullS(_m, result, path, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, session_id, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, no, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, max, _l, _e);
			break;
		}
	case FEP__TYPE__tFileUpdate:
		{
			Fep__FileUpdate *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", rootdir_guid=%s, file_guid=%s",
					_m->id, _m->rootdir_guid, _m->file_guid);

			_value_or_null(_m, result, "%"PRIu64, checkpoint, _l, _e);
			_value_or_nullS(_m, result, directory_guid, _l, _e);
			_value_or_nullS(_m, result, revision_guid, _l, _e);
			_value_or_nullS(_m, result, enc_filename, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, session_id, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, no, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, max, _l, _e);
			break;
		}
	case FEP__TYPE__tWantSync:
		{
			Fep__WantSync *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", checkpoint=%"PRIu64", session_id=%"PRIu32,
					_m->id, _m->checkpoint, _m->session_id);
			_value_or_nullS(_m, result, rootdir_guid, _l, _e);
			break;
		}
	case FEP__TYPE__tEnd:
		{
			Fep__End *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", session_i=%"PRIu32, _m->id, _m->session_id);
			_value_or_null(_m, result, "%"PRIu32, packets, _l, _e);
			break;
		}
	case FEP__TYPE__tOkWrite:
		{
			Fep__OkWrite *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", session_id=%"PRIu32, _m->id, _m->session_id);
			break;
		}
	case FEP__TYPE__tOkRead:
		{
			Fep__OkRead *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", session_id=%"PRIu32
					", size=%"PRIu32", offset=%"PRIu32,
					_m->id, _m->session_id, _m->size, _m->offset);
			break;
		}
	case FEP__TYPE__txfer:
		{
			Fep__Xfer *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", session_id=%"PRIu32
					", offset=%"PRIu64", data.len=%"PRIu64,
					_m->id, _m->session_id,
					_m->offset, _m->data.len);
			break;
		}
	case FEP__TYPE__tReadAsk:
		{
			Fep__ReadAsk *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64
					", rootdir_guid=%s, file_guid=%s, chunk_guid=%s",
					_m->id,
					_m->rootdir_guid, _m->file_guid, _m->chunk_guid);
			break;
		}
	case FEP__TYPE__tQueryRevisions:
		{
			Fep__QueryRevisions *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", session_id=%"PRIu32
					", rootdir_guid=%s, file_guid=%s, depth=%"PRIu32,
					_m->id, _m->session_id,
					_m->rootdir_guid, _m->file_guid, _m->depth);
			break;
		}
	case FEP__TYPE__tResultRevision:
		{
			Fep__ResultRevision *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", session_id=%"PRIu32
					", no=%"PRIu32", max=%"PRIu32", revision_guid=%s",
					_m->id, _m->session_id,
					_m->rev_no, _m->rev_max, _m->revision_guid);
			_value_or_nullS(_m, result, parent_revision_guid, _l, _e);
			break;
		}
	case FEP__TYPE__tQueryChunks:
		{
			Fep__QueryChunks *_m = (void*)msg;
			_l = snprintf(result, _e,
				"id=%"PRIu64", session_id=%"PRIu32
				", rootdir_guid=%s, file_guid=%s, revision_guid=%s",
				_m->id, _m->session_id,
				_m->rootdir_guid, _m->file_guid, _m->revision_guid);
			break;
		}
	case FEP__TYPE__tResultChunk:
		{
			Fep__ResultChunk *_m = (void*)msg;
			char _hash[HASHHEX_MAX + 1];
			memset(_hash, 0, sizeof(_hash));
			bin2hex(_m->chunk_hash.data, _m->chunk_hash.len,
					_hash, sizeof(_hash));
			_l = snprintf(result, _e,
				"id=%"PRIu64", session_id=%"PRIu32
				", no=%"PRIu32", max=%"PRIu32", chunk_guid=%s, chunk_hash=%s",
				_m->id, _m->session_id,
				_m->chunk_no, _m->chunk_max,
				_m->chunk_guid, _hash);

			break;
		}
	case FEP__TYPE__tRenameChunk:
		{
			Fep__RenameChunk *_m = (void*)msg;
			_l = snprintf(result, _e,
				"id=%"PRIu64
				", rootdir_guid=%s, file_guid=%s, chunk_guid=%s"
				", to_chunk_guid=%s, to_revision_guid=%s",
				_m->id,
				_m->rootdir_guid, _m->file_guid, _m->chunk_guid,
				_m->to_chunk_guid, _m->to_revision_guid);
			break;
		}
	case FEP__TYPE__tOkUpdate:
		{
			Fep__OkUpdate *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", checkpoint=%"PRIu64,
					_m->id, _m->checkpoint);
			_value_or_nullS(_m, result, message, _l, _e);
			break;
		}
	case FEP__TYPE__tChat:
		{
			Fep__Chat *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", device_id_from=%"PRIu64
					", message.len=%"PRIuPTR,
					_m->id, _m->device_id_from,
					_m->message.len);
			_value_or_null(_m, result, "%"PRIu64, device_id_to, _l, _e);
			_value_or_nullS(_m, result, user_to, _l, _e);
			break;
		}
	case FEP__TYPE__tState:
		{
			Fep__State *_m = (void*)msg;
			_l = snprintf(result, _e, "id=%"PRIu64, _m->id);
			_value_or_null(_m, result, "%"PRIu32, devices, _l, _e);
			_value_or_null(_m, result, "%"PRIu64, last_auth_device, _l, _e);
			_value_or_nullS(_m, result, last_auth_time, _l, _e);
			_value_or_nullS(_m, result, last_auth_addr, _l, _e);
			break;
		}
	case FEP__TYPE__tQueryDevices:
		{
			Fep__QueryDevices *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", session_id=%"PRIu32,
					_m->id, _m->session_id);
			break;
		}
	case FEP__TYPE__tResultDevice:
		{
			Fep__ResultDevice *_m = (void*)msg;
			_l = snprintf(result, _e,
				"id=%"PRIu64", session_id=%"PRIu32
				", no=%"PRIu32", max=%"PRIu32
				", device_id=%"PRIX64", is_online=%s"
				", last_auth_time=%s",
				_m->id, _m->session_id,
				_m->dev_no, _m->dev_max, _m->device_id,
				(_m->is_online ? "true" : "false"),
				_m->last_auth_time);
			break;
		}
	case FEP__TYPE__tStoreSave:
		{
			Fep__StoreSave *_m = (void*)msg;
			_l = snprintf(result, _e,
					"id=%"PRIu64", shared=%s, store.len=%"PRIu64,
					_m->id, (_m->shared ? "true" : "false"), _m->store.len);
			_value_or_null(_m, result, "%"PRIu32, offset, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, length, _l, _e);
			break;
		}
	case FEP__TYPE__tStoreLoad:
		{
			Fep__StoreLoad *_m = (void*)msg;
			_l = snprintf(result, _e, "id=%"PRIu64", shared=%s",
					_m->id, (_m->shared ? "true" : "false"));
			_value_or_null(_m, result, "%"PRIu32, offset, _l, _e);
			_value_or_null(_m, result, "%"PRIu32, length, _l, _e);
			break;
		}
	case FEP__TYPE__tStoreValue:
		{
			Fep__StoreValue *_m = (void*)msg;
			snprintf(result, _e,
					"id=%"PRIu64", store.len=%"PRIu64", size=%"PRIu32,
					_m->id, _m->store.len, _m->size);
			break;
		}
	case FEP__TYPE__tSatisfied:
		{
			Fep__Satisfied *_m = (void*)msg;
			_l = snprintf(result, _e, "id=%"PRIu64, _m->id);
			_value_or_nullS(_m, result, message, _l, _e);
			break;
		}
	default:
		snprintf(result, sizeof(result), "-");
	}

	xsyslog(LOG_DEBUG, "%s{%s? %s}", head, packet_type_to_name(type), result);
}

