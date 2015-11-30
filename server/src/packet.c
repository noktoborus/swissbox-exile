/* vim: ft=c ff=unix fenc=utf-8
 * file: src/packet.c
 */

#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>

#include "junk/utils.h"
#include "junk/xsyslog.h"
#include "proto/fep.pb-c.h"
#include "packet.h"
#include "client_iterate.h"

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

/*static enum packet_verbose _packet_verbose[FEP__TYPE__t_max];*/

#define PACKET_NAME_LEN 16
static const struct packet_info {
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

bool
packet_name_to_type(char *in, unsigned *type, enum packet_verbose *flags)
{
	char *e = in;
	char _name_lower[PACKET_NAME_LEN + 1] = {0};
	size_t len = 0u;
	uint64_t hash;

	*flags = PACKET_NONE;
	memset(_name_lower, 0u, sizeof(_name_lower));

	if ((e = strchr(e, ':')) == NULL) {
		strncpy(_name_lower, in, sizeof(_name_lower));
	} else {
		memcpy(_name_lower, in, MIN(e - in, PACKET_NAME_LEN));
		/* разбор флагов */
		do {
			e++;
			if (!strncmp(e, PSIZE(":hex"))) {
				*flags |= PACKET_HEX;
			} else if (!strncmp(e, PSIZE(":field"))) {
				*flags |= PACKET_FIELD;
			}
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
packet_verbose(const char *packet_string, enum packet_action a)
{
	char *b = NULL;
	char *c = strdup(packet_string);
	if (!c) {
		xsyslog(LOG_WARNING,
				"packet2syslog error: strdup() failed: %s",
				strerror(errno));
		return;
	}

	/* обработка всего массива */
	while ((b = strrchr(c, ',')) != NULL) {
		*b = '\0';
	}
	/* обрабатываем хвост */

}


void
packet2syslog(const char *head,
		unsigned type, const void *msg)
{
	char result[4096];
	size_t _l = 0u;
	size_t _e = sizeof(result);

	switch (type) {
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
					_m->id, _m->rootdir_guid, _m->directory_guid);

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
	default:
		snprintf(result, sizeof(result), "-");
	}

	xsyslog(LOG_DEBUG, "%s{%s? %s}", head, Fepstr(type), result);
}

