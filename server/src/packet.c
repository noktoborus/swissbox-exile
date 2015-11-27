/* vim: ft=c ff=unix fenc=utf-8
 * file: src/packet.c
 */

#include <stdio.h>
#include <inttypes.h>

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

void
packet2syslog(const char *head,
		unsigned type, const void *msg,
		enum packet_verbose v)
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

