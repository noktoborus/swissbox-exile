/* vim: ft=c ff=unix fenc=utf-8
 * file: src/callback.c
 */
#include "callback.h"


size_t
cb_store_chunk(void *data, size_t size, struct bus_result *br)
{

	if (!data) {
		/* финализация */
		xsyslog(LOG_INFO, "IDKFA");
		free(br);
		return size;
	}
	xsyslog(LOG_INFO, "IDDQD");
	return size;
}

