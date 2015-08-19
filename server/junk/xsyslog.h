/* vim: ft=c ff=unix fenc=utf-8
 * file: xsyslog.h
 */
#ifndef _XSYSLOG_1407962058_H_
#define _XSYSLOG_1407962058_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <inttypes.h>
#include <errno.h>

#include "utils.h"

#define _XS_STR(x) #x
#define XS_STR(x) _XS_STR(x)

#define xsyslog(level, ...) \
	syslog(level, "[" __FILE__ ":" XS_STR(__LINE__) "] "  __VA_ARGS__)

/* example:
 *
 * uint32_t hash = 0u;
 * xsyslogs(LOG_INFO, &hash, "foo %s", "bar");
 */
#define xsyslogs(level, hash, ...) \
	{\
		char __log_buf[4096];\
		uint32_t __log_hash = 0u;\
		snprintf(__log_buf, sizeof(__log_buf), __VA_ARGS__);\
		__log_hash = hash_pjw(__log_buf, strlen(__log_buf));\
		if (__log_hash != *hash) {\
			*hash = __log_hash;\
			snprintf(__log_buf, sizeof(__log_buf),\
					"["__FILE__":"XS_STR(__LINE__)"] " __VA_ARGS__);\
			syslog(level, __log_buf);\
		}\
	}

#endif /* _XSYSLOG_1407962058_H_ */
