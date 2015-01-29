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

#define _XS_STR(x) #x
#define XS_STR(x) _XS_STR(x)

#define xsyslog(level, ...) \
	syslog(level, "[" __FILE__ ":" XS_STR(__LINE__) "] "  __VA_ARGS__)


#endif /* _XSYSLOG_1407962058_H_ */

