/* vim: ft=c ff=unix fenc=utf-8
 * file: src/as3/as3.h
 */
#ifndef _SRC_AS3_AS3_1436863715_H_
#define _SRC_AS3_AS3_1436863715_H_

#include "junk/guid.h"

#include <stdbool.h>
#include <string.h>

bool as3_auth(char *path, char *name, char *secret, uint64_t device_id);

#endif /* _SRC_AS3_AS3_1436863715_H_ */

