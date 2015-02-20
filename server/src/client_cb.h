/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client_cb.h
 */
#ifndef _SRC_CLIENT_CB_1424358244_H_
#define _SRC_CLIENT_CB_1424358244_H_
#include "main.h"
#include "client_iterate.h"
#include <sys/time.h>

bool c_auth_cb(struct client *c, uint64_t id, unsigned int msgtype, void *msg, void *data);
bool c_pong_cb(struct client *c, uint64_t id,
		unsigned int msgtype, Fep__Pong *msg, struct timeval *data);

#endif /* _SRC_CLIENT_CB_1424358244_H_ */

