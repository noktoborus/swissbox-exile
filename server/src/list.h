/* vim: ft=c ff=unix fenc=utf-8
 * file: src/list.h
 */
#ifndef _SRC_LIST_1425461835_H_
#define _SRC_LIST_1425461835_H_
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

struct listRoot {
	size_t count;
	struct listNode *next;
};

struct listNode {
	void *data;
	uint64_t id;

	struct timeval born;

	struct listNode *next;
	struct listNode *prev;
	struct listRoot *root;
};

bool list_alloc(struct listRoot *root, uint64_t id, void *data);
struct listNode *list_find(struct listRoot *root, uint64_t id);
struct listNode *list_find_old(struct listRoot *root, time_t sec);
bool list_free_node(struct listNode *node, void(*data_free)(void*));
bool list_free_root(struct listRoot *root, void(*data_free)(void*));
/* обновление времени "рождения" узла */
bool list_reborn_node(struct listNode *node);

#endif /* _SRC_LIST_1425461835_H_ */

