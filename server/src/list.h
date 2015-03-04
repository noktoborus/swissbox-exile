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
bool list_free_node(struct listNode *node, void(*data_free)(void*));
bool list_free_root(struct listRoot *root, void(*data_free)(void*));

#endif /* _SRC_LIST_1425461835_H_ */

