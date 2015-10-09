/* vim: ft=c ff=unix fenc=utf-8
 * file: src/list.c
 */
#include "list.h"
#include "junk/xsyslog.h"
#include <errno.h>
#include <sys/time.h>
#include <string.h>

bool
list_alloc(struct listRoot *root, uint64_t id, void *data)
{
	struct listNode *ln;

	if (!root)
		return false;

	if (list_find(root, id)) {
#if DEEPDEBUG
		xsyslog(LOG_DEBUG, "list: attemp to add exists id: %"PRIu64, id);
#endif
		return false;
	}

	ln = calloc(1, sizeof(struct listNode));
	if (!ln) {
		xsyslog(LOG_WARNING, "list: memory fail for id %"PRIu64": %s",
				id, strerror(errno));
		return false;
	}

	ln->id = id;
	if (gettimeofday(&ln->born, NULL) != 0) {
		xsyslog(LOG_WARNING, "list: gettimeofday() error: %s", strerror(errno));
		return false;
	}


	if (root->next) {
		ln->next = root->next;
		root->next->prev = ln;
	}
	root->count++;
	root->next = ln;
	ln->root = root;

	ln->data = data;

	return true;
}

struct listNode *
list_find(struct listRoot *root, uint64_t id)
{
	struct listNode *ln;
	if (!root || !root->next)
		return NULL;

	for (ln = root->next; ln; ln = ln->next) {
		if (ln->id == id)
			return ln;
	}

	return NULL;
}

bool
list_free_node(struct listNode *node, void(*data_free)(void*))
{
	if (!node)
		return false;

	if (node->root) {
		node->root->count--;
		if (node->root->next == node) {
			node->root->next = node->next;
		}
	}

	if (node->next)
		node->next->prev = node->prev;

	if (node->prev)
		node->prev->next = node->next;

	if (node->data && data_free) {
		data_free(node->data);
	}

	/* для пущести */
	memset(node, 0, sizeof(struct listNode));
	free(node);
	return true;
}

bool
list_free_root(struct listRoot *root, void(*data_free)(void*))
{
	if (!root || !root->next)
		return NULL;
	return list_free_node(root->next, data_free);
}

struct listNode *
list_find_old(struct listRoot *root, time_t sec)
{
	struct listNode *ln;
	struct timeval tv;
	if (gettimeofday(&tv, NULL) != 0) {
		xsyslog(LOG_WARNING, "list: gettimeofday() error: %s", strerror(errno));
		return false;
	}

	if (!root || !root->next)
		return NULL;

	for (ln = root->next; ln; ln = ln->next) {
		if (ln->born.tv_sec - tv.tv_sec > sec) {
			return ln;
		}
	}
	return NULL;
}

bool
list_reborn_node(struct listNode *node)
{
	if (!node)
		return false;

	if (gettimeofday(&node->born, NULL) != 0) {
		xsyslog(LOG_WARNING, "list: gettimeofday() error: %s", strerror(errno));
		return false;
	}
	return true;
}

