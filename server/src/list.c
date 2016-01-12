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
	struct listPtr lp = {0};

	if (!root)
		return false;

	list_ptr(root, &lp);
	if (list_find(&lp, id)) {
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

	ln->rid = ++root->rid_gen;
	ln->id = id;

	if (root->next) {
		ln->next = root->next;
		root->next->prev = ln;
	} else {
		root->last = ln;
	}
	gettimeofday(&root->updated_at, NULL);

	root->count++;
	root->next = ln;
	ln->root = root;

	ln->data = data;

	return true;
}

bool
list_free_node(struct listNode *node, list_free_cb data_free)
{
	if (!node)
		return false;

	if (node->root) {
		gettimeofday(&node->root->updated_at, NULL);
		node->root->count--;
		if (node->root->next == node) {
			node->root->next = node->next;
		}
		if (node->root->last == node) {
			node->root->last = node->prev;
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
list_free_root(struct listRoot *root, list_free_cb data_free)
{
	if (!root || !root->next)
		return NULL;
	return list_free_node(root->next, data_free);
}

bool
list_ptr(struct listRoot *root, struct listPtr *ptr)
{
	if (!ptr)
		return false;
	memset(ptr, 0, sizeof(*ptr));
	if (!(ptr->r = root))
		return false;
	return true;
}

static inline struct listNode *
_list_find(struct listPtr *p, uint64_t id, list_cmp_cb cmp, void *cb_d)
{
	struct listNode *rval = NULL;
	/* поиск не выполняется если id == 0 */
	if (!p || !p->r || !p->r->next || !id)
		return NULL;

	/* поиск с самого начала выполняется при условии что
	 * p->updated_at != p->r->updated_at
	 */
	if (memcmp(&p->updated_at, &p->r->updated_at, sizeof(struct timeval))) {
		/* копируем значение отметки */
		memcpy(&p->updated_at, &p->r->updated_at, sizeof(struct timeval));
		for (rval = p->r->last; rval; rval = rval->prev) {
			/* в указатели должно быть только положительное значение,
			 * даже если оно не корректное
			 */
			p->n = rval;
			/* отсеивание по rid имеет смысл только
			 * в том случае, если выполняется поиск не по id, а по
			 * значению
			 *
			 * чем дальше от корня - тем младше значения
			 * и нам нужно пропустить последнее найденное
			 */
			if (p->rid >= p->n->rid) {
				continue;
			}
			/* сдвигаем идентификатор пройденных узлов
			 *
			 * идентификатор нужен для того, что бы можно было найти
			 * последний узел в случае изменения списка
			 */
			p->rid = p->n->rid;
			/* сравнение */
			if (cmp) {
				if (cmp(rval->data, rval->id, cb_d)) {
					break;
				}
			} else if (p->n->id == id) {
				break;
			}
		}
	} else if (p->n) {
		/*
		 * поиск имеет смысл продолжать только если
		 * есть указатель на узел
		 * В жизни такой ситуации не должно возникнуть
		 * если метка совпадает, то и указатель на узел должен
		 * быть действительным всегда
		 *
		 * начинаем сразу со следующего узла
		 */
		for (rval = p->n->prev; rval; rval = rval->prev) {
			p->n = rval;
			p->rid = rval->rid;
			if (cmp) {
				if (cmp(rval->data, rval->id, cb_d)) {
					break;
				}
			} else if (p->n->id == id) {
				/* при выходе из цикла получаем валидный указатель */
				break;
			}
		}
	}
	return rval;
}

struct listNode *
list_find(struct listPtr *p, uint64_t id)
{
	return _list_find(p, id, NULL, NULL);
}

struct listNode *
list_find_val(struct listPtr *p, list_cmp_cb cmp, void *cb_d)
{
	return _list_find(p, 0u, cmp, cb_d);
}

