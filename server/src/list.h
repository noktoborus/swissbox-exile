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


/* колбек для сравнения узлов
 * list_d: значение из списка
 * id: идентификатор узла
 * cb_d: пользовательский эталон для сравнения
 *
 */
typedef bool(*list_cmp_cb)(void *list_d, uint64_t id, void *cb_d);
typedef void(*list_free_cb)(void*);

bool list_alloc(struct listRoot *root, uint64_t id, void *data);
/* поиск по id */
struct listNode *list_find(struct listRoot *root, uint64_t id);
/* поиск "устаревших" узлов */
struct listNode *list_find_old(struct listRoot *root, time_t sec);
/* поиск по значению
 * cmp: процедура для сравнения значений
 * *cb_d: данные, передающиеся вторым аргументом в cmp()
 */
struct listNode *list_find_val(struct listRoot *root,
		list_cmp_cb cmp, void *cb_d);
/* освобождение узла из списка */
bool list_free_node(struct listNode *node, list_free_cb data_free);
/* отчистка всех узлов */
bool list_free_root(struct listRoot *root, list_free_cb data_free);
/* обновление времени "рождения" узла */
bool list_reborn_node(struct listNode *node);

#endif /* _SRC_LIST_1425461835_H_ */

