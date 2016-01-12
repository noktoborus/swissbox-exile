/* vim: ft=c ff=unix fenc=utf-8
 * file: src/list.h
 */
#ifndef _SRC_LIST_1425461835_H_
#define _SRC_LIST_1425461835_H_
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

struct listRoot {
	size_t count;
	struct listNode *next;
	struct listNode *last;

	/* генератор внутренних идентификаторов */
	uint64_t rid_gen;
	/*
	 * время последнего обновления (добавления/удаления узлов)
	 */
	struct timeval updated_at;
};

struct listNode {
	void *data;

	/* внутренний идентификатор, учавствует в поиске
	 * предпологается что идентификаторы,
	 * сгенерированные вне библиотеки могут иметь случайные значения,
	 * что не подходит для последовательной итерации
	 */
	uint64_t rid;

	/* "пользовательский" идентификатор */
	uint64_t id;

	struct listNode *next;
	struct listNode *prev;
	struct listRoot *root;
};


/*
 * предпологается что все указатели будут прибиты до того,
 * как будет прибит корень
 */
struct listPtr {
	/* указатель на root */
	struct listRoot *r;
	/* указатель на узел */
	struct listNode *n;
	/* идентификатор узла */
	uint64_t rid;
	/* метка, по которой определяется целостность указателей */
	struct timeval updated_at;
};

/* колбек для сравнения узлов
 * list_d: значение из списка
 * id: идентификатор узла
 * cb_d: пользовательский эталон для сравнения
 *
 */
typedef bool(*list_cmp_cb)(void *list_d, uint64_t id, void *cb_d);
typedef void(*list_free_cb)(void*);

/*
 * можно хранить сообщения с id == 0
 * в таком случае list_find() всегда возвращает NULL
 *
 */
bool list_alloc(struct listRoot *root, uint64_t id, void *data);


/* прикрепление указателя поиска к списку,
 * освобождение производить не требуется,
 * но предпологается что после освобождения корня
 * использоваться указатели не будут
 */
bool list_ptr(struct listRoot *root, struct listPtr *ptr);
/* поиск по id, при id == 0, всегда возвращается NULL */
struct listNode *list_find(struct listPtr *p, uint64_t id);
/* поиск по значению
 * cmp: процедура для сравнения значений
 * *cb_d: данные, передающиеся вторым аргументом в cmp()
 */
struct listNode *list_find_val(struct listPtr *p, list_cmp_cb cmp, void *cb_d);
/* освобождение узла из списка */
bool list_free_node(struct listNode *node, list_free_cb data_free);
/* отчистка всех узлов */
bool list_free_root(struct listRoot *root, list_free_cb data_free);

#endif /* _SRC_LIST_1425461835_H_ */

