/* vim: ft=c ff=unix fenc=utf-8
 * file: squeue/squeue.h
 */
#ifndef _SQUEUE_SQUEUE_1435045130_H_
#define _SQUEUE_SQUEUE_1435045130_H_

#include <stdlib.h>
#include <stdbool.h>

struct squeue_data;

struct squeue {
	pthread_mutex_t lock;

	unsigned long gen_id;

	unsigned count;
	struct squeue_data *n;

	struct squeue_cursor *c;
	unsigned ref;
};

struct squeue_cursor {
	unsigned long last_id;

	struct squeue *root;
	struct squeue_data *current;

	struct squeue_cursor *next;
	struct squeue_cursor *prev;
};


bool squeue_init(struct squeue *q);
/* в случае наличия подписок разрушить очередь нельзя
 *
 */
bool squeue_destroy(struct squeue *q);

bool squeue_subscribe(struct squeue *q, struct squeue_cursor *c);
void squeue_unsubscribe(struct squeue_cursor *c);


/* добавление сообщения в очередь анонимным участником */
bool squeue_send(struct squeue *q, void *data, void(*data_free)(void*));
/* добавление сообщения в очередь подписанным участником */
bool squeue_put(struct squeue_cursor *c, void *data, void(*data_free)(void*));

/* освобождение данных происходит
 * внутри библиотеки при вызове squeue_put() и squeue_send()
 * а так же при squeue_destroy().
 *
 * выборка для удаления происходит по следующему алгоритму:
 * 1. удаление происходит только когда количество подписчиков совпадает
 *  с количеством прочитавших
 * 2. при получении _следующей_ структуры, предыдущая помечается как прочитанная
 *
 * FIXME: возможна ошибка при squeue_unsubscribe(), когда не прочитавших == 1
 */
void *squeue_query(struct squeue_cursor *c);

/* получение количества подписчиков по корню и из курсора */
unsigned squeue_count_subscribers(struct squeue *q);
unsigned squeue_count_subscribers_c(struct squeue_cursor *c);

bool squeue_has_new(struct squeue_cursor *c);


#endif /* _SQUEUE_SQUEUE_1435045130_H_ */

