/* vim: ft=c ff=unix fenc=utf-8
 * file: squeue/squeue.h
 */
#ifndef _SQUEUE_SQUEUE_1435045130_H_
#define _SQUEUE_SQUEUE_1435045130_H_

#include <stdlib.h>
#include <stdbool.h>

struct squeue;
struct squeue_cursor;


bool squeue_init(struct squeue *q);
bool squeue_destroy(struct squeue *q);

bool squeue_subscribe(struct squeue *q, struct squeue_cursor *c);
void squeue_unsubscribe(struct squeue_cursor *c);


bool squeue_put(struct squeue_cursor *c, void *data, void(*data_free)(void*));
void *squeue_query(struct squeue_cursor *c);
bool squeue_has_new(struct squeue_cursor *c);


#endif /* _SQUEUE_SQUEUE_1435045130_H_ */

