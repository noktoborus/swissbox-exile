/* vim: ft=c ff=unix fenc=utf-8
 * file: squeue/squeue.c
 */
#include "squeue.h"
#include "junk/xsyslog.h"

#include <pthread.h>
#include <string.h>

struct squeue_data {
	unsigned long id;
	void *data;

	void (*data_free)(void*);

	unsigned readed;

	struct squeue_data *next;
	struct squeue_data *prev;
};

/* отчистка от старых записей */
static void
_squeue_sanitary(struct squeue *q)
{
	unsigned long min = (unsigned long)-1;
	/* сначала нужно найти минимальный id */
	{
		register struct squeue_cursor *c;
		for (c = q->c; c; c = c->next) {
			if (c->last_id < min) {
				min = c->last_id;
			}
		}
	}
	/* теперь нужно вычистить по списку всё, что меньше этого id */
	{
		register struct squeue_data *n;
		register struct squeue_data *f;
		n = q->n;
		while (n) {
			if (n->id < min && n->readed == q->ref) {
				/* подлежит удалению если количество прочитавших соотвествует
				 */
				f = n;
			}
			n = n->next;
			/* удаление лишних узлов */
			if (f) {
				/* выход из списка */
				if (f->next)
					f->next->prev = f->prev;
				if (f->prev)
					f->prev->next = f->next;
				if (q->n == f)
					q->n = f->next ? f->next : f->prev;
				/* отчистка структуры */
				if (f->data_free)
					f->data_free(f->data);
				q->count--;
				free(f);
				f = NULL;
			}
		}
	}
}

bool
squeue_init(struct squeue *q)
{
	memset(q, 0u, sizeof(struct squeue));
	return true;
}

bool
squeue_destroy(struct squeue *q)
{
	/* в общем-то всё, что можем: сделать чистку очереди
	 * и сообщить что есть ещё узлы
	 */
	_squeue_sanitary(q);
	if (q->ref) {
		xsyslog(LOG_WARNING, "squeue %p has refs: %u", (void*)q, q->ref);
		return false;
	}
	return true;
}

bool
squeue_subscribe(struct squeue *q, struct squeue_cursor *c)
{
	memset(c, 0, sizeof(struct squeue_cursor));
	c->root = q;
	c->root->ref++;
	/* добавляем в начало списка */
	if ((c->next = c->root->c) != NULL)
		c->root->c->prev = c;
	/* и назначем текущее значение генератора id */
	c->last_id = c->root->gen_id;
	return true;
}

void
squeue_unsubscribe(struct squeue_cursor *c)
{
	if (!c || !c->root)
		return;
	pthread_mutex_lock(&c->root->lock);
	c->root->ref--;
	/* вычленение из списка */
	if (c->next)
		c->next->prev = c->prev;
	if (c->prev)
		c->prev->next = c->next;
	if (c->root->c == c)
		c->root->c = c->next ? c->next : c->prev;
	/* отчистка памяти от всякой ерунды */
	_squeue_sanitary(c->root);
	pthread_mutex_unlock(&c->root->lock);
	memset(c, 0u, sizeof(struct squeue_cursor));
}

static struct squeue_data *
_squeue_append(struct squeue *q, void *data, void(*data_free)(void*))
{
	struct squeue_data *n;
	/* выполняем чистку перед тем, как положить
	 * т.к. нельзя удалять сообщения сразу после query()
	 */
	_squeue_sanitary(q);

	n = calloc(1, sizeof(struct squeue_data));
	if (!n)
		return false;
	/* инкрементируем счётчик и присваиваем значение новому члену */
	n->id = ++(q->gen_id);
	n->data = data;
	n->data_free = data_free;
	/* вклячивание в список */
	if ((n->next = q->n) != NULL) {
		n->next->prev = n;
	}
	q->n = n;
	q->count++;
	return n;
}

bool
squeue_send(struct squeue *q, void *data, void(*data_free)(void*))
{
	struct squeue_data *n = NULL;
	pthread_mutex_lock(&q->lock);
	/* если слушателей нет, то добавлять нет смысла */
	if (!q->ref)
		return false;
	n = _squeue_append(q, data, data_free);
	pthread_mutex_unlock(&q->lock);
	return n != NULL;
}

bool
squeue_put(struct squeue_cursor *c, void *data, void(*data_free)(void*))
{
	struct squeue_data *n = NULL;
	pthread_mutex_lock(&c->root->lock);
	n = _squeue_append(c->root, data, data_free);
	pthread_mutex_unlock(&c->root->lock);
	return n != NULL;
}

void *
squeue_query(struct squeue_cursor *c)
{
	pthread_mutex_lock(&c->root->lock);
	if (c->current == NULL) {
		struct squeue_data *n;
		/* если подписчик не получал сообщения раньше
		 * или как-то дошёл до конца списка
		 */
		for (n = c->root->n; n; n = n->next) {
			if (n->id > c->last_id)
				c->current = n;
		}
		if (c->current) {
			c->last_id = c->current->id;
		}
	} else {
		/* отмечаем как прочтённый после того, перешли к следующему узлу */
		c->current->readed++;
		/* если подписчик всё ещё в тренде
		 * движемся в сторону предыдущих, потому что новые элементы
		 * добавляются в начало списка
		 */
		if ((c->current = c->current->prev) != NULL)
			c->last_id = c->current->id;
	}
	pthread_mutex_unlock(&c->root->lock);
	return c->current ? c->current->data : NULL;
}

/* "быстрая" проверка на наличие новых сообщений
 * без локов, как повезёт
 */
bool
squeue_has_new(struct squeue_cursor *c)
{
	if (!c->root)
		return false;
	return c->last_id < c->root->gen_id;
}

unsigned
squeue_count_subscribers_c(struct squeue_cursor *c)
{
	return c ? (c->root ? c->root->ref : 0u) : 0u;
}

unsigned
squeue_count_subscribers(struct squeue *q)
{
	return q ? q->ref : 0u;
}

