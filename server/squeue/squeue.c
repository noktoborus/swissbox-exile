/* vim: ft=c ff=unix fenc=utf-8
 * file: squeue/squeue.c
 */
#include "squeue/squeue.h"
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
			if (n->id < min) {
				/* подлежит удалению если количество прочитавших соотвествует
				 *
				 * */
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
	memset(c, 0u, sizeof(struct squeue_cursor));
	pthread_mutex_unlock(&c->root->lock);
}


bool
squeue_put(struct squeue_cursor *c, void *data, void(*data_free)(void*))
{
	struct squeue_data *n;
	n = calloc(1, sizeof(struct squeue_data));
	if (!n)
		return false;
	pthread_mutex_lock(&c->root->lock);
	/* инкрементируем счётчик и присваиваем значение новому члену */
	n->id = ++(c->root->gen_id);
	n->data = data;
	n->data_free = data_free;
	/* вклячивание в список */
	if ((n->next = c->root->n) != NULL) {
		n->next->prev = n;
	}
	c->root->n = n;
	c->root->count++;
	pthread_mutex_unlock(&c->root->lock);
	return true;
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
		/* если подписчик всё ещё в тренде
		 * движемся в сторону предыдущих, потому что новые элементы
		 * добавляются в начало списка
		 */
		if ((c->current = c->current->prev) != NULL)
			c->last_id = c->current->id;
		/* и выполняем чистку */
		_squeue_sanitary(c->root);
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
	return c->last_id < c->root->gen_id;
}

