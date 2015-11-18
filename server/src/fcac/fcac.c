/* vim: ft=c ff=unix fenc=utf-8
 * file: fcac/fcac.c
 */
#include "fcac/fcac.h"
#include "junk/xsyslog.h"
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static inline bool
_lock(struct fcac *r, struct fcac_node *n)
{
	if (r->thread_safe) {
		if (!pthread_mutex_lock(&r->lock)) {
			/* если указан узел, то нужно освободить
			 * корень после блокировки узла
			 */
			if (n) {
				if (pthread_mutex_lock(&n->lock)) {
					xsyslog(LOG_WARNING, "fcac: lock node error: %s", strerror(errno));
					pthread_mutex_unlock(&r->lock);
					return false;
				}
				pthread_mutex_unlock(&r->lock);
			}
			return true;
		} else {
			xsyslog(LOG_WARNING, "fcac: lock error: %s", strerror(errno));
		}
	}
	return false;
}

static inline void
_unlock(struct fcac *r, struct fcac_node *n)
{
	if (r->thread_safe) {
		/* если указан узел, то корень не был заблокирован */
		if (n) {
			pthread_mutex_unlock(&n->lock);
		} else {
			pthread_mutex_unlock(&r->lock);
		}
	}
}

static void
_fcac_node_remove(struct fcac *r, struct fcac_node *n)
{
	struct fcac_ptr *p = NULL;
	struct fcac_ptr *pnext = NULL;
	if (_lock(r, n)) {
		for (p = n->ref; p; p = pnext) {
			pnext = p->next;
			p->n = NULL;
			/* не заморачиваемся с ссылками,
			 * просто ломаем список
			 */
			p->next = NULL;
			p->prev = NULL;
			if (p->fd != -1) {
				close(p->fd);
				p->fd = -1;
			}
		}
		/* что бы вынуть узел из списка, нужно заблокировать корень */
		if (_lock(r, NULL)) {
			if (r->next == n) {
				r->next = (n->next ? n->next : n->prev);
			}
			if (n->next) {
				n->next->prev = n->prev;
			}
			if (n->prev) {
				n->prev->next = n->next;
			}
			_unlock(r, NULL);
			/* вычистка данных и освобождение памяти */
			switch(n->type) {
				case FCAC_MEMORY:
					if (n->s.memory.buf)
						free(n->s.memory.buf);
					break;
				case FCAC_FILE:
					if (n->s.file.fd != -1)
						close(n->s.file.fd);
					break;
				default:
					break;
			}
			free(n);
		}
		_unlock(r, n);
	}
}

bool
fcac_init(struct fcac *r, bool thread_safe)
{
	if (!r)
		return false;
	memset(r, 0, sizeof(*r));
	if (thread_safe) {
		pthread_mutex_init(&r->lock, NULL);
		r->thread_safe = true;
	}
}

bool
fcac_set(struct fcac *r, enum fcac_key key, ...)
{
	bool rval = true;
	va_list ap;
	if (!_lock(r, NULL))
		return false;

	va_start(ap, key);
	switch (key) {
	case FCAC_KEY:
		break;
	case FCAC_MAX_MEM_SIZE:
		{
			long _size = va_arg(ap, long);
			r->mem_block_max = (size_t)_size;
		}
		break;
	case FCAC_MAX_MEM_BLOCKS:
		{
			long _blocks = va_arg(ap, long);
			r->mem_block_max = (size_t)_blocks;
		}
		break;
	case FCAC_PATH:
		{
			char *_path = va_arg(ap, char*);
			long _len = va_arg(ap, long);
			if (_path == NULL || _len <= 0) {
				xsyslog(LOG_WARNING,
						"fcac error: invalid path (%p, %lu)",
						(void*)_path, _len);
				break;
			}
			r->path = calloc(1, _len + 1);
			if (!r->path) {
				xsyslog(LOG_WARNING,
						"fcac error: path not allocated: calloc(%ld) -> %s",
						_len, strerror(errno));
				rval = false;
				break;
			}
			memcpy(r->path, _path, _len);
			r->path_len = (size_t)_len;
		}
		break;
	default:
		break;
	};
	va_end(ap);

	_unlock(r, NULL);
	return rval;
}

bool
fcac_destroy(struct fcac *r)
{

	xsyslog(LOG_INFO,
			"fcac statistics:"
			" opened_ptr=%"PRIu64","
			" closed_ptr=%"PRIu64","
			" hit_mem=%"PRIu64","
			" hit_cached_fs=%"PRIu64","
			" hit_cached_unk=%"PRIu64","
			" hit_fs=%"PRIu64","
			" miss=%"PRIu64","
			" deserter=%"PRIu64,
			r->statistic.opened_ptr,
			r->statistic.closed_ptr,
			r->statistic.hit_mem,
			r->statistic.hit_cached_fs,
			r->statistic.hit_cached_unk,
			r->statistic.hit_fs,
			r->statistic.miss,
			r->statistic.deserter
			);


	/* чистка списков */
	{
		struct fcac_node *_n = NULL;
		for (_n = r->next; _n; _n = _n->next) {
			_fcac_node_remove(r, _n);
		}

	}

	/* дестрой локов */
	if (r->thread_safe) {
		if (!pthread_mutex_trylock(&r->lock)) {
			pthread_mutex_unlock(&r->lock);
		} else {
			xsyslog(LOG_WARNING,
					"fcac error: lock already taken, wait and destroy");
			if (!pthread_mutex_lock(&r->lock)) {
				pthread_mutex_unlock(&r->lock);
			} else {
				xsyslog(LOG_WARNING,
						"fcac error: lock destroy error: %s", strerror(errno));
			}
			/* не получилось захватить? Ну и ладно, всё равно крушим. */
			pthread_mutex_destroy(&r->lock);
		}
	}
}

/* *** */

bool
fcac_open(struct fcac *r, uint64_t id, void *data, struct fcac_ptr *p)
{
	/*
	 * процедура выполняет только подключение к структуре данных,
	 * все необходимые инициализации (установка указателя, открытие файла)
	 * происходят в fcac_is_ready()
	 *
	 * 1. перечислить узлы в памяти на наличие запрашиваемого
	 * 2. проверить файловый кеш
	 * 3. создать новый узел
	 */
	struct fcac_node *n = NULL;

	/* одна большая блокировка, что бы не плодить кучу мелких
	 * но подумать о сегментировании блокировок
	 */
	if(!_lock(r, NULL))
		return false;

	/* поиск используемого узла */
	for (n = r->next; n; n = n->next) {
		if (n->id == id) {
			switch(n->type) {
			case FCAC_MEMORY:
				r->statistic.hit_mem++;
				break;
			case FCAC_FILE:
				r->statistic.hit_cached_fs++;
				break;
			default:
				r->statistic.hit_cached_unk++;
				break;
			}
			break;
		}
	}

	/* поиск на фс */
	if (!n) {
		/* TODO */
		/* r->statistic.hit_fs++; */

	}

	/* создание нового узла */
	if (!n) {
		n = calloc(1, sizeof(*n));
		if (!n) {
			xsyslog(LOG_WARNING, "fcac open error: calloc(%d) -> %s",
					(int)sizeof(*n), strerror(errno));
			return false;
		}
		/* встраивание в список
		 * FIXME: добавить сортировку
		 */
		if ((n->next = r->next) != NULL) {
			n->next->prev = n;
		}
		r->next = n;
		n->r = r;

		r->statistic.miss++;
	}

	/* подключение ссылки */
	memset(p, 0, sizeof(*p));
	p->n = n;
	p->fd = -1;

	/* вход в список */
	n->ref_count++;
	p->next = n->ref;
	if (n->ref->prev) {
		/* FIXME: не должно быть узлов левее начала? */
		n->ref->prev->next = p;
		p->prev = n->ref->prev;
	}
	if (n->ref->next)
		n->ref->next->prev = p;
	n->ref = p;

	n->r->statistic.opened_ptr++;
	/* выход */
	_unlock(r, NULL);
	return true;
}

bool
fcac_close(struct fcac_ptr *p)
{
	/*
	 * операция удаления fcac_node из списка совершается в fcac_tick()
	 * в этой процедуре нужно только декрементировать счётчик ссылок и закрыть
	 * лишние ресурсы
	 */
	if (!p)
		return false;

	if (p->n) {
		if (!_lock(p->n->r, p->n)) {
			return false;
		}
		/* выход из списка */
		p->n->ref_count--;
		if (p->n->ref == p) {
			p->n->ref = (p->next ? p->next : p->prev);
		}
		if (p->next)
			p->next->prev = p->prev;
		if (p->prev)
			p->prev->next = p->next;
		p->next = NULL;
		p->prev = NULL;

		_unlock(p->n->r, p->n);
	}
	if (p->fd != -1) {
		if (close(p->fd)) {
			xsyslog(LOG_WARNING, "fcac close error: close(%d) -> %s",
					p->fd, strerror(errno));
		}
		p->fd = -1;
	}

	if (_lock(p->n->r, NULL)) {
		p->n->r->statistic.closed_ptr++;
		_unlock(p->n->r, NULL);
	}
}

bool
fcac_is_ready(struct fcac_ptr *p)
{
	/* TODO */
}

