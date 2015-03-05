/* vim: ft=c ff=unix fenc=utf-8
 * file: fakedb/fakedb.c
 */
#include "fakedb.h"
#include <syslog.h>
#include <pthread.h>
#include <sys/time.h>

struct fdbCursor {
	struct fdbNode *cur;
};

struct fdbNode {
	size_t walked;
	pthread_t parent;

	void *data;
	void (*data_free)(void*);

	struct timeval borntime;
	struct fdbNode *next;
};

static struct fdb {
	bool inited;
	size_t cursors;
	struct fdbNode *first;
	struct fdbNode *last;
	pthread_mutex_t single;
} fdb;

#if 0
static uint64_t
fdb_hash(uint8_t *str, size_t len)
{
	/* pjw hash */
	uint64_t hash = 0u;
	uint64_t test = 0u;

	while (len-- > 0) {
		hash = (hash << 4) + (unsigned char)(str[len]);

		if ((test = hash & 0xf0000000) != 0) {
			hash = ((hash ^ (test >> 24)) & (0xfffffff));
		}
	}
	return hash;
}
#endif

void
fdb_open()
{
	fdb.inited = true;
	pthread_mutex_init(&fdb.single, NULL);
}

void
fdb_close()
{
}

static inline bool
_fdb_store(struct fdbCursor *c, void *data, void (*data_free)(void*))
{
	struct fdbNode *n;
	if (!c)
		return false;
	if (!(n = calloc(1, sizeof(struct fdbNode))))
		return false;

	gettimeofday(&n->borntime, NULL);
	n->data_free = data_free;
	n->data = data;
	n->parent = pthread_self();
	n->walked = 1;
	if (fdb.last) {
		fdb.last->next = n;
		fdb.last = n;
	} else if (!fdb.first) {
		fdb.first = n;
		fdb.last = n;
	} else {
		syslog(LOG_WARNING, "fdb wtf?!");
		free(n);
		return false;
	}
	return true;
}

bool
fdb_store(struct fdbCursor *c, void *data, void (*data_free)(void*))
{
	register bool r;
	pthread_mutex_lock(&fdb.single);
	r = _fdb_store(c, data, data_free);
	pthread_mutex_unlock(&fdb.single);
	return r;
}

static inline struct fdbCursor*
_fdb_cursor()
{
	struct fdbCursor *c = calloc(1, sizeof(struct fdbCursor));
	if (c) {
		c->cur = fdb.first;
		fdb.cursors++;
	}
	return c;
}

struct fdbCursor*
fdb_cursor()
{
	struct fdbCursor *r;
	pthread_mutex_lock(&fdb.single);
	r = _fdb_cursor();
	pthread_mutex_unlock(&fdb.single);
	return r;
}

static inline void*
_fdb_walk(struct fdbCursor *c)
{
	pthread_t self;

	self = pthread_self();
	do {
		if (!c->cur) {
			/* идём в рут, если курсор пустой */
			if (fdb.first)
				c->cur = fdb.first;
			else
				return NULL;
		} else if (c->cur->next) {
			/* следующий элемент списка, если есть */
			c->cur = c->cur->next;
		} else {
			break;
		}
		/* пропускаем, если запись была создана в текущим треде */
		if (c->cur->parent == self)
			continue;
		c->cur->walked++;
		return c->cur->data;
	} while (false);
	return NULL;
}

void*
fdb_walk(struct fdbCursor *c)
{
	void *r;
	pthread_mutex_lock(&fdb.single);
	r = _fdb_walk(c);
	pthread_mutex_unlock(&fdb.single);
	return r;
}


