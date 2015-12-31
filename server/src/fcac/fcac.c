/* vim: ft=c ff=unix fenc=utf-8
 * file: fcac/fcac.c
 */
#include <sys/stat.h>

#include "fcac.h"
#include "junk/xsyslog.h"
#include <sys/types.h>
#include <stdarg.h>
#include <libgen.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static inline bool
_lock(struct fcac *r, struct fcac_node *n)
{
	/* FIXME: добавить обязательный лок и необязательный
	 * при необязательном выполняетс mutex_trylock вместо mutex_lock()
	 */
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

/*
 * формирование пути файла на основе его id
 * base: базовый путь к кешу
 * dst и dstlen: массив и максимальный размер массива для
 *  полученного значения
 * id: идентификатор файла
 */
static size_t
_format_filename(const char *base, char *dst, size_t dstlen, uint64_t id)
{
	int rval = 0;

	if (!base) {
		base = "fcac_data";
	}

	if ((rval = snprintf(dst, dstlen, "%s/%"PRIu64, base, id)) < 0) {
		xsyslog(LOG_WARNING,
				"fcac error[id#%"PRIu64"]: snprintf() failed",
				id);
		rval = 0;
	}

	return (size_t)rval;
}

static inline void
_fcac_node_unlink(struct fcac *r, struct fcac_node *n)
{
	if (r->next == n) {
		r->next = (n->next ? n->next : n->prev);
	}
	if (n->next) {
		n->next->prev = n->prev;
	}
	if (n->prev) {
		n->prev->next = n->next;
	}
}

static void
_fcac_node_remove(struct fcac *r, struct fcac_node *n)
{
	struct fcac_ptr *p = NULL;
	struct fcac_ptr *pnext = NULL;
#if FCAC_DEEPDEBUG
	xsyslog(LOG_DEBUG, "fcac remove[id#%"PRIu64"]", n->id);
#endif
	if (_lock(r, n)) {
		/* делаем все ссылки (fcac_ptr*) инвалидными */
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
			_fcac_node_unlink(r, n);
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
		}
		_unlock(r, n);
	}
	free(n);
}

/* перевод в тип file */
static bool
_fcac_to_file(struct fcac_node *n)
{
	char filepath[PATH_MAX];
	char dirpath[sizeof(filepath)];
	int fd = -1;
	size_t offset = 0u;

	if (n->type == FCAC_FILE) {
		/* вроде как желание уже исполнено, уже файл */
		return true;
	}

	_format_filename(n->r->path, filepath, sizeof(filepath), n->id);
	memcpy(dirpath, filepath, sizeof(dirpath));

	dirname(dirpath);

	if (mkpath(dirpath, S_IRWXU)) {
		xsyslog(LOG_WARNING, "fcac error[id#%"PRIu64"]: mkpath(%s) -> %s",
				n->id, dirpath, strerror(errno));
		return false;
	}

	fd = open(filepath, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		xsyslog(LOG_WARNING, "fcac error[id#%"PRIu64"]: open(%s) -> %s",
				n->id, filepath, strerror(errno));
		return false;
	}

	if (n->type == FCAC_MEMORY && n->s.memory.offset) {
		/* если оно в памяти, то нужно перетащить на диск */
		ssize_t _wr;
		if ((_wr = write(fd, n->s.memory.buf, n->s.memory.offset)) == -1) {
			xsyslog(LOG_WARNING,
					"fcac error[id#%"PRIu64"]:"
					" migration write(%"PRIuPTR") -> %s",
					n->id,
					n->s.memory.offset, strerror(errno));
			close(fd);
			unlink(filepath);
			return false;
		}

		offset += _wr;
		if (_wr != n->s.memory.offset) {
			/* на всякий случай делаем две попытки произвести запись,
			 * возвращаем ошибку, в случае неудачи
			 */
			size_t __s;
			xsyslog(LOG_WARNING,
					"fcac error[id#%"PRIu64"]:"
					" writed %"PRIdPTR", expected %"PRIuPTR", retry",
					n->id, _wr, n->s.memory.offset);
			__s = n->s.memory.offset - _wr;
			if ((_wr = write(fd, n->s.memory.buf + _wr, __s)) == -1) {
				xsyslog(LOG_WARNING,
						"fcac error[id#%"PRIu64"]:"
						" migration write(%"PRIuPTR") -> %s",
						n->id, __s, strerror(errno));
				close(fd);
				unlink(filepath);
				return false;
			}
			/* FIXME: по нормальному это нужно как-то разнести по libev loop */
			offset += _wr;
			if (_wr != __s) {
				xsyslog(LOG_WARNING,
						"fcac error[id#%"PRIu64"]:"
						" writed %"PRIdPTR", expected %"PRIuPTR", exit",
						n->id, _wr, n->s.memory.offset);
				unlink(filepath);
				return false;
			}
		}
		free(n->s.memory.buf);
	}
	/* инициализация значений */
	n->type = FCAC_FILE;
	n->s.file.offset = offset;
	n->s.file.fd = fd;

	return true;
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
	r->mem_block_size = 32768;
	xsyslog(LOG_INFO,
			"fcac init %s thread safe", (thread_safe ? "with" : "without"));
	return true;
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
			xsyslog(LOG_INFO,
					"fcac[config]: set max_mem_size to %ld bytes", _size);
		}
		break;
	case FCAC_MAX_MEM_BLOCKS:
		{
			long _blocks = va_arg(ap, long);
			r->mem_block_max = (size_t)_blocks;
			xsyslog(LOG_INFO,
					"fcac[config]: set max_mem_blocks to %ld", _blocks);
		}
		break;
	case FCAC_PATH:
		{
			char *_path = va_arg(ap, char*);
			long _len = va_arg(ap, long);
			if (_path == NULL || _len <= 0) {
				xsyslog(LOG_WARNING,
						"fcac error[config]: invalid path (ptr=%p, len=%lu)",
						(void*)_path, _len);
				break;
			}
			r->path = calloc(1, _len + 1);
			if (!r->path) {
				xsyslog(LOG_WARNING,
						"fcac error[config]:"
						" path not allocated: calloc(%ld) -> %s",
						_len, strerror(errno));
				rval = false;
				break;
			}
			memcpy(r->path, _path, _len);
			r->path_len = (size_t)_len;
			xsyslog(LOG_INFO, "fcac[config]: set path to '%s'", _path);
		}
		break;
	case FCAC_TIME_EXPIRE:
		{
			time_t _time = va_arg(ap, time_t);
			if (!_time) {
				xsyslog(LOG_WARNING,
						"fcac error[config]:"
						" FCAC_TIME_EXPIRE value must be != NULL");
				rval = false;
				break;
			}
			/* паранойя: вдруг time_t страшная структура? */
			memcpy(&r->expire, &_time, sizeof(time_t));
			xsyslog(LOG_INFO,
					"fcac[config]: set time_expire to %llu seconds",
					(long long unsigned)_time);
		}
		break;
	case FCAC_MEM_BLOCK_SIZE:
		{
			unsigned long _size = va_arg(ap, unsigned long);
			if (_size <= 1) {
				xsyslog(LOG_WARNING,
						"fcac error[config]:"
						" set(FCAC_MEM_BLOCK_SIZE)"
						" value must be > 1 (obtain: %lu)", _size);
				rval = false;
				break;
			}
			r->mem_block_size = (size_t)_size;
			xsyslog(LOG_INFO,
					"fcac[config]: set mem_block_size to %lu bytes", _size);
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
		struct fcac_node *_next = NULL;
		for (_n = r->next; _n; _n = _next) {
			_next = _n->next;
			_fcac_node_remove(r, _n);
		}

	}

	/* дестрой локов */
	if (r->thread_safe) {
		if (!pthread_mutex_trylock(&r->lock)) {
			pthread_mutex_unlock(&r->lock);
		} else {
			xsyslog(LOG_WARNING,
					"fcac error[destroy]:"
					" lock already taken, wait and destroy");
			if (!pthread_mutex_lock(&r->lock)) {
				pthread_mutex_unlock(&r->lock);
			} else {
				xsyslog(LOG_WARNING,
						"fcac error[destroy]:"
						" lock destroy error: %s", strerror(errno));
			}
			/* не получилось захватить? Ну и ладно, всё равно крушим. */
			pthread_mutex_destroy(&r->lock);
		}
	}

	if (r->path)
		free(r->path);

	memset(r, 0, sizeof(*r));
	return true;
}

/* *** */

bool
fcac_open(struct fcac *r, uint64_t id, struct fcac_ptr *p, enum fcac_options o)
{
	int fd = -1;
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

	if (o & FCAC_PREFERRED_FILE && o & FCAC_PREFERRED_MEMORY) {
		xsyslog(LOG_WARNING,
				"fcac error: "
				"open with PREFERRED_FILE && PREFERRED_MEMORY not allowed");
		return false;
	}

	if (o & FCAC_AFTER_FILE && o & FCAC_AFTER_MEMORY) {
		xsyslog(LOG_WARNING,
				"fcac error: "
				"open with AFTER_FILE && AFTER_MEMORY not allowed");
		return false;
	}

	/* feature */
	if (o & FCAC_PREFERRED_MEMORY || o & FCAC_AFTER_MEMORY) {
		xsyslog(LOG_WARNING,
				"fcac warning: "
				"PREFERRED_MEMORY && AFTER_MEMORY not supported now");
	}

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
		struct stat st = {0};
		char _path[PATH_MAX] = {0};
		_format_filename(r->path, _path, sizeof(_path), id);

		if (!stat(_path, &st) && !(st.st_mode & S_IWUSR)) {
			if ((fd = open(_path, O_RDONLY)) == -1) {
				xsyslog(LOG_WARNING,
						"fcac error[id#%"PRIu64"]: open(%s) -> %s",
						id, _path, strerror(errno));
			}
		}
	}

	/* создание нового узла */
	if (!n) {
#if FCAC_DEEPDEBUG
		xsyslog(LOG_DEBUG, "fcac create[id#%"PRIu64"]", id);
#endif
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
		n->id = id;
		n->options = o;

		if (fd != -1) {
			r->statistic.hit_fs++;
			n->type = FCAC_FILE;
			n->finalized = true;
		} else {
			r->statistic.miss++;
		}
	}

	/* подключение ссылки */
	memset(p, 0, sizeof(*p));
	p->n = n;
	p->r = n->r;
	p->fd = fd;
	p->id = n->id;

	/* вход в список */
	n->ref_count++;
	if ((p->next = n->ref)) {
		if (n->ref->prev) {
			/* FIXME: не должно быть узлов левее начала? */
			n->ref->prev->next = p;
			p->prev = n->ref->prev;
		}
		if (n->ref->next)
			n->ref->next->prev = p;
	}
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
		if (!_lock(p->r, p->n)) {
			return false;
		}
		/* обновляем время */
		time(&p->n->last);
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

		_unlock(p->r, p->n);
	}
	if (p->fd != -1) {
		if (close(p->fd)) {
			xsyslog(LOG_WARNING, "fcac close error: close(%d) -> %s",
					p->fd, strerror(errno));
		}
		p->fd = -1;
	}

	if (_lock(p->r, NULL)) {
		p->r->statistic.closed_ptr++;
		_unlock(p->r, NULL);
	}
	return true;
}

enum fcac_ready
fcac_is_ready(struct fcac_ptr *p)
{
	enum fcac_ready rval = FCAC_CLOSED;
	/* FIXME: нужна ли здесь блокировка?
	 * даже при обращении к указателю может возникнуть ситуация
	 * в которой p->n будет в неизвестном состоянии
	 * (если операции присвоения значения не атомарны)
	 */

	if (p->fd != -1) {
		/* если у нас уже есть захваченный ресурс, то лезть
		 * в глубины нет смысла
		 */
		return FCAC_READY;
	}

	if (!p->n) {
		/* вероятнее что у нас FCAC_MEMORY или FCAC_UNKNOWN
		 * и структура отвались, потому возвращаем
		 * FCAC_CLOSED
		 */
		return FCAC_CLOSED;
	}

	if (!_lock(p->r, p->n))
		return FCAC_NO_READY;

	if (!p->n->finalized || p->n->type == FCAC_UNKNOWN) {
		/* вообще, если вдруг p->n->finalized */
		rval = FCAC_NO_READY;
	} else {
		rval = FCAC_READY;
		/* структура готова, можно подключаться к ней */
		if (p->n->type == FCAC_MEMORY) {
			/* сделать ссылку на область */
			p->offset = 0u;
		} else if (p->n->type == FCAC_FILE) {
			p->offset = 0u;
			char _path[PATH_MAX] = {0};
			_format_filename(p->r->path, _path, sizeof(_path), p->n->id);
			/* открыть файл или дюпнуть дескриптор */
			if ((p->fd = open(_path, O_RDONLY)) == -1) {
				rval = FCAC_NO_READY;
				xsyslog(LOG_WARNING,
						"fcac error[id#%"PRIu64":%p]:"
						" open(%s) -> %s",
						p->id, (void*)p,
						_path, strerror(errno));
			}
		}
	}
	_unlock(p->r, p->n);

	return rval;
}


size_t
fcac_read(struct fcac_ptr *p, uint8_t *buf, size_t size)
{
	/* файловый дескриптор как приватный ресурс
	 * с чтением из памяти сложнее, должен ссылаться
	 */
	bool remove = false;

	if (p->fd != -1) {
		/* если файловый дескриптор уже готовый, то игнорируем всё,
		 * читаем по нему
		 */
		ssize_t _r = 0;
		lseek(p->fd, p->offset, SEEK_SET);
		if ((_r = read(p->fd, buf, size)) == -1) {
			/* чтение завершилось неудачно, освобождаем ресурс */
			xsyslog(LOG_WARNING, "fcac error[id#%"PRIu64":%p]:"
					" read fd#%d failed: %s",
					p->id, (void*)p,
					p->fd, strerror(errno));
			close(p->fd);
			p->fd = -1;
			/* дропаем порченую ноду */
			_fcac_node_remove(p->r, p->n);
			return 0;
		} else {
			/* TODO: временный костыль */
			close(p->fd);
			p->fd = -1;
			/* TODO: */
			p->offset += (size_t)_r;
			return (size_t)_r;
		}
	} else {
		size_t _r = 0u;
		/* проверка типа узла и чтение из памяти
		 * необходимо выставлять локи и прочее
		 */
		if (!_lock(p->r, p->n))
			return false;

		if (p->n->type == FCAC_MEMORY) {
			/* всё остальные типы нас не инетересуют
			 * попасть сюда с типом FCAC_FILE не должны,
			 * как и с FCAC_UNKNOWN (отсеивается на стадии fcac_is_ready())
			 */
			if (p->n->s.memory.offset < p->offset) {
				xsyslog(LOG_WARNING, "fcac error[id#%"PRIu64":%p]:"
						" memory pointer invalid,"
						" have size: %"PRIuPTR", wanted offset: %"PRIuPTR,
						p->id, (void*)p,
						p->n->s.memory.size, p->offset);
			} else {
				_r = p->n->s.memory.offset - p->offset;
				_r = MIN(_r, size);
				memcpy(buf, p->n->s.memory.buf + p->offset, _r);
				p->offset += _r;
			}
		} else if (p->n->type == FCAC_FILE) {
			/* попали сюда с p->fd == -1, нужно переоткрыть */
			char _path[PATH_MAX] = {0};
			_format_filename(p->r->path, _path, sizeof(_path), p->id);
			if ((p->fd = open(_path, O_RDONLY)) != -1) {
				/* попытка чтения номер два */
				_r = fcac_read(p, buf, size);
			} else {
				/* несчастье, удаляем ноду, закрываемся */
				xsyslog(LOG_WARNING,
						"fcac error[id#%"PRIu64":%p]:"
						" read reopen failed: %s",
						p->id, (void*)p, strerror(errno));
				remove = true;
			}

		}

		_unlock(p->r, p->n);
		 /* предпологаем что ошибка чтения будет происходить по всему
		  * приложению и закрываем чтение другим указателям
		 */
		if (remove)
			_fcac_node_remove(p->r, p->n);
		return _r;
	}
}

bool
fcac_set_ready(struct fcac_ptr *p)
{
	bool rval = false;

	if (!p->n)
		return false;

	if (_lock(p->r, p->n)) {
		if (p->n->type != FCAC_UNKNOWN) {
			/* если тип всё ещё FCAC_UNKNOWN,
			 * то ни какой готовность быть не может
			 */
			p->n->finalized = true;
			rval = true;
		}
		if (p->n->type == FCAC_MEMORY && p->n->options & FCAC_AFTER_FILE) {
			if (!_fcac_to_file(p->n))
				return false;
		}
		if (p->n->type == FCAC_FILE) {
			char _path[PATH_MAX] = {0};
			_format_filename(p->r->path, _path, sizeof(_path), p->n->id);
			/* закрытие дескрипторов */
			close(p->n->s.file.fd);
			p->n->s.file.fd = -1;
			/* финализация файлов в кеше заключается в удалении флага "u+w" */
			if (chmod(_path, S_IRUSR)) {
				xsyslog(LOG_WARNING,
						"fcac error[id#%"PRIu64":%p]: finalization failed: %s",
						p->n->id, (void*)p, strerror(errno));
			}
			/* даже если финализация не прошла,
			 * то файл всё равно записан и можно сейчас продолжать
			 * читать его
			 */
			p->n->finalized = true;
			rval = true;
		}
		_unlock(p->r, p->n);
	}
	return rval;
}

size_t
fcac_write(struct fcac_ptr *p, uint8_t *buf, size_t size)
{
	size_t max_count = 0u;
	size_t max_size = 0u;
	size_t count = 0u;
	size_t block_size = 0u;

	size_t rval = 0u;
	bool allow = true;

	if (!_lock(p->r, p->n)) {
		return 0u;
	}

	if (p->n->finalized) {
		xsyslog(LOG_WARNING,
				"fcac error[id#%"PRIu64":%p]:"
				" write to finalized structure",
				p->id, (void*)p);
		_unlock(p->r, p->n);
		return 0u;
	}

	if (_lock(p->r, NULL)) {
		/* кеширование полезных значений
		 * при блокировке узла происходит освобождение корня,
		 * потому нужно ещё раз заблокировать корень
		 * FIXME: слишком много блокировок
		 */
		max_count = p->r->mem_count_max;
		max_size = p->r->mem_block_max;
		block_size = p->r->mem_block_size;
		count = p->r->count;
		_unlock(p->r, NULL);

		/* проверка значений */
		if (p->n->type == FCAC_UNKNOWN) {
			/* подготовка, выбор типа */
			if (!(p->n->options & FCAC_PREFERRED_FILE)
					&& (!max_size || size <= max_size)
					&& (!count || count < max_count)) {
				p->n->type = FCAC_MEMORY;
#if FCAC_DEEPDEBUG
				xsyslog(LOG_DEBUG,
						"fcac write[id#%"PRIu64"]: set type to memory",
						p->id);
#endif
			} else {
				allow = _fcac_to_file(p->n);
#if FCAC_DEEPDEBUG
				xsyslog(LOG_DEBUG,
						"fcac write[id#%"PRIu64"]: set type to file",
						p->id);
#endif
			}
		} else if (p->n->type == FCAC_MEMORY) {
			/* проверка на выход за допустимые значения */
			if (p->n->s.memory.offset + size > max_size) {
				allow = _fcac_to_file(p->n);
#if FCAC_DEEPDEBUG
				xsyslog(LOG_DEBUG,
						"fcac write[id#%"PRIu64"]: migrate type to file",
						p->id);
#endif
				if (_lock(p->r, NULL)) {
					p->r->statistic.deserter++;
					_unlock(p->r, NULL);
				}
			}
		}
	}

	if (allow) {
		/* инициализация записи прошла, осталось произвести запись */
		if (p->n->type == FCAC_FILE) {
			/* если дескриптор закрыли, то его нужно вновь открыть */
			if (p->n->s.file.fd == -1) {
				char filepath[PATH_MAX];
				_format_filename(p->r->path, filepath, sizeof(filepath), p->id);
				if ((p->n->s.file.fd = open(filepath, O_RDWR | O_APPEND)) == -1) {
					xsyslog(LOG_WARNING,
						"fcac error[id#%"PRIu64"]: write reopen failed: %s",
						p->id, strerror(errno));
					allow = false;
				}
				/* на всякий случай меняем положение курсора */
				lseek(p->n->s.file.fd, p->n->s.file.offset, SEEK_SET);
			}
			if (allow) {
				/* с файлом всё просто */
				ssize_t _wr = 0;
				if ((_wr = write(p->n->s.file.fd, buf, size)) == -1) {
					xsyslog(LOG_WARNING,
							"fcac error[id#%"PRIu64":%p]:"
							" write(%"PRIuPTR") -> %s",
							p->id, (void*)p, size, strerror(errno));
				} else {
					rval = (size_t)_wr;
					p->n->s.file.offset += rval;
				}
				/* TODO: временный костыль */
				close(p->n->s.file.fd);
				p->n->s.file.fd = -1;
				/* TODO: */
			}
		} else if (p->n->type == FCAC_MEMORY) {
			/* для памяти нужно выделить кусок и положить туда */
			if (p->n->s.memory.offset + size > p->n->s.memory.size) {
				uint8_t *_t = NULL;
				size_t _s;
				/* расчёт будущего размера
				 * сначала выясняем количество необходимых блоков
				 */
				_s = ((p->n->s.memory.offset + size) / block_size) + 1;
				/* и вычисляем размер блока под данные */
				if ((_s *= block_size) > max_size && max_size) {
					/* если размер, вычесленный блоками больше максимального
					 * размера, то подрезаем
					 */
					_s = max_size;
				}
				_t = realloc(p->n->s.memory.buf, _s);
				if (!_t) {
					xsyslog(LOG_WARNING,
							"fcac error[id#%"PRIu64":%p]:"
							" realloc(%"PRIuPTR") -> %s",
						    p->id, (void*)p, _s, strerror(errno));
				} else {
					p->n->s.memory.buf = _t;
					p->n->s.memory.size = _s;
					/* длина записываемых данных
					 * может оказаться чуть короче, чем планировалось
					 */
					_s = _s - p->n->s.memory.offset;
					rval = MIN(_s, size);
					memcpy(&p->n->s.memory.buf[p->n->s.memory.offset], buf, rval);
					p->n->s.memory.offset += rval;
				}
			} else {
				rval = size;
				memcpy(&p->n->s.memory.buf[p->n->s.memory.offset], buf, rval);
				p->n->s.memory.offset += rval;
			}
		}
	}
	_unlock(p->r, p->n);

	if (!allow) {
		/* т.к. нам не разрешили запись, то нужно дропнуть
		 * узел, ничего сделать дальше не сможем
		 */
		_fcac_node_remove(p->r, p->n);
	}

	return rval;
}

bool
fcac_tick(struct fcac *r)
{
	struct fcac_node *n = NULL;
	struct fcac_node *_n = NULL;
	time_t curtime = 0;
	bool tofree = false;
	if (!r) {
		return false;
	}

	/* нет смысла получать время, если таймаут не назначен */
	if (r->expire) {
		time(&curtime);
	}

	if (!_lock(r, NULL))
		return false;
	/* нужно обойти все узлы и проверить что там с ними */
	for (n = r->next; n; n = _n) {
		_n = n->next;
		tofree = false;
		/* не нужно делать серьёзный лок, только пробуем */
		if (!pthread_mutex_trylock(&n->lock)) {
			if (!n->ref_count) {
				/* если !r->expire, то разреференный узел освобождаем сразу же
				 * или освобождаем если время истекло
				 */
				if (!r->expire ||
						(r->expire &&
						 (time_t)difftime(curtime, n->last) > r->expire)) {
#if FCAC_DEEPDEBUG
					xsyslog(LOG_DEBUG,
							"fcac tick[id#%"PRIu64"]: expired", n->id);
#endif
					tofree = true;
				}
			}
			/* для следующих операций требуется разлочиться */
			pthread_mutex_unlock(&n->lock);
			if (tofree) {
				/* FIXME: слишком много lock/unlock
				 * для разделения времени использования между тредами
				 * это может и хорошо, но во всех других случаях
				 * получается около 6 лишних mutex_lock/mutex_unlock
				 */
				_unlock(r, NULL);
				_fcac_node_remove(r, n);
				_lock(r, NULL);
			}
		}
	}

	_unlock(r, NULL);
	return true;
}

bool
fcac_opened(struct fcac_ptr *p)
{
	if (p) {
		if (p->fd != -1 || p->n || p->next || p->prev)
			return true;
	}

	return false;
}

#if 0
bool
fcac_claw(struct fcac *r, struct fcac_ptr *p, uint64_t id)
{
	struct fcac_node *n = NULL;
	struct fcac *or = NULL;

	/* старый корень */
	or = p->r;

	if (or == r) {
		if (p->id == id) {
			/* пытается перенести к самому себе -- выполнено? */
			return true;
		}
		/* если id не совпадает, то нужно или его менять или давать отлуп */
		return false;
	}

	/* блокируем корень-приёмник */
	if (!_lock(r, NULL)) {
		return false;
	}

	/* 1. удостоверяемся что нет такого id в списке */
	for (n = r->next; n; n = n->next) {
		if (n->id == id) {
			xsyslog(LOG_WARNING,
					"fcac warning[id#%"PRIu64"]: "
					"already exists at migration (from id#%"PRIu64")",
					id, p->id);

			_unlock(r, NULL);
			return false;
		}
	}


	/* 2. отцепить от старого корня */
	if (!_lock(or, NULL))
		return false;
	_fcac_node_unlink(or, p->n);
	p->n->r = NULL;
	_unlock(or, NULL);

	/* 3. прицепить к новому корню */
	if (!_lock(or

	/* 4. передёрнуть все ссылки */


	return true;
}
#endif
