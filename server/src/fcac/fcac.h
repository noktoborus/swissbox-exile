/* vim: ft=c ff=unix fenc=utf-8
 * file: fcac/fcac.h
 */
#ifndef _FCAC_FCAC_1447326016_H_
#define _FCAC_FCAC_1447326016_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

/* запрос к кешу только по id файла (location_id в bd) */

/* ключи для fcac_set() */
enum fcac_key {
	/* ключ */
	FCAC_KEY = 0,
	/* наибольший размер блока узла данных в памяти
	 * при превышении узел меняет тип на "файл",
	 * аргументы:
	 * 	long size
	 */
	FCAC_MAX_MEM_SIZE = 1,
	/*
	 * максимальное количество узлов типа "память",
	 * при привышении новые узлы создаются с типом "файл",
	 * аргументы:
	 *  long blocks
	 */
	FCAC_MAX_MEM_BLOCKS = 2,
	/*
	 * путь к файловому кешу
	 * аргументы:
	 *  char *path, long len
	 */
	FCAC_PATH = 3,
	/*
	 * через сколько секунд считать структуру устаревшей
	 * (после последнего закрытия)
	 * аргументы:
	 *  time_t *time
	 */
	FCAC_TIME_EXPIRE = 4,
	/*
	 * размер размечаемого блока памяти для записи в FCAC_MEMORY
	 * на это значение каждый раз увеличивается буфер,
	 * но не более FCAC_MAX_MEM_SIZE
	 * аргументы:
	 *  unsigned long size
	 */
	FCAC_MEM_BLOCK_SIZE = 5
};

enum fcac_type {
	FCAC_UNKNOWN = 0,
	FCAC_MEMORY = 1,
	FCAC_FILE = 2
};

struct fcac_ptr {
	struct fcac_node *n;

	int fd;
	size_t offset;

	struct fcac_ptr *prev;
	struct fcac_ptr *next;
};

struct fcac_node {
	enum fcac_type type;
	bool finilized;

	time_t last;

	uint64_t id;

	union {
		struct {
			uint8_t *buf;
			size_t offset;
			size_t size;
		} memory;
		struct {
			int fd;
			char *path;
			size_t offset;
		} file;
	} s;

	/* количество ссылок и ссписок ссылок */
	size_t ref_count;
	struct fcac_ptr *ref;

	struct fcac *r;
	struct fcac_node *next;
	struct fcac_node *prev;

	pthread_mutex_t lock;
};

struct fcac {
	/* максимальное количество хранимых элементов в памяти */
	size_t mem_count_max;
	/* максимальный размер элемента в памяти */
	size_t mem_block_max;
	/* размер начального размера и размера блока для реалокации
	 * при записи в FCAC_MEMORY */
	size_t mem_block_size;
	/* учёт тухлятины */
	time_t expire;
	/* путь к файловому кешу */
	char *path;
	size_t path_len;


	/* cчётчик узлов */
	size_t count;
	/* узлы */
	struct fcac_node *next;

	/* включена ли потокобезопасность */
	bool thread_safe;

	/* статистика */
	struct {
		/* общий счётчик открытых структур */
		uint64_t opened_ptr;
		/* счётчик закрытых структур */
		uint64_t closed_ptr;
		/* попадания в созданные узлы типа "memory" */
		uint64_t hit_mem;
		/* попадания в созданные узлы типа "file" */
		uint64_t hit_cached_fs;
		/* попадания в "пустые" (не заполненные) узлы */
		uint64_t hit_cached_unk;
		/* попадания в файловый кеш */
		uint64_t hit_fs;
		/* создание новых узлов */
		uint64_t miss;
		/* изменившие с типа "memory" на тип "file" */
		uint64_t deserter;
	} statistic;

	pthread_mutex_t lock;
};

/*
 * последовательность следующая:
 * 1. открытие элемента: fcac_open()
 * 2. проверка готовности: fcac_ready()
 * 3. чтение элемента: fcac_read()
 * 4. закрытие узла: fcac_close()
 */

/* *** инициализация/деинициализация */

/*
 * инициализация с потокобезопасностью и без неё
 * потокобезопасный режим включает в себя использование
 * pthread_mutex_lock/pthread_mutex_unlock,
 * что создаёт некоторые ненужные тормоза в
 * предварительно потокобезопасной среде
 */
bool fcac_init(struct fcac *r, bool thread_safe);
/*
 * управление параметрами очереди,
 * дополнительные аргументы указаны в fcac_key
 */
bool fcac_set(struct fcac *r, enum fcac_key key, ...);

/*
 * переодический обход списка для вычистки устаревших стктур
 */
bool fcac_tick(struct fcac *r);

/* закрытие узла
 * все указатели (fcac_ptr) становятся штатно невалидными
 */
bool fcac_destroy(struct fcac *r);

/* *** общее */

/* открытие узла (результат в *ptr)
 * true при успехе,
 * false при неудаче
 */
bool fcac_open(struct fcac *r, uint64_t id, void *data, struct fcac_ptr *p);
/* закрытие узла */
bool fcac_close(struct fcac_ptr *p);

/* *** чтение */

/* проверка готовности на чтения узла кеша */
enum fcac_ready{
	/* готово к чтению */
	FCAC_READY = 0,
	/* не готово к чтению */
	FCAC_NO_READY = 1,
	/* не готово и узел в кеше умер (кривой указатель?) */
	FCAC_CLOSED = 2,
};
enum fcac_ready fcac_is_ready(struct fcac_ptr *p);

/* чтение узла в буфер buf */
size_t fcac_read(struct fcac_ptr *p, uint8_t *buf, size_t size);

/* *** запись и прочее */

/* назначение элемента завершённым */
bool fcac_set_ready(struct fcac_ptr *p);

/* запись в узел, запись возможна только перед fcac_set_ready() */
size_t fcac_write(struct fcac_ptr *p, uint8_t *buf, size_t size);

#endif /* _FCAC_FCAC_1447326016_H_ */

