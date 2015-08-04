/* vim: ft=c ff=unix fenc=utf-8
 * file: almsg.h
 *
 *
 * smtp-like message parser/formatter
 * all lines must be terminated by symbol '\n'
 * *** Example key-val:
 * Key: value
 *
 * *** multiline key-val:
 * key2: -
 * multi-line
 * value
 * .
 * key3: line1\
 * line2\
 * line3
 *
 * *** empty value with key:
 * key3:
 *
 * *** array key:
 * Key: value1
 * Key: value2
 * Key: value3
 *
 */
#ifndef _ALMSG_1438677124_H_
#define _ALMSG_1438677124_H_
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include "utils.h"

struct almsg_node {
	uint32_t key_hash;
	char *key;
	size_t key_len;
	char *val;
	size_t val_len;
	struct almsg_node *next;
};

#define ALMSG_KEY_MAX 128
#define ALMSG_VAL_MAX 1024

#define ALMSG_E_MEM 1
#define ALMSG_E_KEYSIZE 2
#define ALMSG_E_VALSIZE 3

struct almsg_parser {

	struct {
		int err;

		size_t pos;

		char *tkey;
		char *tval;
	} p;

	struct {
		char *unparsed;
		size_t unparsed_size;

		char penult;
		char lasts;
		bool multiline;
		bool dirty;
	} t;

	struct almsg_node *first;
	struct almsg_node *last;
};

/* инициализация, сброс состояния и деинициализация
 */
bool almsg_init(struct almsg_parser *p);
bool almsg_reset(struct almsg_parser *p);
bool almsg_destroy(struct almsg_parser *p);

/*
 * false если достигнут конец файла или произошла ошибка во время разбора
 */
bool almsg_parse_stream(struct almsg_parser *p, int stream);
bool almsg_parse_file(struct almsg_parser *p, FILE *file);

/*
 * false если произошла ошибка во время разбора
 *
 * можно использовать для потока
 */
bool almsg_parse_buf(struct almsg_parser *p, const char *buf, size_t size);

/*
 * false если невозможно сформировать буфер
 */
bool almsg_format_buffer(struct almsg_parser *p, char **buf, size_t *size);

/*
 * получение значения по ключу
 * после выполнения almsg_reset и almsg_destroy все указатели становятся
 * не валидными
 *
 * возвращает NULL в случае не нахождения ключа
 *
 * аргумент i служит для указания элемента массива
 */
const char *almsg_get(struct almsg_parser *p, const char *key, size_t i);

/*
 * получение количества вхождений элементов с ключём key
 */
size_t almsg_count(struct almsg_parser *p, const char *key);

const char *almsg_errstr(struct almsg_parser *p);

#endif /* _ALMSG_1438677124_H_ */

