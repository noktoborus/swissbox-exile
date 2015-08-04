/* vim: ft=c ff=unix fenc=utf-8
 * file: almsg.c
 */
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "almsg.h"

const char*
almsg_errstr(struct almsg_parser *p)
{
	if (!p)
		return strdup("Invalid parser pointer");
	return NULL;
}

/* init */
bool
almsg_init(struct almsg_parser *p)
{
	memset(p, 0u, sizeof(struct almsg_parser));
	return false;
}

bool
almsg_reset(struct almsg_parser *p)
{
	almsg_destroy(p);
	almsg_init(p);
	return true;
}

bool
almsg_destroy(struct almsg_parser *p)
{
	memset(p, 0u, sizeof(struct almsg_parser));
	return false;
}

/* get */
const char*
almsg_get(struct almsg_parser *p, const char *key, size_t i)
{
	return 0u;
}

/* feel */
bool
almsg_parse_stream(struct almsg_parser *p, int stream)
{
	return false;
}

bool
almsg_parse_file(struct almsg_parser *p, FILE *file)
{
	return false;
}

static inline bool
_realloc_unparsed(struct almsg_parser *p, const char *buf, size_t size)
{
	char *tmp = realloc(p->t.unparsed, p->t.unparsed_size + size + 1);
	if (!tmp) {
		p->p.err = ALMSG_E_MEM;
		return false;
	}
	p->t.unparsed = tmp;
	memcpy(&p->t.unparsed[p->t.unparsed_size], buf, size);
	p->t.unparsed_size += size;
	p->t.unparsed[p->t.unparsed_size] = '\0';
	return true;
}

/* parse */
bool
almsg_parse_buf(struct almsg_parser *p, const char *buf, size_t size)
{
	size_t i = 0u;
	/* 1. выделить ключ */
	if (!p->p.tkey) {
		for (; i < size; i++, p->p.pos++) {
			if (p->t.unparsed_size + i >= ALMSG_KEY_MAX) {
				/* ключ слишком длинный */
				p->p.err = ALMSG_E_KEYSIZE;
				return false;
			}
			if (buf[i] == ':') {
				p->p.tkey = calloc(1, p->t.unparsed_size + i + 1);
				if (!p) {
					p->p.err = ALMSG_E_MEM;
					return false;
				}
				if (p->t.unparsed_size)
					memcpy(p->p.tkey, p->t.unparsed, p->t.unparsed_size);
				memcpy(&p->p.tkey[p->t.unparsed_size], buf, i);
				/* обновление позиции */
				free(p->t.unparsed);
				memset(&p->t, 0u, sizeof(p->t));
				i++;
				break;
			}
		}
		/* если на предыдущем шаге не был выделен ключ,
		 * то теперь требуется обновить временный буфер
		 */
		if (!p->p.tkey) {
			/* ничего не напарсили, но работу можно всё ещё продолжать */
			return _realloc_unparsed(p, buf, size);
				return false;
		}
	}
	/* 2. выделить значение */
	if (p->p.tkey) {
		/* специальные последовательности:
		 * '-\n' переход в многострочность
		 * '.\n' завершение многострочности
		 * '\\n' многострочность
		 * '\n' завершение строки
		 */
		size_t s = i;
		/* пропускаем первые пробелы */
		for (; buf[i] == ' ' && i < size; i++, s++, p->p.pos++);
		/* ищем конец */
		for (; i < size;
				p->t.penult = p->t.lasts,
				p->t.lasts = buf[i++],
				p->p.pos++) {
			if (p->t.unparsed_size + i > ALMSG_VAL_MAX) {
				/* значение слишком длинное */
				p->p.err = ALMSG_E_VALSIZE;
				return false;
			}

			/* костыль: игнорируем двойной бекслеш */
			if (buf[i] == '\\' && p->t.lasts == '\\')
				p->t.lasts = '\0';

			if (!p->t.dirty && buf[i] == '\n'
					&& p->t.lasts == '-') {
				/* включение мультилайна и обновление начальной позиции */
				p->t.multiline = true;
				s = i + 1;
			} else if (/* перевод строки по символу '\n' без экранирования */
				(!p->t.multiline && (buf[i] == '\n' && p->t.lasts != '\\'))
					/* конец мультистроки по '\n.\n' */
					|| (p->t.multiline
						&& buf[i] == '\n'
						&& p->t.lasts == '.'
						&& p->t.penult == '\n')) {
				/* законченое значение */
				p->p.tval = calloc(1, p->t.unparsed_size + i - s + 1);
				if (!p->p.tval) {
					p->p.err = ALMSG_E_MEM;
					return false;
				}
				memcpy(p->p.tval, p->t.unparsed, p->t.unparsed_size);
				if (!p->t.multiline) {
					memcpy(&p->p.tval[p->t.unparsed_size], &buf[s], i - s);
				} else { /* копируем всё, за исключением точки */
					memcpy(&p->p.tval[p->t.unparsed_size], &buf[s], i - s - 2);
				}
				free(p->t.unparsed);
				memset(&p->t, 0u, sizeof(p->t));
				s = ++i;
				/* отсечение лишних нулей и пробелов */
				for (; (buf[i] == '\0' || buf[i] == ' ' || buf[i] == '\n')
						&& i < size;
						p->p.pos++, i++, s++);
				break;
			} else if (!p->t.multiline && (buf[i] == '\n'
						&& p->t.lasts == '\\')) {
				/* уточняем что это не первая строка */
				p->t.dirty = true;
			}
		}
		/* если в хвосте ещё остались данные или не пропарсились */
		if (!p->p.tval || i != size) {
			/* выходим только в случае, когда хвост не скопировался
			 * и не тзначения.
			 * В остальном нам ещё требуется скопировать в список
			 */
			if (!_realloc_unparsed(p, &buf[s], size - s)) {
				return false;
			} else if (!p->p.tval) {
				return true;
			}
		}
	}
	/* 3. сбор ключей и значений */
	{
		struct almsg_node *tn = calloc(1, sizeof(struct almsg_node));
		if (!tn) {
			p->p.err = ALMSG_E_MEM;
			return false;
		}
		tn->key = p->p.tkey;
		tn->val = p->p.tval;
		/* TODO: чистка массивов от двойных бекслешей (и одинарных) */
		if (p->last) {
			p->last->next = tn;
		} else {
			p->last = p->first = tn;
		}
		p->p.tkey = NULL;
		p->p.tval = NULL;
		return true;
	}
	/* n. не должны были дойти в нормальной ситуации */
	return false;
}

