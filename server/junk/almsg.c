/* vim: ft=c ff=unix fenc=utf-8
 * file: almsg.c
 */
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "almsg.h"

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

/*
 * копирует string в target с разворачиванием
 * специальных символов ('\\' в "\\\\", '\n' в "\\\n")
 * и добавлением завершающего '\n'
 *
 * предпологается что target имеет размер, подходящий для
 * вмещения развёрнутого string
 *
 * возвращает количество записанных байт
 */
static inline size_t
_expand_keyval(char *target, char *string, size_t len)
{
	size_t si = 0u;
	size_t ti = 0u;
	for (; si < len; si++, ti++) {
		if (string[si] == '\n' || string[si] == '\\') {
			target[ti++] = '\\';
		}
		target[ti] = string[si];
	}
	target[ti++] = '\n';
	return ti;
}

/*
 * принимает строку (string) и длину строки (*len)
 * возвращает успех операции и изменнённую строку (string),
 * текущую длину строки (*len) и количество символов, попавших под
 * обрезание (*special)
 */
static inline bool
_normalize_keyval(char *string, size_t *len, size_t *special, bool is_static)
{
	size_t _spec_out = 0u;
	size_t _len_out = *len;
	size_t i = 0u;
	size_t ir = 0u;
	size_t ib = 0u;
	char last = '\0';

	for (; i < _len_out; i++) {
		if (/* обрезание двойных бекслешей */
			(string[i] == '\\' && last == '\\')
			/* обрезание экранированного переноса */
			|| (string[i] == '\n' && last == '\\')) {

			/* выполнять перенос только по специальному запросу */
			if (!is_static) {
				/* сдвиг строки на один символ влево */
				for (ir = i, ib = --i; ir < _len_out; ir++, ib++) {
					string[ib] = string[ir];
				}

				/* махинации над счётчиками */
				_len_out--;
				last = '\0';

				/* и нолик, на всякий случай */
				string[_len_out] = '\0';
			}
			/* счётчик спецсимволов */
			_spec_out++;
		} else if (
				/* костыль для учёта одинарных бекслешей и
				 * сиротливых переносов строк
				 */
				string[i] == '\n' ||
				(string[i] != '\\' && last == '\\')) {
			/* тот же самый костыль, что и для одинарных бекслешей */
			_spec_out++;
		} else {
			last = string[i];
		}
	}
	*len = _len_out;
	if (special)
		*special = _spec_out;

	return true;
}

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
almsg_remove(struct almsg_parser *p, const char *key, size_t key_len, size_t i)
{
	struct almsg_node *np;
	struct almsg_node *fp = NULL;
	struct almsg_node *lp = NULL;
	uint32_t hash = hash_pjw((char*)key, key_len);
	size_t n;
	bool r = false;

	for (np = p->first, n = 0u; np; np = fp) {
		fp = np->next;
		if (np->key_hash == hash) {
			if (n == i || i == ALMSG_ALL) {
				if (np->key)
					free(np->key);
				if (np->val)
					free(np->val);
				memset(np, 0u, sizeof(struct almsg_node));
				free(np);
				r = true;

				if (p->first == np) {
					p->first = fp;
				}
				if (p->last == np) {
					p->last = lp;
				}
			}
			n++;
		} else {
			lp = np;
		}
	}

	return r;
}

bool
almsg_destroy(struct almsg_parser *p)
{
	struct almsg_node *np;

	/* освобождение узлов и прочего */
	for (np = p->first, p->last = NULL; np; np = p->first) {
		p->first = np->next;
		/* чистка всякой херни */
		if (np->key)
			free(np->key);
		if (np->val)
			free(np->val);
		/* удаление текущей ноды */
		memset(np, 0u, sizeof(struct almsg_node));
		free(np);
	}

	if (p->t.unparsed)
		free(p->t.unparsed);

	if (p->p.tkey)
		free(p->p.tkey);
	if (p->p.tval)
		free(p->p.tval);

	/* зануление структуры */
	memset(p, 0u, sizeof(struct almsg_parser));
	return true;
}

/* get */
const char*
almsg_get(struct almsg_parser *p, const char *key, size_t key_len, size_t i)
{
	struct almsg_node *np;
	size_t n;
	uint32_t hash = hash_pjw((char*)key, key_len);

	for (np = p->first, n = 0u; np; np = np->next) {
		if (np->key_hash == hash) {
			if (n == i || i == ALMSG_ALL) {
				return np->val;
			}
			n++;
		}
	}
	return NULL;
}

size_t
almsg_count(struct almsg_parser *p, const char *key, size_t key_len)
{
	struct almsg_node *np;
	size_t n = 0u;
	uint32_t hash = hash_pjw((char*)key, key_len);

	for (np = p->first, n = 0u; np; np = np->next) {
		if (np->key_hash == hash) {
			n++;
		}
	}
	return n;
}

/* set */
bool
almsg_add(struct almsg_parser *p,
		const char *key, size_t key_len,
		const char *val, size_t val_len)
{
	struct almsg_node *np;
	size_t special;

	np = calloc(1, sizeof(struct almsg_node));
	if (np) {
		np->key = calloc(1, key_len + 1);
		np->val = calloc(1, val_len + 1);
	}

	if (!np || (!np->key || !np->val)) {
		if (np) {
			if (np->key)
				free(np->key);
			if (np->val)
				free(np->val);
			free(np);
		}
		p->p.err = ALMSG_E_MEM;
		return false;
	}

	np->key_len = key_len;
	np->val_len = val_len;

	memcpy(np->key, key, key_len);
	memcpy(np->val, val, val_len);

	_normalize_keyval(np->val, &np->val_len, &special, true);

	/* key + ': ' + val + special + '\n' */
	np->data_size = (np->key_len + 2) + (np->val_len + special + 1);
	p->data_size += np->data_size;

	if (p->last) {
		p->last->next = np;
		p->last = np;
	} else {
		p->last = p->first = np;
	}

	return false;
}

/* feel */
#if 0
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
#endif

/* parse */
bool
almsg_parse_buf(struct almsg_parser *p, const char *buf, size_t size)
{
	size_t i = 0u;
	size_t s = 0u;
begin_parse:
	/* 1. выделить ключ */
	if (!p->p.tkey) {
		for (i = 0u; i < size; i++, p->p.pos++) {
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
				p->p.tkey_len = p->t.unparsed_size + i;
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
		s = i;
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
				/* и нужно отбросить весь unparsed */
				if (p->t.unparsed_size) {
					p->t.unparsed_size = 0u;
					free(p->t.unparsed);
					p->t.unparsed = NULL;
				}
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
				memcpy(&p->p.tval[p->t.unparsed_size], &buf[s], i - s);
				/* убираем лишние символы для мультилайна */
				if (p->t.multiline) {
					p->p.tval_len = p->t.unparsed_size + i - s - 2;
				} else {
					p->p.tval_len = p->t.unparsed_size + i - s;
				}
				p->p.tval[p->p.tval_len] = '\0';
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
		/* значение не собралось */
		if (!p->p.tval) {
			/* выходим, сообщая что готовы жрать следующую порцию */
			return _realloc_unparsed(p, &buf[s], size - s);
		}
	}
	/* 3. сбор ключей и значений */
	{
		size_t special = 0u;
		struct almsg_node *tn = calloc(1, sizeof(struct almsg_node));
		if (!tn) {
			p->p.err = ALMSG_E_MEM;
			return false;
		}
		tn->key_len = p->p.tkey_len;
		tn->val_len = p->p.tval_len;
		tn->key = p->p.tkey;
		tn->val = p->p.tval;
		tn->key_hash = hash_pjw(tn->key, tn->key_len);
		_normalize_keyval(tn->val, &tn->val_len, &special, false);

		/* key + ': ' + val + special + '\n' */
		tn->data_size = (tn->key_len + 2) + (tn->val_len + special + 1);
		p->data_size += tn->data_size;

		if (p->last) {
			p->last->next = tn;
			p->last = tn;
		} else {
			p->last = p->first = tn;
		}
		p->p.tkey = NULL;
		p->p.tval = NULL;
	}
	/* 4. дообработка хвоста */
	if (i != size) {
		/* обновляем позции в буфере и переходим в начало */
		buf += s;
		size -= s;
		goto begin_parse;
	}

	return true;
}

bool
almsg_format_buffer(struct almsg_parser *p, char **buf, size_t *size)
{
	char *out = NULL;
	struct almsg_node *pn = NULL;
	size_t filled = 0u;
	if (!buf || !size) {
		p->p.err = ALMSG_E_ARGS;
		return false;
	}

	*buf = NULL;
	*size = 0u;

	if (!p->first) {
		return true;
	}

	out = calloc(1, p->data_size + 1);
	if (!out) {
		p->p.err = ALMSG_E_MEM;
		return false;
	}

	for (pn = p->first; pn; pn = pn->next) {
		memcpy(&out[filled], pn->key, pn->key_len);
		filled += pn->key_len;
		out[filled++] = ':';
		out[filled++] = ' ';
		filled += _expand_keyval(&out[filled], pn->val, pn->val_len);
	}

	*buf = out;
	*size = filled;

	return true;
}

