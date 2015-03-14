/* vim: ft=c ff=unix fenc=utf-8
 * file: simplepq/simplepq.h
 */
#ifndef _SIMPLEPQ_SIMPLEPQ_1426075906_H_
#define _SIMPLEPQ_SIMPLEPQ_1426075906_H_
/*
 * менеджмент подключения к pgsql,
 * ерунда для простого выполнения запросов
 */
#include "junk/guid.h"
#include <stdbool.h>

/* открытие подключений к бд, pool -- количество подключений */
void spq_open(unsigned pool, char *pgstring);
void spq_resize(unsigned pool);
void spq_close();


bool spq_create_tables();

#endif /* _SIMPLEPQ_SIMPLEPQ_1426075906_H_ */

