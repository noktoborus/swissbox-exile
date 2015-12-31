/* vim: ft=c ff=unix fenc=utf-8
 * file: main.h
 */
#ifndef _MAIN_1422961154_H_
#define _MAIN_1422961154_H_

#include "curlev/curlev.h"
#include "list.h"
#include "junk/xsyslog.h"
#include "junk/almsg.h"
#include "proto/fep.pb-c.h"
#include "squeue/squeue.h"

#include <hiredis/hiredis.h>
#include <hiredis/adapters/libev.h>

#include <confuse.h>

#include <ev.h>
#include <stdbool.h>
#include <pthread.h>

#include "fcac/fcac.h"

#define SPQ_DEFAULT_POOLSIZE 3

struct evptr {
	union {
		struct ev_io io;
		struct ev_async async;
	} e;
	struct sev_ctx *cev;
};

/* по 1МБ на буфер */
#define SEV_RECV_BUF 1024 * 1024
#define SEV_SEND_BUF 1024 * 1024

#define SEV_LOG "06"PRIuPTR

/* в буфере отправки есть данные */
#define SEV_ACTION_READ 1
/* буфер чтения свободен */
#define SEV_ACTION_WRITE 2
/* событие на выход из треда */
#define SEV_ACTION_EXIT 4

struct sev_ctx
{
	/* io */
	struct ev_loop *loop;
	struct ev_io io;
	struct ev_async async;
	struct ev_timer timer;

	/* ссылка на main->ev_lock */
	pthread_mutex_t *ev_lock;

	struct { /* буфер чтения */
		pthread_mutex_t lock;
		uint8_t *buf;
		size_t size; /* размер буфера */
		size_t len; /* длина данных в буфере */
		bool eof;
	} recv;

	struct { /* буфер записи */
		pthread_mutex_t lock;
		uint8_t *buf;
		size_t size;
		size_t len;
		bool eof;
	} send;

	struct main *pain;
	struct sev_main *sev;

	uint8_t action;
	pthread_mutex_t cev_lock;
	pthread_t thread;

	/* указатель на приватные данные потока */
	void *p;

	/* оче
	 * событие на пополнение: SEV_ACTION_INPUT
	 */
	struct squeue bus_inqueue;

	/* список id запросов к шине, если при получении ответа в шине
	 * желаемого id нет в списке, значит запрос считается невалидным
	 * содержит в себе указатель на pain->bus_task[n]
	 */
	struct listRoot bus_wanted;
	/* генератор id для шины */
	uint64_t bus_idgen;

	time_t recv_timeout;
	time_t send_timeout;

	int fd;

	bool isfree;

	size_t serial;

	struct sev_ctx *prev;
	struct sev_ctx *next;
};

/* server socket */
struct sev_main
{
	ev_io evio;

	int fd;

	char *host;
	char *port;

	struct main *pain;
	struct sev_ctx *client;

	struct sev_main *prev;
	struct sev_main *next;
};

/* olo */
struct redis_c {
	size_t self;
	uint32_t msghash;
	redisAsyncContext *ac;
	bool connected;

	pthread_mutex_t x;

	struct main *pain;
};

#define	REDIS_C_MAX 5
struct main
{
	ev_signal sigint;
	ev_signal sigterm;
	ev_signal sigpipe;
	ev_timer watcher;
	ev_async alarm;

	/* helgrind предпологает что обращение к сигналированию
	 * из тредов может быть опасным
	 */
	pthread_mutex_t ev_lock;

	/* подключение к редису
	 * нулевое подключение используется для подписок (SUBSCRIBE)
	 */
	struct redis_c rs[REDIS_C_MAX];
	pthread_cond_t rs_wait;
	pthread_mutex_t rs_lock;
	size_t rs_awaits;

	/* работа с курлом */
	struct curlev cuev;

	/* синхронизатор для работы со списками */
	pthread_mutex_t sev_lock;
	/* server list */
	struct sev_main *sev;

	/* автобусные задачи
	 * структура: (id, client_ptr)
	 */
	struct listRoot bus_task;

	/* файловый кеш */
	struct fcac fcac;

	/* конфигурашка и прочее */
	cfg_t *cfg;
	char *a_basename;
	/* параметры */
	struct {
		char *name;
		char *redis_chan;
		char *cache_dir;
		char *pidfile;
		char *user;
		char *group;

		long pg_poolsize;
		char *bindline;
		char *packet_verbose;
		char *pg_connstr;
		cfg_bool_t log_failed_queries;

		cfg_bool_t unique_device_id;
	} options;

};

/* сообщение-ответ для клиента */
enum bus_inq_type {
	/* ответ драйвера */
	BUSINQ_DRIVER = 1,
	BUSINQ_SAMPLE = 10
};

struct bus_inq_message {
	/* TODO */
	enum bus_inq_type type;
	void *data;
	union {
		struct {
			/* отправка driver
			 * происходит два раза:
			 * с success = True, loaded = False
			 * success = True, loaded = True
			 * в случае неудачи success == false
			 */
			/* запрос был успешен */
			bool success;
			/* загружен ли файл */
			bool loaded;
		} driver;
		struct {
			char a;
		} sample;
	} s;
};

struct bus_result {
	/* указатель на клиентский тред */
	struct sev_ctx *cev;
	size_t cev_serial;
	uint64_t cev_bus_id;
	/* данные для треда клиента */
	void *data;
	/* */
};

typedef enum direction
{
	/* в любую сторону, нужно осторожно использовать в циклах */
	DANY = 0,
	/* только в правую сторону */
	DRIGHT,
	/* только в левую сторону */
	DLEFT
} direction_t;

/*
 * void *ctx == struct sev_ctx
 * вовзращает 0, если время ожидания ответа было достигнуто
 * и -1 если произошла ошибка при чтении
 */
int sev_send(struct sev_ctx *cev, const unsigned char *buf, size_t len);
int sev_recv(struct sev_ctx *cev, unsigned char *buf, size_t len);
/*
 * проверка возможности совершения действия
 * SEV_ACTION_READ или SEV_ACTION_WRITE
 */
bool sev_perhaps(struct sev_ctx *cev, int action);
/* пропуск ожидания событий
 * например, для быстрой чтения из сокетов без ущерба
 * для обработки другиъ событий
 */
bool sev_continue(struct sev_ctx *cev);

/* отправка сообщения по шине дальше клиенту */
bool cev_bus_result(struct sev_ctx *cev,
		uint64_t bus_id, struct bus_inq_message *b);

/* возвращает структуру клиента по его serial или NULL, если не найден */
struct sev_ctx *cev_by_serial(struct main *pain, size_t serial);

/* запрос к шине, возвращает номер запроса в очереди
 * если вернуло 0, значит запрос неудался
 */
uint64_t bus_query(struct sev_ctx *cev, struct almsg_parser *a, void *data);
/* отмена запроса к шине, указывается номер запроса */
bool bus_cancel(struct sev_ctx *cev, uint64_t id);

bool redis_t(struct main *pain, const char *cmd, const char *ch,
		const char *data, size_t size);
void almsg2redis(struct main *pain, const char *cmd, const char *chan,
		struct almsg_parser *alm);

/* информации о версии */
const char *const sev_version_string();


/* вход для аллокации клиентской структуры
 * результат этой процедуры будет передаваться в аргументе void *p
 */
void *client_begin(struct sev_ctx *cev);

/* основная точка входа клиента */
bool client_iterate(struct sev_ctx *cev, void *p);

/* освобождение памяти под клиентские структуры */
void client_end(struct sev_ctx *cev, void *p);

/* точка входа для обработки очереди */
void client_bus_input(struct sev_ctx *cev, void *p);


#endif /* _MAIN_1422961154_H_ */

