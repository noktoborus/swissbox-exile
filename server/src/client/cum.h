/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client/cum.h
 */
#ifndef _SRC_CLIENT_CUM_1435139382_H_
#define _SRC_CLIENT_CUM_1435139382_H_
#include "squeue/squeue.h"
#include "src/list.h"
#include "junk/xsyslog.h"

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/* структура для коммуникаций внутри одной учётной записи */
struct client_cum {
	uint32_t namehash;
	pthread_mutex_t lock;
	/* обращение только после захвата client_cum.lock */
	unsigned ref; /* подсчёт ссылок */

	uint64_t new_checkpoint;
	uint64_t from_device;

	/* список рутдир */
	struct listRoot rootdir;

	/* список подключённых устройств */
	struct listRoot devices;

	/* сообщения от клиента к клиенту */
	struct squeue broadcast;

	/* к этим областям нужно обращаться только
	 * после блокировки корня (clients_cum.lock)
	 */
	struct client_cum *next;
	struct client_cum *prev;
};

struct clients_cum {
	bool inited;
	struct client_cum *first;
	pthread_mutex_t lock;
};

struct client_cum *client_cum_create(uint32_t namehash);
void client_cum_free(struct client_cum *ccum);

void client_cum_init();
void client_cum_destroy();

#endif /* _SRC_CLIENT_CUM_1435139382_H_ */

