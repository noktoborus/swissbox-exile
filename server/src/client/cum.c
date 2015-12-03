/* vim: ft=c ff=unix fenc=utf-8
 * file: src/client/cum.c
 */
#include "cum.h"


static struct clients_cum clients_cum;

void
client_cum_free(struct client_cum *ccum)
{
	unsigned ref;
	if (!ccum)
		return;
	/* считаем ссылки */
	pthread_mutex_lock(&ccum->lock);
	ref = (--ccum->ref);
	pthread_mutex_unlock(&ccum->lock);

	/* не нужно ничего чистить, если на структуру ещё ссылаются */
	if (ref)
		return;

	pthread_mutex_lock(&clients_cum.lock);
	/* выпатрашиваем список rootdir */
	while (list_free_root(&ccum->rootdir, (void(*)(void*))&free));
	while (list_free_root(&ccum->devices, NULL));
	/* развязываем список */
	if (ccum == clients_cum.first)
		clients_cum.first = ccum->next ? ccum->next : ccum->prev;
	if (ccum->next)
		ccum->next->prev = ccum->prev;
	if (ccum->prev)
		ccum->prev->next = ccum->next;
	pthread_mutex_unlock(&clients_cum.lock);

	pthread_mutex_destroy(&ccum->lock);
	squeue_destroy(&ccum->broadcast);
	free(ccum);
}

struct client_cum*
client_cum_create(uint32_t namehash)
{
	struct client_cum *ccum = NULL;

	if (pthread_mutex_lock(&clients_cum.lock))
		return NULL;

	for (ccum = clients_cum.first; ccum; ccum = ccum->next) {
		if (ccum->namehash == namehash)
			break;
	}

	if (!ccum) {
		ccum = calloc(1, sizeof(struct client_cum));
		if (!ccum) {
			xsyslog(LOG_WARNING, "memory fail when communication with over");
		} else {
			pthread_mutex_init(&ccum->lock, NULL);
			squeue_init(&ccum->broadcast);
			ccum->namehash = namehash;
			if ((ccum->next = clients_cum.first) != NULL)
				ccum->next->prev = ccum;
			clients_cum.first = ccum;
		}
	}

	if (ccum) {
		/* нужно отметиться */
		ccum->ref++;
	}
	/* и разметить список */
	pthread_mutex_unlock(&clients_cum.lock);

	return ccum;
}

void
client_cum_init()
{
	pthread_mutex_init(&clients_cum.lock, NULL);
	clients_cum.inited = true;
}

void
client_cum_destroy()
{
	while (clients_cum.first)
		client_cum_free(clients_cum.first);

	pthread_mutex_destroy(&clients_cum.lock);
	clients_cum.inited = false;
}

#if DEEPDEBUG
static void
cli_cum()
{
	struct client_cum *cum;
	unsigned c = 1u;
	fprintf(stderr, "stats \n");
	for (cum = clients_cum.first; cum; cum = cum->next, c++) {
		fprintf(stderr, "n#%02u ref: %u, checkpoint: %"PRIu64
				", device: %"PRIX64"\n", c, cum->ref, cum->new_checkpoint,
				cum->from_device);
	}
}

#endif
