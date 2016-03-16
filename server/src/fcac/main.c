/* vim: ft=c ff=unix fenc=utf-8
 * file: src/fcac/main.c
 * ${CC} -o fcac -I../../ -I../ -std=c99 -ggdb2 -DFCAC_DEEPDEBUG -D_DEFAULT_SOURCE main.c fcac.c ../../junk/utils.c -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "junk/xsyslog.h"
#include "fcac.h"

int
main(int argc, char *argv[])
{
	struct fcac fcac = {0};
	const char fcac_path[] = "./fcac_data";

	struct fcac_ptr fptr[10] = {0};
	const size_t count = sizeof(fptr) / sizeof(struct fcac_ptr);

	openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);
	mkdir(fcac_path, S_IRWXU);
	fcac_init(&fcac, true);
	fcac_set(&fcac, FCAC_PATH, PSLEN_S(fcac_path));
	fcac_set(&fcac, FCAC_MAX_MEM_SIZE, 19);
	/*fcac_set(&fcac, FCAC_TIME_EXPIRE, (time_t)1);*/

	for (size_t i = 0u; i < count; i++) {
		fcac_open(&fcac, i, fptr + i, 0);
	}

	for (size_t i = 0u; i < count; i++) {
		if (fcac_is_ready(fptr + i) == FCAC_READY) {
			fprintf(stderr, "ready\n");
		} else {
			fprintf(stderr, "write: %"PRIuPTR"\n", fcac_write(fptr + i, "123456789", 9));
			fprintf(stderr, "write: %"PRIuPTR"\n", fcac_write(fptr + i, "123456789", 9));
			fprintf(stderr, "write: %"PRIuPTR"\n", fcac_write(fptr + i, "123456789", 9));
			fcac_set_ready(fptr + i);
		}
		fcac_close(fptr + i);
	}

	fcac_tick(&fcac);

	fcac_tick(&fcac);

	fcac_tick(&fcac);

	fcac_destroy(&fcac);
	closelog();
	return EXIT_SUCCESS;
}

