/* vim: ft=c ff=unix fenc=utf-8
 * file: src/fcac/main.c
 * ${CC} -o fcac -I../../ -I../ -std=c99 -ggdb2 -D_DEFAULT_SOURCE main.c fcac.c ../../junk/utils.c -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "junk/xsyslog.h"
#include "fcac.h"

int
main(int argc, char *argv[])
{
	struct fcac fcac = {0};
	struct fcac_ptr fptr = {0};
	openlog(NULL, LOG_PERROR | LOG_PID, LOG_LOCAL0);
	fcac_init(&fcac, true);
	fcac_set(&fcac, FCAC_PATH, PSLEN_S("./fcac_data"));
	fcac_set(&fcac, FCAC_MAX_MEM_SIZE, 19);
	fcac_set(&fcac, FCAC_TIME_EXPIRE, (time_t)1);

	fcac_open(&fcac, 1, &fptr);

	if (fcac_is_ready(&fptr) == FCAC_READY) {
		fprintf(stderr, "ready\n");
	} else {
		fprintf(stderr, "write: %"PRIuPTR"\n", fcac_write(&fptr, "123456789", 9));
		fprintf(stderr, "write: %"PRIuPTR"\n", fcac_write(&fptr, "123456789", 9));
		fprintf(stderr, "write: %"PRIuPTR"\n", fcac_write(&fptr, "123456789", 9));
		fcac_set_ready(&fptr);
	}

	fcac_tick(&fcac);
	fcac_close(&fptr);
	sleep(2);
	fcac_tick(&fcac);

	fcac_destroy(&fcac);
	closelog();
	return EXIT_SUCCESS;
}

