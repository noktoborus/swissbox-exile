/* vim: ft=c ff=unix fenc=utf-8
 * file: almsg_main.c
 * ${CC} -D_DEFAULT_SOURCE -std=c99 almsg_main.c almsg.c -Wall -pedantic
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include "almsg.h"

int
main(int argc, char *argv[])
{
	char *outs;
	size_t outsz;

	struct almsg_parser alp;
	char *in = strdup("key: -\nvalue\\\nx\n.\nkey2: -\nvalue3\\\nx\n.\nkey2: -\nvalue3\\\nx\n.\n");

	almsg_init(&alp);
	almsg_parse_buf(&alp, in, strlen(in));

	almsg_add(&alp, "XXX", 3, "yyy\ny", 5);
	almsg_format_buffer(&alp, &outs, &outsz);

	printf("len: %"PRIuPTR", buf:\n%s", outsz, outs);
	if (outs)
		free(outs);

	free(in);
	almsg_destroy(&alp);
	return EXIT_SUCCESS;
}

