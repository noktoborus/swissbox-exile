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

#include "almsg.h"

int
main(int argc, char *argv[])
{
	struct almsg_parser alp;
	char in[] = "key: -\nvalue\\\nx\n.\n";
	almsg_init(&alp);
	almsg_parse_buf(&alp, in, sizeof(in));
	almsg_destroy(&alp);
	return EXIT_SUCCESS;
}

