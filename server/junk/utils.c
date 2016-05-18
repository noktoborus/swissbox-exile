/* vim: ft=c ff=unix fenc=utf-8
 * file: utils.c
 */
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include "utils.h"


size_t
tolower_s(char *string, size_t len)
{
	size_t c = 0u;

	if (len == 0u) {
		for (c = 0u; string[c]; c++) {
			string[c] = tolower(string[c]);
		}
	} else {
		for (c = 0u; c < len; c++) {
			string[c] = tolower(string[c]);
		}
	}

	return c;
}

uint32_t
hash_pjw(const char *str, size_t size)
{
	register uint32_t hash = 0u;
	register uint32_t test = 0u;
	register size_t i = 0u;

	for (; i < size; i++) {
		hash = (hash << 4) + (uint8_t)(*(str + i));

		if ((test = hash & 0xf0000000) != 0) {
			hash = ((hash ^ (test >> 24)) & (0xfffffff));
		}
	}
	return hash;
}


void
saddr_char(char *str, size_t size, sa_family_t family, struct sockaddr *sa)
{
	char xhost[40];
	switch(family) {
	case AF_INET:
		inet_ntop(AF_INET, &((struct sockaddr_in*)sa)->sin_addr,
				xhost, sizeof(xhost));
		snprintf(str, size, "%s:%u", xhost,
				ntohs(((struct sockaddr_in*)sa)->sin_port));
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6*)sa)->sin6_addr,
				xhost, sizeof(xhost));
		snprintf(str, size, "[%s]:%u", xhost,
				ntohs(((struct sockaddr_in6*)sa)->sin6_port));
		break;
	default:
		snprintf(str, size, "[unknown fa]");
		break;
	}
}

int
mkpath(const char *path, mode_t mode)
{
	char rpath[PATH_MAX] = {0};
	const char *base;
	char *end;
	size_t len;
	int rval = 0;

	base = path;
	while ((end = strchr(base, '/')) != NULL) {
		len = end - base;
		if (len > 0) {
			len = end - path;
			memcpy(rpath, path, len);
			rpath[len] = '\0';
			if ((rval = mkdir(rpath, mode)) == -1) {
				if (errno == EEXIST) {
					rval = 0;
				} else {
					break;
				}
			}
		}
		base = ++end;
	}
	/* обработка хвоста */
	if (*base && !rval) {
		if ((rval = mkdir(path, mode)) == -1 && errno == EEXIST)
			rval = 0;
	}

	return rval;
}

