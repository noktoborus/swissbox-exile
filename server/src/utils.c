/* vim: ft=c ff=unix fenc=utf-8
 * file: utils.c
 */
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"

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
