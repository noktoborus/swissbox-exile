/* vim: ft=c ff=unix fenc=utf-8
 * file: utils.c
 */
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"


size_t
bin2hex(char *binary, size_t bin_len, char *string, size_t str_len)
{
	const char hex[16] = "0123456789ABCDEF";
	size_t i;

	if (!string || !str_len || !binary || !bin_len)
		return 0u;

	for (i = 0u; i < str_len - 1 && i < bin_len * 2; i++) {
		if (!(i % 2)) {
			/* first nibble */
			string[i] = hex[binary[i / 2] >> 4 & 0xf];
		} else {
			/* second nibble */
			string[i] = hex[binary[i / 2] & 0xf];
		}
	}
	string[i] = '\0';
	return i;
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
