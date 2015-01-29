/* vim: ft=c ff=unix fenc=utf-8
 * file: utils.h
 */
#ifndef _UTILS_1422516244_H_
#define _UTILS_1422516244_H_
/*
 * print port and host to str with lenght size
 * output must be have least 48 byte
 *  (len(ipv6) + len(':') + len(SHORT_MAX) + len('\0')) == (41 + 1 + 5 + 1)
 *
 */
void
saddr_char(char *str, size_t size, sa_family_t family, struct sockaddr *sa);


#endif /* _UTILS_1422516244_H_ */

