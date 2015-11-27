/* vim: ft=c ff=unix fenc=utf-8
 * file: src/packet.h
 */
#ifndef _SRC_PACKET_1448617020_H_
#define _SRC_PACKET_1448617020_H_

enum packet_verbose {
	PACKET_NONE = 0,
	PACKET_HEX = 1,
	PACKET_FIELDS = 2,
	PACKET_ALL = 3
};

void packet2syslog(const char *head,
		unsigned type, const void *msg,
		enum packet_verbose v);

#endif /* _SRC_PACKET_1448617020_H_ */

