/* vim: ft=c ff=unix fenc=utf-8
 * file: src/packet.h
 */
#ifndef _SRC_PACKET_1448617020_H_
#define _SRC_PACKET_1448617020_H_

enum packet_verbose {
	PACKET_HEX = 1,
	PACKET_FIELD = 2,
	PACKET_ALL = 3,
};

enum packet_action {
	PACKET_NONE = 0,
	PACKET_MERGE = 1, /* добавить указанные пакеты в лог */
	PACKET_INVERT = 2 /* исключить/добавить указанные пакеты в лог */
};

/*
 * packet_string format:
 * <Packet_name[:flag][:flag]>,<Packet_Name>
 *
 * example:
 * 	Ping,Pong,End
 * 	WantSync:hex,Ping:hex:field,End
 *
 * flags:
 * 	:hex -- print packet in hex
 * 	:field -- print packet's field value
 *
 * default flags:
 *  :field
 *
 */
void packet_verbose(const char *packet_string, enum packet_action a);

void packet2syslog(const char *head,
		unsigned type, const void *msg);

bool
packet_name_to_type(char *in, unsigned *type, enum packet_verbose *flags);

#endif /* _SRC_PACKET_1448617020_H_ */

