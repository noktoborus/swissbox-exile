/* vim: ft=c ff=unix fenc=utf-8
 * file: src/packet.h
 */
#ifndef _SRC_PACKET_1448617020_H_
#define _SRC_PACKET_1448617020_H_

enum packet_verbose {
	PACKET_NONE = 0,
	PACKET_HEX = 1,
	PACKET_FIELD = 2,
	PACKET_ALL = 3,
	PACKET_DISCARD = 4
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
 * 	:discard -- discard all flags
 *
 * default flags:
 *  :field
 *
 */
void packet_verbose(const char *packet_string);

void packet2syslog(const char *head,
		unsigned type, const void *msg);

bool
packet_name_to_type(char *in, unsigned *type, enum packet_verbose *flags);

const char *
packet_type_to_name(unsigned type);

#endif /* _SRC_PACKET_1448617020_H_ */

