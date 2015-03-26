#!/bin/sh
# vim: ft=sh ff=unix fenc=utf-8
# file: buildtools/findprotobuf-c.sh

XF=$(tempfile)
# find protobuf-c
(
	#pkg-config --libs --cflags libprotobuf-c
	exit 1
) 2>/dev/null || (
	(find /usr/include/ /usr/local/include/ -name "protobuf-c.h" -print\
		| while read x; do echo -n "-I`dirname $x` "; done) >${XF}

	[ "`stat -c%s ${XF}`" -eq 0 ] && exit 1
	(find /usr/lib/ /usr/local/lib/ -name "libprotobuf-c.so" -print\
		| while read x; do echo -n "-L`dirname $x` "; done) >>${XF}
	echo -n "-lprotobuf-c "
	cat ${XF}
	exit 0
) 2>/dev/null || (
	echo "libprotobuf-c not found" >&2
	exit 1
)

rm -f ${XF}

