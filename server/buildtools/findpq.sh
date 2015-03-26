#!/bin/sh
# vim: ft=sh ff=unix fenc=utf-8
# file: buildtools/findpq.sh

XF=$(tempfile)
# find libpq
(
	pkg-config --libs --cflags libpq
) 2>/dev/null || (
	(find /usr/include/ /usr/local/include/ -name "libpq-fe.h" -print\
		| while read x; do echo -n "-I`dirname $x` "; done) >${XF}

	[ "`stat -c%s ${XF}`" -eq 0 ] && exit 1
	(find /usr/lib/ /usr/local/lib/ -name "libpq.so" -print\
		| while read x; do echo -n "-L`dirname $x` "; done) >>${XF}
	echo -n "-lpq "
	cat ${XF}
	exit 0
) 2>/dev/null || (
	echo "libpq not found" >&2
	exit 1
)

rm -f ${XF}
