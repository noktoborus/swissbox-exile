#!/bin/sh
# vim: ft=sh ff=unix fenc=utf-8
# file: buildtools/findconfuse.sh

# find libconfuse
(
	pkg-config --libs --cflags libconfuse
) 2>/dev/null || (
	if [ -r /usr/include/confuse.h ];
	then
		echo -n "-lconfuse "
	elif [ -r /usr/local/include/confuse.h ];
	then
		echo -n "-I/usr/local/include -L/usr/local/lib -lconfuse"
	else
		exit 1
	fi
) || (
	echo "libconfuse not found" >&2
	exit 1
)

