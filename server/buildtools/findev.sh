#!/bin/sh
# vim: ft=sh ff=unix fenc=utf-8
# file: buildtools/findev.sh

# find libev
(
	pkg-config --libs --cflags libev
) 2>/dev/null || (
	if [ -r /usr/include/ev.h ];
	then
		echo -n "-lev "
	elif [ -r /usr/local/include/ev.h ];
	then
		echo -n "-I/usr/local/include -L/usr/local/lib -lev"
	else
		exit 1
	fi
) || (
	echo "libev not found" >&2
	exit 1
)


