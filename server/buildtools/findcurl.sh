#!/bin/sh
# vim: ft=sh ff=unix fenc=utf-8
# file: buildtools/findcurl.sh

# find libcurl
(
	pkg-config --libs --cflags libcurl
) 2>/dev/null || (
	if [ -r /usr/include/curl/curl.h ];
	then
		echo -n "-lcurl "
	elif [ -r /usr/local/include/curl/curl.h ];
	then
		echo -n "-I/usr/local/include -L/usr/local/lib -lcurl"
	else
		exit 1
	fi
) || (
	echo "libcurl not found" >&2
	exit 1
)


