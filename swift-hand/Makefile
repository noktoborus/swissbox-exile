# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
LIBS=`pkg-config --libs --cflags json-c libcurl`
CFLAGS=-ggdb2 -D_GNU_SOURCE -D_POSIX_C_SOURCE -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall -pedantic -std=c99 -I.
BIN=swift-hand
SRC=main.c keystone-client/keystone-client.c

all: ${BIN}

${BIN}: ${SRC}
	${CC} -o ${BIN} ${CFLAGS} ${SRC} ${LIBS}

