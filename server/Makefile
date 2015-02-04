# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
LIBS=`pkg-config --libs --cflags libev pthread-stubs libprotobuf-c`
LIBS+=-pthread
CFLAGS=-ggdb2 -D_POSIX_C_SOURCE -D_BSD_SOURCE -Wall -pedantic -std=c99
BIN=bin/server
SRC=src/


all: ${BIN}

${BIN}: ${SRC}/main.c ${SRC}/utils.c ${SRC}/client_iterate.c gen/fet.pb-c.c
	${CC} -o ${BIN} ${CFLAGS} $^ ${LIBS}

gen/fet.pb-c.c:
	protoc-c --c_out=gen/ -I../ ../fet.proto

