# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
LIBS=
CFLAGS=-Wall -pedantic -std=c99
BIN=server
SRC=src/


all: ${BIN}
	${BIN}

${BIN}: ${SRC}/main.c ${SRC}/utils.c
	${CC} -o ${BIN} ${CFLAGS} $< ${LIBS}

