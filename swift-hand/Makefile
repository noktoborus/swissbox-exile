# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
LIBS=`pkg-config --libs --cflags json-c` -lhiredis -lpthread
CFLAGS=-ggdb2 -D_GNU_SOURCE -D_POSIX_C_SOURCE -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall -pedantic -std=c99 -I. -I../server -I../server/src/fcac
BIN=swift-hand
SRC=main.c keystone-client/keystone-client.c rdc.c ../server/junk/utils.c ../server/junk/almsg.c
FCAC=../server/src/fcac/fcac.c

all: ${BIN}

.buildflags: ../server/buildtools/findev.sh\
		../server/buildtools/findconfuse.sh\
		../server/buildtools/findpolarssl.sh\
		../server/buildtools/findcurl.sh
	echo > .buildflags
	../server/buildtools/findev.sh >>.buildflags
	../server/buildtools/findconfuse.sh >>.buildflags
	../server/buildtools/findcurl.sh >>.buildflags
	../server/buildtools/findpolarssl.sh >>.buildflags
	echo -n " " >>.buildflags

${BIN}: ${SRC} .buildflags
	${CC} -o ${BIN} ${CFLAGS} ${SRC} ${FCAC} ${LIBS} `cat .buildflags` ${BUILDFLAGS}

