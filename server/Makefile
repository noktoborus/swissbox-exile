# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
LIBS=`pkg-config --libs --cflags libev pthread-stubs libprotobuf-c libpq`
LIBS+=-pthread
CFLAGS=-ggdb2 -D_GNU_SOURCE -D_POSIX_C_SOURCE -D_BSD_SOURCE -Wall -pedantic -std=c99 -I.
CFLAGS+=${EF}
BIN=bin/server
SRC=src/
FAKEDB=fakedb/fakedb.c
SIMPLEPQ=simplepq/simplepq.c simplepq/snip.c
JUNK=junk/guid.c junk/utils.c

all: ${BIN}

clean:
	rm -f ${BIN}

debug:
	make clean && make EF=-DDEEPDEBUG ${BIN}

runtest: ${BIN} proto/fep_pb2.py
	python2 test/proto.py ${BIN} auth

${BIN}: ${SRC}/main.c ${SRC}/client_iterate.c proto/fep.pb-c.c\
	${SRC}/client_cb.c ${SRC}/list.c ${FAKEDB} ${SIMPLEPQ} ${JUNK}
	${CC} -o ${BIN} ${CFLAGS} $^ ${LIBS}

proto/fep.pb-c.c: ../fep.proto
	protoc-c --c_out=proto/ -I../ ../fep.proto

proto/fep_pb2.py: ../fep.proto
	protoc --python_out=proto/ -I../ ../fep.proto

