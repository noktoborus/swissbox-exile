# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
LIBS+=-pthread
CFLAGS=-ggdb2 -D_GNU_SOURCE -D_POSIX_C_SOURCE -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall -pedantic -std=c99 -I.
CFLAGS+=${EF}
BIN=bin/server
SRC=src/
FAKEDB=fakedb/fakedb.c
SIMPLEPQ=simplepq/simplepq.c simplepq/snip.c
JUNK=junk/guid.c junk/utils.c

SOURCES=${SRC}/main.c ${SRC}/client_iterate.c proto/fep.pb-c.c\
	${SRC}/client_cb.c ${SRC}/list.c ${FAKEDB} ${SIMPLEPQ} ${JUNK}

all: ${BIN}

clean:
	rm -f ${BIN} .buildflags

debug:
	make clean && make EF=-DDEEPDEBUG ${BIN}

runtest: ${BIN} proto/fep_pb2.py
	python2 test/proto.py ${BIN} auth

${BIN}: .buildflags ${SOURCES}
	${CC} -o ${BIN} ${CFLAGS} ${SOURCES} ${LIBS} `cat .buildflags`

.buildflags: buildtools/findev.sh buildtools/findpq.sh\
	buildtools/findprotobuf-c.sh
	buildtools/findev.sh >>.buildflags
	buildtools/findpq.sh >>.buildflags
	buildtools/findprotobuf-c.sh >>.buildflags


proto/fep.pb-c.c: ../fep.proto
	protoc-c --c_out=proto/ -I../ ../fep.proto

proto/fep_pb2.py: ../fep.proto
	protoc --python_out=proto/ -I../ ../fep.proto

