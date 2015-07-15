# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
LIBS+=-pthread
CFLAGS=-ggdb2 -D_GNU_SOURCE -D_POSIX_C_SOURCE -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall -pedantic -std=c99 -I.
CFLAGS+=${EF}
BIN=bin/server
SRC=src/
SIMPLEPQ=simplepq/simplepq.c
SQUEUE=squeue/squeue.c
JUNK=junk/guid.c junk/utils.c
AS3=${SRC}/as3/as3.c

SOURCES=${SRC}/main.c ${SRC}/client_iterate.c proto/fep.pb-c.c\
	${SRC}/list.c ${SRC}/client/cum.c ${SRC}/client_cb.c\
	${AS3}\
	${SQUEUE}\
	${SIMPLEPQ}\
	${JUNK}

INC_SOURCES=${SRC}/client/include/send.c ${SRC}/client/include/handle.c

all: ${BIN}

clean:
	rm -f ${BIN} .buildflags .sqlversion

debug:
	make clean && make EF=-DDEEPDEBUG ${BIN}

runtest: proto/fep_pb2.py
	python test/unit_all_test.py

${BIN}: .buildflags .sqlversion ${SOURCES} ${INC_SOURCES}
	${CC} -o ${BIN} ${CFLAGS} -DSQLSTRUCTVER=`cat .sqlversion` ${SOURCES} ${LIBS} `cat .buildflags` ${BUILDFLAGS}
	echo "build ok"

.buildflags: buildtools/findev.sh buildtools/findpq.sh\
	buildtools/findprotobuf-c.sh buildtools/findpolarssl.sh\
	buildtools/findconfuse.sh\
	buildtools/findcurl.sh\
	additional_flags
	buildtools/findev.sh >>.buildflags
	buildtools/findpq.sh >>.buildflags
	buildtools/findprotobuf-c.sh >>.buildflags
	buildtools/findpolarssl.sh >>.buildflags
	buildtools/findconfuse.sh >>.buildflags
	buildtools/findcurl.sh >>.buildflags
	echo -n " " >>.buildflags
	cat additional_flags >>.buildflags

additional_flags:
	@echo Echo your optional flags in file 'additional_flags'
	@touch $@


proto/fep.pb-c.c: ../fep.proto
	protoc-c --c_out=proto/ -I../ ../fep.proto

proto/fep_pb2.py: ../fep.proto
	protoc --python_out=proto/ -I../ ../fep.proto

.sqlversion: sql/struct.sql
	sed -e "s/.*_struct_version_value '\([0-9]*\)'.*\|.*/\1/" -e '/^$$/d' $< > $@

