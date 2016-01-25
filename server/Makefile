# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
LIBS+=-pthread -lhiredis
CFLAGS=-ggdb2 -D_GNU_SOURCE -D_POSIX_C_SOURCE -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall -pedantic -std=c99 -I. -I./junk
CFLAGS+=${EF}
BIN=bin/server
SRC=src/
SIMPLEPQ=simplepq/simplepq.c
SQUEUE=squeue/squeue.c
JUNK=junk/guid.c junk/utils.c junk/almsg.c junk/curlev/curlev.c
AS3=${SRC}/as3/as3.c
FCAC=${SRC}/fcac/fcac.c

SOURCES=${SRC}/main.c ${SRC}/packet.c ${SRC}/client_iterate.c proto/fep.pb-c.c\
	${SRC}/redis_process.c ${SRC}/callback.c\
	${SRC}/list.c ${SRC}/client/cum.c ${SRC}/client_cb.c\
	${AS3}\
	${FCAC}\
	${SQUEUE}\
	${SIMPLEPQ}\
	${JUNK}

INC_SOURCES=${SRC}/client/include/send.c ${SRC}/client/include/handle.c\

INST_N=dodiboxd
INST_B=/usr/bin/${INST_N}
INST_C=/etc/${INST_N}.conf
INST_I=/etc/init.d/${INST_N}

all: ${BIN}

install:
	install -m 0555 -o root ${BIN} ${INST_B}
	install -m 0444 -o root server.conf ${INST_C}
	install -m 0555 -o root rc/server ${INST_I}
	sed -e 's/^pidfile.*/pidfile=\/run\/${INST_N}.pid/' -i ${INST_C}
	sed -e 's@^cfg=.*@cfg=${INST_C}@' -e 's@^e=.*@e=${INST_B}@' -i ${INST_I}

clean:
	rm -f ${BIN} .buildflags .sqlversion

debug:
	make clean && make EF=-DDEEPDEBUG ${BIN}

runtest: proto/fep_pb2.py
	python test/unit_all_test.py

pack: .pack_feps

.pack_feps: ${BIN}
	@echo pack into dist/feps-`git describe --always --long`.tbz
	mkdir -p dist
	tar -cjvf dist/feps-`git describe --always --long`.tbz bin/ user/.keep sql/*.sql fcac_data/.keep
	@touch $@

${BIN}: .buildflags .sqlversion ${SOURCES} ${INC_SOURCES}
	${CC} -o ${BIN} ${CFLAGS} -DSQLSTRUCTVER=`cat .sqlversion` -DGIT_VERSION=`git describe --always --long` ${SOURCES} ${LIBS} `cat .buildflags` ${BUILDFLAGS}
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

