CC	= gcc
CFLAGS	= -Wall -O0 -g
LPATH	= -L/usr/local/lib64 -L/usr/local/lib

HEADER	= ../include/conf.h

all	: rand_bytes rand_poll

rand_bytes	: ${HEADER} perf.h rand_bytes.c
	${CC} ${LPATH} ${CFLAGS} -o $@ rand_bytes.c -lcrypto

rand_poll	: ${HEADER} perf.h rand_poll.c
	${CC} ${LPATH} ${CFLAGS} -o $@ rand_poll.c -lcrypto

${HEADER}	: ../include/conf.pl
	cd ../include/ && ./conf.pl

clean	:
	rm -f ${HEADER} rand_bytes rand_poll
