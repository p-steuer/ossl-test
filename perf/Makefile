CC	= gcc
CFLAGS	= -Wall -O0 -g
LPATH	= -L/usr/local/lib64 -L/usr/local/lib

all	: rand_bytes rand_poll

rand_bytes	: rand_bytes.c perf.h cpuinfo.h
	${CC} ${LPATH} ${CFLAGS} -o $@ rand_bytes.c -lcrypto

rand_poll	: rand_poll.c perf.h cpuinfo.h
	${CC} ${LPATH} ${CFLAGS} -o $@ rand_poll.c -lcrypto

cpuinfo.h	: cpuinfo.pl
	./cpuinfo.pl

clean	:
	rm -f rand_bytes rand_poll cpuinfo.h
