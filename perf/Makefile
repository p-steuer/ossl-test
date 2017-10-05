CC	= gcc
CFLAGS	= -Wall -O0 -g
LPATH	= -L/usr/local/lib64 -L/usr/local/lib

all	: rand

rand	: rand.c perf.h cpuinfo.h
	${CC} ${LPATH} ${CFLAGS} -o $@ rand.c -lcrypto

cpuinfo.h	: cpuinfo.pl
	./cpuinfo.pl

clean	:
	rm -f rand cpuinfo.h
