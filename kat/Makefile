CC	= gcc
CFLAGS	= -Wall
LPATH	= -L/usr/local/lib64 -L/usr/local/lib

all	: test

test	: test.c test.h testvec.o
	${CC} ${LPATH} ${CFLAGS} -o $@ test.c testvec.o -lcrypto

testvec.o	: testvec.c testvec.h
	${CC} ${LPATH} ${CFLAGS} -c testvec.c -lcrypto

testvec.c	: parse.pl
	./parse.pl

clean	:
	rm -f testvec.c test testvec.o
