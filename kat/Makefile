CC	= gcc
CFLAGS	= -Wall -O0 -g
LPATH	= -L/usr/local/lib64 -L/usr/local/lib

all	: test

test	: test.c test.h testvec-gcm.o testvec-ccm.o
	${CC} ${LPATH} ${CFLAGS} -o $@ test.c testvec-gcm.o testvec-ccm.o -lcrypto

clean	:
	rm -f test testvec-gcm.c testvec-gcm.o testvec-ccm.o

testvec-gcm.o	: testvec-gcm.c testvec.h
	${CC} ${LPATH} ${CFLAGS} -c testvec-gcm.c -lcrypto
testvec-ccm.o	: testvec-ccm.c testvec.h
	${CC} ${LPATH} ${CFLAGS} -c testvec-ccm.c -lcrypto

testvec-gcm.c	: parse-gcm.pl
	./parse-gcm.pl
testvec-ccm.c	: parse-ccm.pl
	./parse-ccm.pl
