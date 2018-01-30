CC	= gcc
CFLAGS	= -Wall -O0 -g
LPATH	= -L/usr/local/lib64 -L/usr/local/lib

all	: test

test	: test.c test.h testvec-gcm.o testvec-ccmDVPT.o testvec-ccmVADT.o testvec-ccmVNT.o
	${CC} ${LPATH} ${CFLAGS} -o $@ test.c testvec-gcm.o testvec-ccmDVPT.o testvec-ccmVADT.o testvec-ccmVNT.o -lcrypto

clean	:
	rm -f test testvec-gcm.c testvec-ccmDVPT.c testvec-ccmVADT.c testvec-ccmVNT.c testvec-gcm.o testvec-ccmDVPT.o testvec-ccmVADT.o testvec-ccmVNT.o

testvec-gcm.o		: testvec-gcm.c testvec.h
	${CC} ${LPATH} ${CFLAGS} -c testvec-gcm.c -lcrypto
testvec-ccmDVPT.o	: testvec-ccmDVPT.c testvec.h
	${CC} ${LPATH} ${CFLAGS} -c testvec-ccmDVPT.c -lcrypto
testvec-ccmVADT.o	: testvec-ccmVADT.c testvec.h
	${CC} ${LPATH} ${CFLAGS} -c testvec-ccmVADT.c -lcrypto
testvec-ccmVNT.o	: testvec-ccmVNT.c testvec.h
	${CC} ${LPATH} ${CFLAGS} -c testvec-ccmVNT.c -lcrypto

testvec-gcm.c		: parse-gcm.pl
	./parse-gcm.pl
testvec-ccmDVPT.c	: parse-ccmDVPT.pl
	./parse-ccmDVPT.pl
testvec-ccmVADT.c	: parse-ccmVADT.pl
	./parse-ccmVADT.pl
testvec-ccmVNT.c	: parse-ccmVNT.pl
	./parse-ccmVNT.pl
