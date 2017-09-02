#ifndef TEST_VEC_H
#define TEST_VEC_H

#include <stddef.h>

/* dir */
#define ENC	1
#define DEC	0

/* rv */
#define SUCC	1
#define FAIL	0

struct aead_tv {
	int i;
	int dir;
	int count;
	size_t keylen;
	size_t ivlen;
	size_t len;
	size_t aadlen;
	size_t taglen;
	unsigned char *key;
	unsigned char *iv;
	unsigned char *pt;
	unsigned char *aad;
	unsigned char *tag;
	unsigned char *ct;
	int rv;
};

extern const struct aead_tv AES_GCM_TV[];
extern const size_t AES_GCM_TV_LEN;

#endif
