#ifndef TEST_VEC_H
#define TEST_VEC_H

#include <stddef.h>

/* dir */
#define ENC	1
#define DEC	0

/* rv */
#define SUCC	1
#define FAIL	0

struct aes_gcm_tv {
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

struct aes_ccm_tv {
	int i;
	int dir;
	size_t keylen;

	size_t alen;
	size_t plen;
	size_t nlen;
	size_t tlen;

	unsigned char *key;

	int count;
	unsigned char *nonce;
	unsigned char *adata;
	unsigned char *ct;
	int rv;
	unsigned char *payload;
};

extern const struct aes_gcm_tv AES_GCM_TV[];
extern const size_t AES_GCM_TV_LEN;
extern const struct aes_ccm_tv AES_CCM_TV_DVPT[];
extern const size_t AES_CCM_TV_DVPT_LEN;
extern const struct aes_ccm_tv AES_CCM_TV_VADT[];
extern const size_t AES_CCM_TV_VADT_LEN;
extern const struct aes_ccm_tv AES_CCM_TV_VNT[];
extern const size_t AES_CCM_TV_VNT_LEN;
extern const struct aes_ccm_tv AES_CCM_TV_VPT[];
extern const size_t AES_CCM_TV_VPT_LEN;
extern const struct aes_ccm_tv AES_CCM_TV_VTT[];
extern const size_t AES_CCM_TV_VTT_LEN;

#endif
