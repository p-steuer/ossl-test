/* Author: Patrick Steuer <psteuer@mail.de> */

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test.h"
#include "testvec.h"

/* COMPAT MACROS */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#else
 #define EVP_CTRL_GCM_SET_IVLEN			EVP_CTRL_AEAD_SET_IVLEN
 #define EVP_CTRL_GCM_SET_TAG			EVP_CTRL_AEAD_SET_TAG
 #define EVP_CTRL_GCM_GET_TAG			EVP_CTRL_AEAD_GET_TAG

 #define EVP_CTRL_CCM_SET_IVLEN			EVP_CTRL_AEAD_SET_IVLEN
 #define EVP_CTRL_CCM_SET_TAG			EVP_CTRL_AEAD_SET_TAG
 #define EVP_CTRL_CCM_GET_TAG			EVP_CTRL_AEAD_GET_TAG
#endif

static void *malloc_(size_t len);
static void aes_gcm_test(int inplace, int stream, const struct aes_gcm_tv *tv);
static void aes_ccm_test(int inplace, const struct aes_ccm_tv *tv);

EVP_CIPHER_CTX *ctx;

int main(void)
{
	const struct aes_gcm_tv *aes_gcm_tvec;
	const struct aes_ccm_tv *aes_ccm_tvec;

	unsigned long long total;
	time_t seed;
	int i;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
#else
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC
	    | OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif

	srand(time(&seed));

	total = 0;

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		test_failed("EVP_CIPHER_CTX failed");
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (EVP_CIPHER_CTX_cleanup(ctx) != 1)
		test_failed("EVP_CIPHER_CTX_cleanup failed");
#else
	if (EVP_CIPHER_CTX_reset(ctx) != 1)
		test_failed("EVP_CIPHER_CTX_reset failed");
#endif

	/* aes-gcm */
	for (aes_gcm_tvec = AES_GCM_TV, i = 0; i < AES_GCM_TV_LEN; aes_gcm_tvec++, i++)
		aes_gcm_test(0, 0, aes_gcm_tvec);
	total += i;
	for (aes_gcm_tvec = AES_GCM_TV, i = 0; i < AES_GCM_TV_LEN; aes_gcm_tvec++, i++)
		aes_gcm_test(1, 0, aes_gcm_tvec);
	total += i;
	for (aes_gcm_tvec = AES_GCM_TV, i = 0; i < AES_GCM_TV_LEN; aes_gcm_tvec++, i++)
		aes_gcm_test(0, 1, aes_gcm_tvec);
	total += i;
	for (aes_gcm_tvec = AES_GCM_TV, i = 0; i < AES_GCM_TV_LEN; aes_gcm_tvec++, i++)
		aes_gcm_test(1, 1, aes_gcm_tvec);
	total += i;

	/* aes-ccm */
	for (aes_ccm_tvec = AES_CCM_TV_DVPT, i = 0; i < AES_CCM_TV_DVPT_LEN; aes_ccm_tvec++, i++)
		aes_ccm_test(0, aes_ccm_tvec);
	total += i;
	for (aes_ccm_tvec = AES_CCM_TV_DVPT, i = 0; i < AES_CCM_TV_DVPT_LEN; aes_ccm_tvec++, i++)
		aes_ccm_test(1, aes_ccm_tvec);
	total += i;
	for (aes_ccm_tvec = AES_CCM_TV_VADT, i = 0; i < AES_CCM_TV_VADT_LEN; aes_ccm_tvec++, i++)
		aes_ccm_test(0, aes_ccm_tvec);
	total += i;
	for (aes_ccm_tvec = AES_CCM_TV_VADT, i = 0; i < AES_CCM_TV_VADT_LEN; aes_ccm_tvec++, i++)
		aes_ccm_test(1, aes_ccm_tvec);
	total += i;
	for (aes_ccm_tvec = AES_CCM_TV_VNT, i = 0; i < AES_CCM_TV_VNT_LEN; aes_ccm_tvec++, i++)
		aes_ccm_test(0, aes_ccm_tvec);
	total += i;
	for (aes_ccm_tvec = AES_CCM_TV_VNT, i = 0; i < AES_CCM_TV_VNT_LEN; aes_ccm_tvec++, i++)
		aes_ccm_test(1, aes_ccm_tvec);
	total += i;

        EVP_CIPHER_CTX_free(ctx);

	printf("All %llu tests passed.\n", total);
	test_passed();
	return 0;
}

static void *malloc_(size_t len)
{
	void *ptr;

	if (len == 0)
		return NULL;

	if ((ptr = malloc(len)) == NULL)
		test_failed("malloc failed");

	return ptr;
}

static void aes_gcm_test(int inplace, int stream, const struct aes_gcm_tv *tv)
{
	struct aes_gcm_tv tv_out;
	unsigned char *in, *out, *buf;
	const EVP_CIPHER *type;
	size_t len, off, datalen;
	int outlen, rv;

	printf("aes-gcm test: ");

	tv_out.pt = malloc_(tv->len);
	tv_out.tag = malloc_(tv->taglen);
	tv_out.ct = malloc_(tv->len);

	if (inplace) {
		if ((tv_out.pt != NULL) && (tv->pt != NULL))
			memcpy(tv_out.pt, tv->pt, tv->len);
		if ((tv_out.ct != NULL) && (tv->ct != NULL))
			memcpy(tv_out.ct, tv->ct, tv->len);
	}

	printf("no.%d,", tv->i);

	switch (tv->dir) {
	case DEC:
		printf("dec,");
		if (inplace) {
			printf("in-place,");
			in = tv_out.ct;
			buf = tv_out.ct;
		} else {
			in = tv->ct;
			buf = tv_out.ct;
		}
		out = tv->pt;
		break;
	case ENC:
		printf("enc,");
		if (inplace) {
			printf("in-place,");
			in = tv_out.pt;
			buf = tv_out.pt;
		} else {
			in = tv->pt;
			buf = tv_out.pt;
		}
		out = tv->ct;
		break;
	default:
		test_failed("Invalid test vector (%d)", tv->i);
	}

	if (stream)
		printf("stream,");

	switch (tv->keylen * 8) {
	case 128:
		type = EVP_aes_128_gcm();
		break;
	case 192:
		type = EVP_aes_192_gcm();
		break;
	case 256:
		type = EVP_aes_256_gcm();
		break;
	default:
		test_failed("Invalid test vector (%d)", tv->i);
	}

	if (EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, -1) != 1)
		test_failed("EVP_EncryptInit_ex failed (%d)", tv->i);

	if (tv->dir == DEC) {
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
		    tv->taglen, tv->tag))
			test_failed("EVP_CIPHER_CTX_ctrl failed (%d)", tv->i);
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, tv->ivlen,
				 NULL))
		test_failed("EVP_CIPHER_CTX_ctrl failed (%d)", tv->i);

	if (EVP_CipherInit_ex(ctx, NULL, NULL, tv->key, tv->iv, tv->dir) != 1)
		test_failed("EVP_EncryptInit_ex failed (%d)", tv->i);

	printf("aad(");
	datalen = tv->aadlen;
	off = 0;

	if (tv->aadlen == 0)
		goto _aad_done_;

	while (1) {
		len = stream ? (rand() % (datalen + 1 - off)) : datalen;

		printf("%lu", len);

		if (EVP_CipherUpdate(ctx, NULL, &outlen, tv->aad + off, len)
		    != 1)
			test_failed("EVP_CipherUpdate failed (%d)", tv->i);

		if ((off += len) != datalen)
			printf(",");
		else
			break;
	}
_aad_done_:
	printf("),pt(");
	datalen = tv->len;
	off = 0;

	if (tv->len == 0)
		goto _ptct_done_;

	while (1) {
		len = stream ? (rand() % (datalen + 1 - off)) : datalen;

		printf("%lu", len);

		if (EVP_CipherUpdate(ctx, buf + off, &outlen, in + off, len)
		    != 1)
			test_failed("EVP_CipherUpdate failed (%d)", tv->i);
		if ((size_t)outlen != len)
			test_failed("EVP_CipherUpdate failed (%d)", tv->i);

		if ((off += len) != datalen)
			printf(",");
		else
			break;
	}
_ptct_done_:
	printf(") ... ");

	rv = EVP_CipherFinal_ex(ctx, buf + off, &outlen);

	if (((tv->dir == ENC) && (rv != 1))
	    || ((tv->dir == DEC) && (tv->rv == SUCC) && (rv < 1))
	    || ((tv->dir == DEC) && (tv->rv == FAIL) && (rv >= 1)))
		test_failed("EVP_CipherFinal_ex failed (%d)", tv->i);

	if ((out != NULL) && (memcmp(buf, out, datalen) != 0))
		test_failed("Wrong plain/cipher-text (%d)", tv->i);

	if (tv->dir == ENC) {
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
					 tv->taglen, tv_out.tag))
			test_failed("EVP_CIPHER_CTX_ctrl failed (%d)", tv->i);
		if (memcmp(tv_out.tag, tv->tag, tv->taglen) != 0)
			test_failed("Wrong tag value (%d)", tv->i);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (EVP_CIPHER_CTX_cleanup(ctx) != 1)
		test_failed("EVP_CIPHER_CTX_cleanup failed (%d)", tv->i);
#else
	if (EVP_CIPHER_CTX_reset(ctx) != 1)
		test_failed("EVP_CIPHER_CTX_reset failed (%d)", tv->i);
#endif

	free(tv_out.pt);
	free(tv_out.tag);
	free(tv_out.ct);
	printf("OK\n");
}

static void aes_ccm_test(int inplace, const struct aes_ccm_tv *tv)
{
	struct aes_ccm_tv tv_out;
	unsigned char *in, *out, *buf, tag[16];
	const EVP_CIPHER *type;
	size_t len, datalen;
	int outlen, rv;

	printf("aes-ccm test: ");

	tv_out.ct = malloc_(tv->plen + tv->tlen);
	tv_out.payload = malloc_(tv->plen);

	if (inplace) {
		if ((tv_out.payload != NULL) && (tv->payload != NULL))
			memcpy(tv_out.payload, tv->payload, tv->plen);
		if ((tv_out.ct != NULL) && (tv->ct != NULL))
			memcpy(tv_out.ct, tv->ct, tv->plen + tv->tlen);
	}

	printf("no.%d,", tv->i);

	switch (tv->dir) {
	case DEC:
		printf("dec,");
		if (inplace) {
			printf("in-place,");
			in = tv_out.ct;
			buf = tv_out.ct;
		} else {
			in = tv->ct;
			buf = tv_out.ct;
		}
		out = tv->payload;
		break;
	case ENC:
		printf("enc,");
		if (inplace) {
			printf("in-place,");
			in = tv_out.payload;
			buf = tv_out.payload;
		} else {
			in = tv->payload;
			buf = tv_out.payload;
		}
		out = tv->ct;
		break;
	default:
		test_failed("Invalid test vector (%d)", tv->i);
	}

	switch (tv->keylen * 8) {
	case 128:
		type = EVP_aes_128_ccm();
		break;
	case 192:
		type = EVP_aes_192_ccm();
		break;
	case 256:
		type = EVP_aes_256_ccm();
		break;
	default:
		test_failed("Invalid test vector (%d)", tv->i);
	}

	if (EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, tv->dir) != 1)
		test_failed("EVP_EncryptInit_ex failed (%d)", tv->i);

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, tv->nlen,
				 NULL))
		test_failed("EVP_CIPHER_CTX_ctrl failed (%d)", tv->i);

	if (tv->dir == DEC) {
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
		    tv->tlen, tv->ct + tv->plen))
			test_failed("EVP_CIPHER_CTX_ctrl failed (%d)", tv->i);
	} else {
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
		    tv->tlen, NULL))
			test_failed("EVP_CIPHER_CTX_ctrl failed (%d)", tv->i);
	}

	if (EVP_CipherInit_ex(ctx, NULL, NULL, tv->key, tv->nonce, -1) != 1)
		test_failed("EVP_EncryptInit_ex failed (%d)", tv->i);

	/* pass packet length */
	if (EVP_CipherUpdate(ctx, NULL, &outlen, NULL, tv->plen) != 1)
		test_failed("EVP_CipherUpdate failed (%d)", tv->i);

	printf("aad(");
	datalen = tv->alen;

	if (tv->alen == 0)
		goto _aad_done_;

	len = datalen;
	printf("%lu", len);

	if (EVP_CipherUpdate(ctx, NULL, &outlen, tv->adata, len) != 1)
		test_failed("EVP_CipherUpdate failed (%d)", tv->i);

_aad_done_:
	printf("),pt(");
	datalen = tv->plen;

	if (tv->plen == 0)
		goto _ptct_done_;

	len = datalen;
	printf("%lu", len);

	rv = EVP_CipherUpdate(ctx, buf, &outlen, in, len);
	if (rv == 1 && (size_t)outlen != len)
		test_failed("EVP_CipherUpdate failed (%d)", tv->i);
	if (((tv->dir == ENC) && (rv != 1))
	    || ((tv->dir == DEC) && (tv->rv == SUCC) && (rv < 1))
	    || ((tv->dir == DEC) && (tv->rv == FAIL) && (rv >= 1)))
		test_failed("EVP_CipherUpdate failed (%d)", tv->i);

_ptct_done_:
	printf(") ... ");

	EVP_CipherFinal_ex(ctx, NULL, &outlen);	/* not needed for ccm */

	if ((out != NULL) && (memcmp(buf, out, datalen) != 0))
		test_failed("Wrong plain/cipher-text (%d)", tv->i);

	if (tv->dir == ENC) {
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tv->tlen,
					 tag))
			test_failed("EVP_CIPHER_CTX_ctrl failed (%d)", tv->i);
		if (memcmp(tv->ct + tv->plen, tag, tv->tlen) != 0)
			test_failed("Wrong tag value (%d)", tv->i);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (EVP_CIPHER_CTX_cleanup(ctx) != 1)
		test_failed("EVP_CIPHER_CTX_cleanup failed (%d)", tv->i);
#else
	if (EVP_CIPHER_CTX_reset(ctx) != 1)
		test_failed("EVP_CIPHER_CTX_reset failed (%d)", tv->i);
#endif

	free(tv_out.ct);
	free(tv_out.payload);
	printf("OK\n");
}
