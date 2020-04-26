#include "crypt_srp.h"
#include "openssl/evp.h"
#include <string.h>

static int _compute_digest_v1(BIGNUM *A, BIGNUM *B, BIGNUM *C, unsigned char *out);
static int _compute_digest_v2(BIGNUM *A, BIGNUM *B, unsigned char *out);

int qinn_srp_calx(unsigned char *salt, int saltlen, char *username, char *password, BIGNUM *ret) {
	int rc = 0;
	EVP_MD_CTX *ctx = NULL;
	unsigned char digest[20] = { 0 };
	unsigned int digest_len = sizeof(digest);

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) ||
		!EVP_DigestUpdate(ctx, salt, saltlen) ||
		!EVP_DigestUpdate(ctx, username, strlen(username)) ||
		!EVP_DigestUpdate(ctx, password, strlen(password)) ||
		!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
		goto exit;
	}

	BN_bin2bn(digest, digest_len, ret);
	rc = 1;
exit:
	EVP_MD_CTX_free(ctx);
	return rc;
}

int qinn_srp_calV(BIGNUM *g, BIGNUM *x, BIGNUM *N, BIGNUM *ret) {
	int rc = 0;
	BN_CTX *ctx = NULL;

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	rc = BN_mod_exp(ret, g, x, N, ctx);
	if (rc != 1) {
		goto exit;
	}
exit:
	BN_CTX_free(ctx);
	return rc;
}

int qinn_srp_calA(BIGNUM *g, BIGNUM *a, BIGNUM *N, BIGNUM *ret) {
	int rc = 1;
	BN_CTX *ctx = NULL;

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	rc = BN_mod_exp(ret, g, a, N, ctx);
	
	BN_CTX_free(ctx);
	return rc;
}

int qinn_srp_calB(BIGNUM *k, BIGNUM *v, BIGNUM *g, BIGNUM *b, BIGNUM *N, BIGNUM *ret) {
	int rc = 1;
	BN_CTX *ctx = NULL;
	BIGNUM *b1, *b2;

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	BN_CTX_start(ctx);
	b1 = BN_CTX_get(ctx);
	b2 = BN_CTX_get(ctx);

	rc = BN_mod_mul(b1, k, v, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = BN_mod_exp(b2, g, b, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = BN_mod_add(ret, b1, b2, N, ctx);
	if (rc != 1) {
		goto exit;
	}

exit:
	BN_CTX_free(ctx);
	return rc;
}

int qinn_srp_calu(BIGNUM *A, BIGNUM *B, BIGNUM *ret) {
	int rc = 0;
	unsigned char digest[20] = { 0 };
	
	rc = _compute_digest_v2(A, B, digest);
	if (rc != 0) {
		goto exit;
	}

	BN_bin2bn(digest, sizeof(digest), ret);
	rc = 1;
exit:
	return rc;
}

int qinn_srp_calk(BIGNUM *N, BIGNUM *g, BIGNUM *ret) {
	int rc = 0;
	unsigned char digest[20] = { 0 };

	rc = _compute_digest_v2(N, g, digest);
	if (rc != 1) {
		goto exit;
	}

	BN_bin2bn(digest, sizeof(digest), ret);
	rc = 1;
exit:
	return rc;
}

int qinn_srp_cal_clientS(BIGNUM *B, BIGNUM *k, BIGNUM *g, BIGNUM *x, BIGNUM *a,
	BIGNUM *u, BIGNUM *N, BIGNUM *ret) {
	int rc = 0;
	BN_CTX *ctx = NULL;
	BIGNUM *b1, *b2;

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	BN_CTX_start(ctx);
	b1 = BN_CTX_get(ctx);
	b2 = BN_CTX_get(ctx);
	if (b2 == NULL) {
		goto exit;
	}

	rc = BN_mod_exp(b1, g, x, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = BN_mod_mul(b1, k, b1, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = BN_mod_sub(b1, B, b1, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = BN_mul(b2, u, x, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = BN_add(b2, a, b2);
	if (rc != 1) {
		goto exit;
	}

	rc = BN_mod_exp(ret, b1, b2, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = 1;
exit:
	BN_CTX_free(ctx);
	return rc;
}

int qinn_srp_cal_serverS(BIGNUM *A, BIGNUM *v, BIGNUM *u, BIGNUM *b, BIGNUM *N, BIGNUM *ret) {
	int rc = 0;
	BN_CTX *ctx = NULL;
	BIGNUM *b1;

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	BN_CTX_start(ctx);
	b1 = BN_CTX_get(ctx);
	if (b1 == NULL) {
		goto exit;
	}

	rc = BN_mod_exp(b1, v, u, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	//BN_mul also OK
	rc = BN_mod_mul(b1, A, b1, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = BN_mod_exp(ret, b1, b, N, ctx);
	if (rc != 1) {
		goto exit;
	}

	rc = 1;
exit:
	BN_CTX_free(ctx);
	return rc;
}

int qinn_srp_calM1(BIGNUM *A, BIGNUM *B, BIGNUM *S, BIGNUM *ret) {
	int rc = 0;
	unsigned char digest[20] = { 0 };

	rc = _compute_digest_v1(A, B, S, digest);
	if (rc != 1) {
		return 0;
	}

	BN_bin2bn(digest, sizeof(digest), ret);
	return 1;
}

int qinn_srp_calM2(BIGNUM *A, BIGNUM *M1, BIGNUM *S, BIGNUM *ret) {
	int rc = 0;
	unsigned char digest[20] = { 0 };

	rc = _compute_digest_v1(A, M1, S, digest);
	if (rc != 1) {
		return 0;
	}

	BN_bin2bn(digest, sizeof(digest), ret);
	return 1;
}

int qinn_srp_calK(BIGNUM *S, BIGNUM *ret) {
	int rc = 0;
	EVP_MD_CTX *ctx = NULL;
	unsigned char digest[20] = { 0 };
	unsigned int digest_len = sizeof(digest);
	unsigned char *buf = NULL;
	int len;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	len = BN_num_bytes(S);

	buf = (unsigned char*)calloc(len, 1);
	if (buf == NULL) {
		goto exit;
	}

	if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) ||
		!EVP_DigestUpdate(ctx, buf, len) ||
		!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
		goto exit;
	}

	BN_bin2bn(digest, digest_len, ret);
	rc = 1;
exit:
	EVP_MD_CTX_free(ctx);
	return rc;
}

static int _compute_digest_v1(BIGNUM *A, BIGNUM *B, BIGNUM *C, unsigned char *out) {
	int rc = 0;
	EVP_MD_CTX *ctx = NULL;
	unsigned char digest[20] = { 0 };
	unsigned int digest_len = sizeof(digest);
	unsigned char *buf1 = NULL;
	unsigned char *buf2 = NULL;
	unsigned char *buf3 = NULL;
	int len1, len2, len3;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	len1 = BN_num_bytes(A);
	len2 = BN_num_bytes(B);
	len3 = BN_num_bytes(C);

	buf1 = (unsigned char*)calloc(len1, 1);
	buf2 = (unsigned char*)calloc(len2, 1);
	buf3 = (unsigned char*)calloc(len3, 1);
	if (buf3 == NULL) {
		goto exit;
	}

	if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) ||
		!EVP_DigestUpdate(ctx, buf1, len1) ||
		!EVP_DigestUpdate(ctx, buf2, len2) ||
		!EVP_DigestUpdate(ctx, buf3, len3) ||
		!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
		goto exit;
	}

	memcpy(out, digest, digest_len);
	rc = 1;
exit:
	EVP_MD_CTX_free(ctx);
	return rc;
}


static int _compute_digest_v2(BIGNUM *A, BIGNUM *B, unsigned char *out) {
	int rc = 0;
	EVP_MD_CTX *ctx = NULL;
	unsigned char digest[20] = { 0 };
	unsigned int digest_len = sizeof(digest);
	unsigned char *buf1 = NULL;
	unsigned char *buf2 = NULL;
	int len1, len2;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	len1 = BN_num_bytes(A);
	len2 = BN_num_bytes(B);

	buf1 = (unsigned char*)calloc(len1, 1);
	buf2 = (unsigned char*)calloc(len2, 1);
	if (buf2 == NULL) {
		goto exit;
	}

	if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) ||
		!EVP_DigestUpdate(ctx, buf1, len1) ||
		!EVP_DigestUpdate(ctx, buf2, len2) ||
		!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
		goto exit;
	}

	memcpy(out, digest, digest_len);
	rc = 1;
exit:
	EVP_MD_CTX_free(ctx);
	return rc;
}