#include "crypt_ecdsa.h"

int qinn_ecdsa_sign(EC_KEY *eckey, EVP_MD *md, unsigned char *msg, int inlen,
	unsigned char *sigr, int *rlen, unsigned char *sigs, int *slen) {
	int ret;
	BIGNUM *k = NULL;
	BIGNUM *n = NULL;
	BIGNUM *x1 = NULL;
	BIGNUM *invk = NULL;
	BIGNUM *sk = NULL;
	BIGNUM *dr = NULL;
	BIGNUM *hm = NULL;
	BIGNUM *s = NULL;
	BN_CTX *ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *kg = NULL;
	uint8_t hash[32] = { 0 };
	EVP_MD_CTX *mdctx = NULL;
	int hash_len = sizeof(hash);
	uint8_t rbuf[32] = { 0 };
	uint8_t sbuf[32] = { 0 };
	int rbuf_len, sbuf_len;
	int padlen = 0;

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, msg, inlen);
	EVP_DigestFinal_ex(mdctx, hash, &hash_len);

	k = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	invk = BN_CTX_get(ctx);
	dr = BN_CTX_get(ctx);
	hm = BN_CTX_get(ctx);
	s = BN_CTX_get(ctx);

	group = EC_KEY_get0_group(eckey);
	if (group == NULL) {
		return 1;
	}
	
	ret = EC_GROUP_get_order(group, n, ctx);
	if (ret != 1) {
		return 1;
	}

	BN_rand_range(k, n);

	if (BN_mod_inverse(invk, k, n, ctx) == NULL) {
		return 1;
	}

	kg = EC_POINT_new(group);
	if (kg == NULL) {
		return 1;
	}

	ret = EC_POINT_mul(group, kg, k, NULL, NULL, ctx);
	if (ret != 1) {
		return 1;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(group, kg, 
		  x1, NULL, ctx);
	if (ret != 1) {
		return 1;
	}

	sk = EC_KEY_get0_private_key(eckey);
	if (sk == NULL) {
		return 1;
	}

	ret = BN_mod_mul(dr, sk, x1, n, ctx);
	if (ret != 1) {
		return 1;
	}

	BN_bin2bn(hash, hash_len, hm);

	BN_mod_add(s, hm, dr, n, ctx);

	ret = BN_mod_mul(s, invk, s, n, ctx);
	if (ret != 1) {
		return 1;
	}

	rbuf_len = BN_bn2bin(x1, rbuf);
	sbuf_len = BN_bn2bin(s, sbuf);

	if (rbuf_len < 32) {
		padlen = 32 - rbuf_len;
	}
	memcpy(sigr + padlen, rbuf, rbuf_len);

	if (sbuf_len < 32) {
		padlen = 32 - sbuf_len;
	}
	memcpy(sigs + padlen, sbuf, sbuf_len);

	*rlen = sizeof(rbuf);
	*slen = sizeof(sbuf);

	BN_CTX_free(ctx);
	EVP_MD_CTX_free(mdctx);
	EC_POINT_free(kg);
	return 0;
}

int qinn_ecdsa_verify(EC_KEY *eckey, EVP_MD *md, unsigned char *msg, int inlen,
	unsigned char *sigr, int rlen, unsigned char *sigs, int slen) {
	int ret;
	BIGNUM *n = NULL;
	BIGNUM *r = NULL;
	BIGNUM *invs = NULL;
	BIGNUM *u1 = NULL;
	BIGNUM *u2 = NULL;
	BIGNUM *hm = NULL;
	BIGNUM *s = NULL;
	BIGNUM *x = NULL;
	BN_CTX *ctx = NULL;
	EC_GROUP *group = NULL;
	uint8_t hash[32] = { 0 };
	EVP_MD_CTX *mdctx = NULL;
	int hash_len = sizeof(hash);
	EC_POINT *t = NULL;
	EC_POINT *pk = NULL;

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, msg, inlen);
	EVP_DigestFinal_ex(mdctx, hash, &hash_len);
	
	n = BN_CTX_get(ctx);
	r = BN_CTX_get(ctx);
	invs = BN_CTX_get(ctx);
	u1 = BN_CTX_get(ctx);
	u2 = BN_CTX_get(ctx);
	s = BN_CTX_get(ctx);
	x = BN_CTX_get(ctx);
	hm = BN_CTX_get(ctx);
	if (hm == NULL) {
		return 1;
	}

	BN_bin2bn(hash, hash_len, hm);

	group = EC_KEY_get0_group(eckey);
	if (group == NULL) {
		return 1;
	}

	ret = EC_GROUP_get_order(group, n, ctx);
	if (ret != 1) {
		return 1;
	}

	BN_bin2bn(sigs, slen, s);
	BN_bin2bn(sigr, rlen, r);

	if (BN_mod_inverse(invs, s, n, ctx) == NULL) {
		return 1;
	}

	ret = BN_mod_mul(u1, hm, invs, n, ctx);
	if (ret != 1) {
		return 1;
	}

	ret = BN_mod_mul(u2, r, invs, n, ctx);
	if (ret != 1) {
		return 1;
	}

	t = EC_POINT_new(group);
	pk = EC_KEY_get0_public_key(eckey);
	if (pk == NULL) {
		return 1;
	}

	ret = EC_POINT_mul(group, t, u1, pk, u2, ctx);
	if (ret != 1) {
		return 1;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(group, t, x, NULL, ctx);
	if (ret != 1) {
		return 1;
	}

	ret = BN_cmp(r, x);
	if (ret != 0) {
		return 1;
	}

	BN_CTX_free(ctx);
	EVP_MD_CTX_free(mdctx);
	EC_POINT_free(t);
	return 0;
}

