#include "crypt_ecc.h"
#include "crypt_sm2.h"

#include <openssl/obj_mac.h>
#include <openssl/sha.h>

EC_POINT* qinn_point_add(EC_GROUP *gp, EC_POINT *a, EC_POINT *b) {
	int ret;
	EC_POINT *pt = NULL;
	BN_CTX *ctx = NULL;

	pt = EC_POINT_new(gp);
	ctx = BN_CTX_new();

	ret = EC_POINT_add(gp, pt, a, b, ctx);
	if (ret != 1) {
		return NULL;
	}
	return pt;
}

EC_POINT* qinn_point_double(EC_GROUP *gp, EC_POINT *a) {
	int ret;
	EC_POINT *pt = NULL;
	BN_CTX *ctx = NULL;

	pt = EC_POINT_new(gp);
	ctx = BN_CTX_new();

	ret = EC_POINT_dbl(gp, pt, a, ctx);
	if (ret != 1) {
		return NULL;
	}
	return ret;
}

//SM2256P 倍点运算
EC_POINT* qinn_point_double_v2(EC_GROUP *gp, EC_POINT *a) {
	int ret;
	EC_POINT *pt = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *lmda = NULL, *lmdapow2 = NULL;
	BIGNUM *x1 = NULL, *y1 = NULL;
	BIGNUM *x2 = NULL, *y2 = NULL;
	BIGNUM * dby1 = NULL, *two = NULL, *three = NULL;
	BIGNUM *n = NULL, *invdby1 = NULL;
	BIGNUM *x1pow2 = NULL, *x1pow2mul3 = NULL;
	BIGNUM *x1pow2mul3adda = NULL;
	BIGNUM *dbx1 = NULL, *x1subx2 = NULL;
	BIGNUM *x1subx2mullmda = NULL;
	BIGNUM *sm2p = NULL, *sm2a = NULL, *sm2b = NULL;

	pt = EC_POINT_new(gp);
	ctx = BN_CTX_new();

	BN_CTX_start(ctx);

	lmda = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	y1 = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);
	dby1 = BN_CTX_get(ctx);
	two = BN_CTX_get(ctx);
	three = BN_CTX_get(ctx);
	invdby1 = BN_CTX_get(ctx);
	x1pow2 = BN_CTX_get(ctx);
	x1pow2mul3 = BN_CTX_get(ctx);
	x1pow2mul3adda = BN_CTX_get(ctx);
	lmdapow2 = BN_CTX_get(ctx);
	dbx1 = BN_CTX_get(ctx);
	x1subx2 = BN_CTX_get(ctx);
	x1subx2mullmda = BN_CTX_get(ctx);
	sm2p = BN_CTX_get(ctx);
	sm2a = BN_CTX_get(ctx);
	sm2b = BN_CTX_get(ctx);

	BN_set_word(two, 2);
	BN_set_word(three, 3);

	ret = EC_POINT_get_affine_coordinates_GFp(gp, a, x1, y1, ctx);
	if (ret != 1) {
		return NULL;
	}

	n = EC_GROUP_get0_order(gp);
	if (n == NULL) {
		return NULL;
	}

	ret = EC_GROUP_get_curve_GFp(gp, sm2p, sm2a, sm2b, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mul(dby1, two, y1, ctx);
	if (ret != 1) {
		return NULL;
	}
	
	if (BN_mod_inverse(invdby1, dby1, sm2p, ctx) == NULL) {
		return NULL;
	}

	ret = BN_exp(x1pow2, x1, two, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mul(x1pow2mul3, x1pow2, three, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_add(x1pow2mul3adda, x1pow2mul3, sm2a, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mod_mul(lmda, x1pow2mul3adda, invdby1, sm2p, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_exp(lmdapow2, lmda, two, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mul(dbx1, two, x1, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mod_sub(x2, lmdapow2, dbx1, sm2p, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_sub(x1subx2, x1, x2, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mul(x1subx2mullmda, lmda, x1subx2, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mod_sub(y2, x1subx2mullmda, y1, sm2p, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = EC_POINT_set_affine_coordinates_GFp(gp, pt, x2, y2, ctx);
	if (ret != 1) {
		return NULL;
	}

	return pt;
}


//SM2256P 点加运算
EC_POINT* qinn_point_add_v2(EC_GROUP *gp, EC_POINT *a, EC_POINT *b) {
	int ret;
	EC_POINT *pt = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *lmda = NULL, *lmdapow2 = NULL;
	BIGNUM *x1 = NULL, *y1 = NULL;
	BIGNUM *x2 = NULL, *y2 = NULL;
	BIGNUM *x3 = NULL, *y3 = NULL;
	BIGNUM *x2subx1 = NULL, *invx2subx1 = NULL;
	BIGNUM *x1addx2 = NULL, *y2suby1 = NULL;
	BIGNUM *x1subx3 = NULL, *lmdamulx1subx3 = NULL;
	BIGNUM *two = NULL, *three = NULL;
	BIGNUM *sm2p = NULL, *sm2a = NULL, *sm2b = NULL;

	pt = EC_POINT_new(gp);
	ctx = BN_CTX_new();

	BN_CTX_start(ctx);

	lmda = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	y1 = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);
	two = BN_CTX_get(ctx);
	three = BN_CTX_get(ctx);
	lmdapow2 = BN_CTX_get(ctx);
	sm2p = BN_CTX_get(ctx);
	sm2a = BN_CTX_get(ctx);
	sm2b = BN_CTX_get(ctx);
	x3 = BN_CTX_get(ctx);
	y3 = BN_CTX_get(ctx);
	x2subx1 = BN_CTX_get(ctx);
	invx2subx1 = BN_CTX_get(ctx);
	x1addx2 = BN_CTX_get(ctx);
	x1subx3 = BN_CTX_get(ctx);
	lmdamulx1subx3 = BN_CTX_get(ctx);
	y2suby1 = BN_CTX_get(ctx);

	BN_set_word(two, 2);
	BN_set_word(three, 3);

	ret = EC_POINT_get_affine_coordinates_GFp(gp, a, x1, y1, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(gp, b, x2, y2, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = EC_GROUP_get_curve_GFp(gp, sm2p, sm2a, sm2b, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_sub(x2subx1, x2, x1);
	if (ret != 1) {
		return NULL;
	}

	if (BN_mod_inverse(invx2subx1, x2subx1, sm2p, ctx) == NULL) {
		return NULL;
	}

	ret = BN_sub(y2suby1, y2, y1);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mod_mul(lmda, y2suby1, invx2subx1, sm2p, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_exp(lmdapow2, lmda, two, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_add(x1addx2, x1, x2);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mod_sub(x3, lmdapow2, x1addx2, sm2p, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_sub(x1subx3, x1, x3);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mul(lmdamulx1subx3, lmda, x1subx3, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_mod_sub(y3, lmdamulx1subx3, y1, sm2p, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = EC_POINT_set_affine_coordinates_GFp(gp, pt, x3, y3, ctx);
	if (ret != 1) {
		return NULL;
	}

	return pt;
}

int std_ecc_verify(uint8_t *msg, int msglen, char *pubkey, uint8_t *sig, int siglen) {
	int ret;
	EC_KEY *eckey = NULL;
	EC_POINT *pub_key = NULL;
	EC_GROUP *gp = NULL;
	BN_CTX *ctx = NULL;
	
	unsigned char digest[32] = { 0 };
	int digestlen;

	ctx = BN_CTX_new();

	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL) {
		return 1;
	}

	gp = EC_KEY_get0_group(eckey);
	if (gp == NULL) {
		return 1;
	}

	pub_key = EC_POINT_new(gp);
	if (pub_key == NULL) {
		return 1;
	}

	if (EC_POINT_hex2point(gp, pubkey, pub_key, ctx) == NULL) {
		return NULL;
	}

	ret = EC_KEY_set_public_key(eckey, pub_key);
	if (ret != 1) {
		return 1;
	}

	//TODO
	SHA256(msg, msglen, digest);

	ret = ECDSA_verify(0, digest, sizeof(digest), sig, siglen, eckey);
	if (ret != 1) {
		return 1;
	}

	return 0;
}

int std_ecc_gen_keypair(uint8_t *prikey, int *prikey_len, uint8_t *pubkey, int *pubkey_len) {
	int ret;
	EC_KEY *eckey = NULL;
	const BIGNUM *pri = NULL;
	const EC_POINT *pub = NULL;
	const BIGNUM *x = NULL;
	const BIGNUM *y = NULL;
	EC_GROUP *gp = NULL;
	BN_CTX *ctx = NULL;
	int xlen, ylen;

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);


	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL) {
		return 1;
	}

	gp = EC_KEY_get0_group(eckey);
	if (gp == NULL) {
		return 1;
	}

	ret = EC_KEY_generate_key(eckey);
	if (ret != 1) {
		return 1;
	}

	pri = EC_KEY_get0_private_key(eckey);
	if (pri == NULL) {
		return 1;
	}

	*prikey_len = BN_bn2bin(pri, prikey);

	pub = EC_KEY_get0_public_key(eckey);
	if (pub == NULL) {
		return 1;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(gp, pub, x, y, ctx);
	if (ret != 1) {
		return 1;
	}

	pubkey[0] = 0x04;
	xlen = BN_bn2bin(x, pubkey+1);
	
	ylen = BN_bn2bin(y, pubkey + 1 + xlen);
	*pubkey_len = 1 + xlen + ylen;

	return 0;
}

int std_ecc_sign(uint8_t *msg, int msglen, unsigned char *prikey, int prikey_len, uint8_t *sig, int *siglen) {
	int ret;
	EC_KEY *eckey = NULL;
	BIGNUM *pri_key = NULL;
	EC_GROUP *gp = NULL;
	BN_CTX *ctx = NULL;

	unsigned char digest[32] = { 0 };
	int digestlen;

	ctx = BN_CTX_new();
	pri_key = BN_new();

	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL) {
		return 1;
	}

	gp = EC_KEY_get0_group(eckey);
	if (gp == NULL) {
		return 1;
	}

	BN_bin2bn(prikey, prikey_len, pri_key);

	ret = EC_KEY_set_private_key(eckey, pri_key);
	if (ret != 1) {
		return 1;
	}

	//TODO
	SHA256(msg, msglen, digest);

	ECDSA_sign(0, digest, sizeof(digest), sig, siglen, eckey);
	if (ret != 1) {
		return 1;
	}

	return 0;
}

//return k*G
EC_POINT* qinn_point_generator_mul(EC_GROUP *gp, BIGNUM *k) {
	int ret;
	int bits;
	EC_POINT *G = NULL;
	EC_POINT *P = NULL, *Q = NULL;
	BN_CTX *ctx = NULL;

	ctx = BN_CTX_new();
	bits = BN_num_bits(k);
	G = EC_GROUP_get0_generator(gp);
	if (G == NULL) {
		return NULL;
	}

	P = EC_POINT_new(gp);
	Q = EC_POINT_new(gp);

	ret = EC_POINT_copy(P, G);
	if (ret != 1) {
		return NULL;
	}

	ret = EC_POINT_set_to_infinity(gp, Q);
	if (ret != 1) {
		return NULL;
	}

	for (int i = 0; i < bits; i++) {
		if (i == 0) {
			if (BN_is_bit_set(k, i)) {
				ret = EC_POINT_add(gp, Q, Q, P, ctx);
				if (ret != 1) {
					return NULL;
				}
			}
			continue;
		}

		ret = EC_POINT_dbl(gp, P, P, ctx);
		if (ret != 1) {
			return NULL;
		}

		if (BN_is_bit_set(k, i)) {
			ret = EC_POINT_add(gp, Q, Q, P, ctx);
			if (ret != 1) {
				return NULL;
			}
		}
	}

	return Q;
}