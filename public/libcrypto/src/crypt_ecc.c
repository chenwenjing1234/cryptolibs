#include "crypt_ecc.h"
#include "crypt_sm2.h"

char *ecc_sm2_a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";

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
	return ret;
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
	BIGNUM *sm2a = NULL, *x1pow2mul3adda = NULL;
	BIGNUM *dbx1 = NULL, *x1subx2 = NULL;
	BIGNUM *x1subx2mullmda = NULL;

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

	//dby1 = 2*y1 mod n
	ret = BN_mod_mul(dby1, two, y1, n, ctx);
	if (ret != 1) {
		return NULL;
	}
	
	//invdby1 = inverse(dby1) mod n
	if (BN_mod_inverse(invdby1, dby1, n, ctx) == NULL) {
		return NULL;
	}

	//x1pow2 = x1**2 mod n
	ret = BN_mod_exp(x1pow2, x1, two, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	//x1pow2mul3 = 3 * x1**2 mod n
	ret = BN_mod_mul(x1pow2mul3, x1pow2, three, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = BN_hex2bn(&sm2a, ecc_sm2_a);
	if (ret <= 0) {
		return NULL;
	}

	//x1pow2mul3adda = 3 * x1**2 + a mod n
	ret = BN_mod_add(x1pow2mul3adda, x1pow2mul3, sm2a, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	//lmda = (3 * x1**2 + a) / 2y1
	ret = BN_mod_mul(lmda, x1pow2mul3adda, invdby1, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	//lmdapow2 = lmda**2 mod n
	ret = BN_mod_exp(lmdapow2, lmda, two, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	//dbx1 = 2 * x1 mod n
	ret = BN_mod_mul(dbx1, two, x1, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	//x2 = lmdapow2 - 2*x1
	ret = BN_mod_sub(x2, lmdapow2, dbx1, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	//x1subx2 = x1 - x2 mod n
	ret = BN_mod_sub(x1subx2, x1, x2, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	//x1subx2mullmda = lmda*(x1 - x2) mod n 
	ret = BN_mod_mul(x1subx2mullmda, lmda, x1subx2, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	//y2 = x1subx2mullmda - y1 mod n
	ret = BN_mod_sub(y2, x1subx2mullmda, y1, n, ctx);
	if (ret != 1) {
		return NULL;
	}

	ret = EC_POINT_set_affine_coordinates_GFp(gp, pt, x2, y2, ctx);
	if (ret != 1) {
		return NULL;
	}

	return pt;
}