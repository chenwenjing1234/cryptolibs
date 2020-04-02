#include "crypt_ecdh.h"

int qinn_ecdh_mock(EC_KEY *eckey) {
	int ret;
	BN_CTX *ctx = NULL;
	EC_POINT *g = NULL;
	BIGNUM *a = NULL, *b = NULL;
	BIGNUM *n = NULL;
	EC_GROUP *gp = NULL;
	EC_POINT *A = NULL, *B = NULL;
	EC_POINT *KA = NULL, *KB = NULL;
	BIGNUM *KAX = NULL, *KAY = NULL;
	BIGNUM *KBX = NULL, *KBY = NULL;

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	KAX = BN_CTX_get(ctx);
	KAY = BN_CTX_get(ctx);
	KBX = BN_CTX_get(ctx);
	KBY = BN_CTX_get(ctx);

	gp = EC_KEY_get0_group(eckey);

	n = EC_GROUP_get0_order(gp);

	//ģ���û�1����a��A A=a*G
	ret = BN_rand_range(a, n);
	if (ret != 1) {
		return 0;
	}

	A = EC_POINT_new(gp);
	ret = EC_POINT_mul(gp, A, a, NULL, NULL, ctx);
	if (ret != 1) {
		return 0;
	}

	//ģ���û�2����b��B B=b*G
	ret = BN_rand_range(b, n);
	if (ret != 1) {
		return 0;
	}

	B = EC_POINT_new(gp);
	ret = EC_POINT_mul(gp, B, b, NULL, NULL, ctx);
	if (ret != 1) {
		return 0;
	}

	//ģ����ԿЭ�̹��� K = a*B = b*A = a*b*G
	KA = EC_POINT_new(gp);
	KB = EC_POINT_new(gp);

	//�û�1����K = a*B
	ret = EC_POINT_mul(gp, KA, NULL, B, a, ctx);
	if (ret != 1) {
		return 0;
	}

	//�û�2����K = b*A
	ret = EC_POINT_mul(gp, KB, NULL, A, b, ctx);
	if (ret != 1) {
		return 0;
	}

	//�Ƚ��û�1���û���������ĵ������Ƿ����
	ret = EC_POINT_get_affine_coordinates_GFp(gp, KA, KAX, KAY, ctx);
	if (ret != 1) {
		return 0;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(gp, KB, KBX, KBY, ctx);
	if (ret != 1) {
		return 1;
	}

	if (BN_cmp(KAX, KBX) != 0 || BN_cmp(KAY, KBY) != 0) {
		return 0;
	}

	BN_CTX_end(ctx);

	return 1;
}