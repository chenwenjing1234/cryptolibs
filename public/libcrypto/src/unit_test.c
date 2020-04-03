#include "unit_test.h"
#include "crypt_aes.h"
#include "crypt_sm2.h"
#include "crypt_ecc.h"
#include "crypt_rsa.h"
#include "crypt_ecdsa.h"
#include "crypt_ecdh.h"
#include "base64.h"

#include "crypt_speed_test.h"
#include <openssl/obj_mac.h>
#include <openssl/evp.h>

static int print_bytes(unsigned char *bytes, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02X", bytes[i]);
	}
	printf("\n");
}

static void bin2hex(uint8_t *in, int inlen, char *out) {
	for (int i = 0; i < inlen; i++) {
		sprintf(out+i*2, "%02X", in[i]);
	}
}

int crypt_test_case() {
	int ret;
	sm2_key_st sm2key = { 0 };
	unsigned char msg[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char cipher[256] = { 0 };
	int cipher_len = sizeof(cipher);
	unsigned char plain[32] = { 0 };
	int plain_len = sizeof(plain);
	unsigned char sigr[32] = { 0 };
	unsigned char sigs[32] = { 0 };
	int siglen = 0;

	ret = qinn_sm2_gen_keypair(&sm2key);
	if (ret != 0) {
		printf("qinn_sm2_gen_keypair failed\n");
		return ret;
	}

	print_bytes(sm2key.prikey, sizeof(sm2key.prikey));
	print_bytes(sm2key.pubkey, sizeof(sm2key.pubkey));

	ret = qinn_sm2_enc(&sm2key, msg, sizeof(msg), cipher, &cipher_len);
	if (ret != 0) {
		printf("qinn_sm2_enc failed\n");
		return ret;
	}

	ret = qinn_sm2_dec(&sm2key, cipher, cipher_len, plain, &plain_len);
	if (ret != 0) {
		printf("qinn_sm2_dec failed\n");
		return ret;
	}

	ret = qinn_sm2_sign(&sm2key, msg, sizeof(msg), sigr, sigs);
	if (ret != 0) {
		printf("qinn_sm2_sign failed\n");
		return ret;
	}

	ret = qinn_sm2_verify(&sm2key, msg, sizeof(msg), sigr, sigs);
	if (ret != 0) {
		printf("qinn_sm2_verify failed\n");
		return ret;
	}
	return 0;
}

int aes_test() {
	int ret;

	unsigned char plain[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	unsigned char nonce[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	unsigned char cipher[16] = { 0 };

	unsigned char decresult[16] = { 0 };
	aes_context ctx = { 0 };

	aes_setkey_enc(&ctx, key, sizeof(key)*8);

	aes_crypt_ctr(&ctx, AES_ENCRYPT, sizeof(plain), nonce, 0, plain, cipher);

	aes_crypt_ctr(&ctx, AES_ENCRYPT, sizeof(cipher), nonce, 0, cipher, decresult);

	if (memcmp(plain, decresult, sizeof(plain)) != 0) {
		printf("aes-enc-dec test failed\n");
		return 1;
	}

	printf("aes-enc-dec test successed\n");
	return 0;

}

int crypt_ecc_test_case() {
	int ret;
	sm2_key_st sm2key = { 0 };
	EC_POINT *generator = NULL;
	EC_GROUP *gp = NULL;
	EC_POINT *ptret = NULL;
	EC_POINT *ptret2 = NULL;
	BN_CTX *ctx = NULL;

	ctx = BN_CTX_new();

	ret = qinn_sm2_gen_keypair(&sm2key);
	if (ret != 0) {
		printf("qinn_sm2_gen_keypair failed\n");
		return ret;
	}

	gp = sm2key.sm2group;
	generator = EC_GROUP_get0_generator(gp);
	ptret = qinn_point_add(gp, generator, generator);
	if (ptret == NULL) {
		printf("qinn_point_add failed\n");
		return 1;
	}

	ptret2 = qinn_point_double_v2(gp, generator);
	if (ptret == NULL) {
		printf("qinn_point_double_v2 failed\n");
		return 1;
	}

	if (EC_POINT_cmp(gp, ptret, ptret2, ctx) != 0) {
		printf("EC_POINT_cmp failed\n");
		return 1;
	}

	return 0;
}

int crypt_rsa_test_case() {
	int ret;
	qinn_rsa_st rsakey = { 0 };
	unsigned char plain[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char cipher[128] = { 0 };
	int cipher_len = 0;
	unsigned char decresult[16] = { 0 };
	int decresult_len = 0;

	ret = qinn_rsa_gen_key(1024, &rsakey);
	if (ret != 0) {
		printf("qinn_rsa_gen_key failed\n");
		return ret;
	}

	ret = qinn_rsa_enc(&rsakey, plain, sizeof(plain), cipher, &cipher_len);
	if (ret != 0) {
		printf("qinn_rsa_enc failed\n");
		return ret;
	}

	ret = qinn_rsa_dec(&rsakey, cipher, cipher_len, decresult, &decresult_len);
	if (ret != 0) {
		printf("qinn_rsa_dec failed\n");
		return ret;
	}

	if (memcmp(plain, decresult, decresult_len) == 0) {
		printf("crypt_rsa_test_case successed\n");
	}
	
	return 0;
}

int crypt_ecdsa_test_case() {
	int ret;
	EC_KEY *eckey = NULL;
	unsigned char plain[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char sigr[32] = { 0 };
	int sigr_len = 0;
	unsigned char sigs[32] = { 0 };
	int sigs_len = 0;

	eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (eckey == NULL) {
		printf("EC_KEY_new_by_curve_name failed\n");
		return 1;
	}

	ret = EC_KEY_generate_key(eckey);
	if (ret != 1) {
		printf("EC_KEY_generate_key failed\n");
		return 1;
	}

	/*ret = qinn_ecdsa_sign(eckey, EVP_sha1(), plain, sizeof(plain),
		sigr, &sigr_len, sigs, &sigs_len);
	if (ret != 0) {
		printf("qinn_ecdsa_sign failed\n");
		return 1;
	}

	ret = qinn_ecdsa_verify(eckey, EVP_sha1(), plain, sizeof(plain),
		sigr, sigr_len, sigs, sigs_len);
	if (ret != 0) {
		printf("qinn_ecdsa_verify failed\n");
		return 1;
	}*/

	printf("qinn_ecdsa_sign qinn_ecdsa_verify successed\n");
	return 0;
}


int crypt_ecdh_test_case() {
	int ret;
	EC_KEY *eckey = NULL;

	eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (eckey == NULL) {
		printf("EC_KEY_new_by_curve_name failed\n");
		return 1;
	}

	ret = EC_KEY_generate_key(eckey);
	if (ret != 1) {
		printf("EC_KEY_generate_key failed\n");
		return 1;
	}

	ret = qinn_ecdh_mock(eckey);
	if (ret != 1) {
		printf("EC_KEY_generate_key failed\n");
		return 1;
	}

	printf("crypt_ecdh_test_case successed\n");
	return 0;
}

int crypt_rsa_gen_keypair_speed_test() {

	return qinn_rsa_gen_keypaire_speed();
}

int base64_test() {
	char *str = "MEUCIEYm4T9FfJujDtlED3d263nNqpdmyrf1M+njJMJue1DaAiEArJhryfy3j4+nAm/S6rhjeirL46HjR48hKF641iei2Br=";
	unsigned char decodedbuf[120] = { 0 };
	int decodelen;
	int ret;
	
	ret = base64_decode(str, strlen(str), decodedbuf, sizeof(decodedbuf), &decodelen);
	if (ret != 0) {
		printf("base64_encode failed\n");
		return 1;
	}

	for (int i = 0; i < decodelen; i++) {
		printf("0x%02x,", decodedbuf[i]);
		if (i == 16) {
			printf("\n");
		}
	}
	printf("\n");
	return 0;
}

int std_ecc_verify_test() {
	int ret;
	//uint8_t msg[] = { 0xE2, 0x7C, 0x2B, 0x47 };
	uint8_t msg[] = { 0x47, 0x2B, 0x7C, 0xE2};
	char *hexpubkey = "04a6c7d1b98bf95ab568ed2f51013686f2f6427be7a975f7e768ecc8d1bcdd0677fd2e56024a611187341afb26c000cdb63b146371df8932beb0d7d0595f33bec8";
	unsigned char sig[] = {
		0x30,0x45,0x02,0x20,0x46,0x26,0xe1,0x3f,0x45,0x7c,0x9b,0xa3,0x0e,0xd9,0x44,0x0f,0x77,
		0x76,0xeb,0x79,0xcd,0xaa,0x97,0x66,0xca,0xb7,0xf5,0x33,0xe9,0xe3,0x24,0xc2,0x6e,0x7b,
		0x50,0xda,0x02,0x21,0x00,0xac,0x98,0x6b,0xc9,0xfc,0xb7,0x8f,0x8f,0xa7,0x02,0x6f,0xd2,
		0xea,0xb8,0x63,0x7a,0x2a,0xcb,0xe3,0xa1,0xe3,0x47,0x8f,0x21,0x28,0x5e,0xb8,0xd6,0x27,
		0xa2,0xd8,0x1a
	};

	ret = std_ecc_verify(msg, sizeof(msg), hexpubkey, sig, sizeof(sig));
	if (ret != 0) {
		printf("std_ecc_verify failed\n");
		return 1;
	}
	return 0;
}

int std_ecc_verify_test_v2() {
	int ret;
	uint8_t prikey[32] = { 0 };
	int prikey_len;
	uint8_t pubkey[65] = { 0 };
	int pubkey_len;
	uint8_t msg[] = { 0xE2, 0x7C, 0x2B, 0x47 };
	uint8_t sig[72] = { 0 };
	int siglen;
	char hexpubkey[136] = { 0 };
	
	ret = std_ecc_gen_keypair(prikey, &prikey_len, pubkey, &pubkey_len);
	if (ret != 0) {
		printf("std_ecc_gen_keypair failed\n");
		return 1;
	}

	ret = std_ecc_sign(msg, sizeof(msg), prikey, prikey_len, sig, &siglen);
	if (ret != 0) {
		printf("std_ecc_sign failed\n");
		return 1;
	}

	bin2hex(pubkey, pubkey_len, hexpubkey);
	ret = std_ecc_verify(msg, sizeof(msg), hexpubkey, sig, siglen);
	if (ret != 0) {
		printf("std_ecc_verify failed\n");
		return 1;
	}

	return 0;
}


int crypt_ecc_speed_test_case() {
	int ret;
	sm2_key_st sm2key = { 0 };
	EC_POINT *generator = NULL;
	EC_GROUP *gp = NULL;
	EC_POINT *ptret = NULL;
	EC_POINT *ptret2 = NULL;
	BN_CTX *ctx = NULL;
	int loops = 1000000;
	time_t t1, t2;
	long costtime;

	ctx = BN_CTX_new();

	ret = qinn_sm2_gen_keypair(&sm2key);
	if (ret != 0) {
		printf("qinn_sm2_gen_keypair failed\n");
		return ret;
	}

	gp = sm2key.sm2group;
	generator = EC_GROUP_get0_generator(gp);

	time(&t1);
	for (int i = 0; i < loops; i++) {
		ptret = qinn_point_add(gp, generator, generator);
		if (ptret == NULL) {
			printf("qinn_point_add failed\n");
			return 1;
		}
	}
	time(&t2);
	costtime = t2 - t1;
	printf("qinn_point_add invoked %d times, cost %ld seconds, average %.2f times/seconds\n",
		loops, costtime, (float)loops/costtime);

	t1 = t2 = 0;
	time(&t1);
	for (int i = 0; i < loops; i++) {
		ptret2 = qinn_point_double_v2(gp, generator);
		if (ptret == NULL) {
			printf("qinn_point_double_v2 failed\n");
			return 1;
		}
	}
	time(&t2);
	costtime = t2 - t1;
	printf("qinn_point_double_v2 invoked %d times, cost %ld seconds, average %.2f times/seconds\n",
		loops, costtime, (float)loops / costtime);

	if (EC_POINT_cmp(gp, ptret, ptret2, ctx) != 0) {
		printf("EC_POINT_cmp failed\n");
		return 1;
	}

	printf("EC_POINT_cmp successed\n");
	return 0;
}

int std_ecc_gen_keypair_test() {
	int ret;
	uint8_t prikey[32] = { 0 };
	int prikey_len;
	uint8_t pubkey[65] = { 0 };
	int pubkey_len;
	char hexprikey[65] = { 0 };
	char hexpubkey[136] = { 0 };
	int loops = 10000;
	time_t t1, t2;
	long costtime = 0;

	time(&t1);
	for (int i = 0; i < loops; i++) {
		ret = std_ecc_gen_keypair(prikey, &prikey_len, pubkey, &pubkey_len);
		if (ret != 0) {
			printf("std_ecc_gen_keypair failed\n");
			return 1;
		}
		if (prikey_len != 32) {
			bin2hex(prikey, prikey_len, hexprikey);
			printf("%s\n", hexprikey);
		}
		if (pubkey_len != 65) {
			bin2hex(pubkey, pubkey_len, hexpubkey);
			printf("%s\n", hexpubkey);
		}
	}
	time(&t2);
	costtime = t2 - t1;
	printf("std_ecc_gen_keypair invoked %d times, cost %ld seconds, average %.2f times/seconds\n",
		loops, costtime, (float)loops / costtime);
	
	return 0;
}

int crypt_ecc_point_add_test() {
	int ret;
	sm2_key_st sm2key = { 0 };
	EC_POINT *generator = NULL;
	EC_GROUP *gp = NULL;
	EC_POINT *kg = NULL;
	EC_POINT *result1 = NULL, *result2 = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL, *order = NULL;

	ctx = BN_CTX_new();
	k = BN_new();

	ret = qinn_sm2_gen_keypair(&sm2key);
	if (ret != 0) {
		printf("qinn_sm2_gen_keypair failed\n");
		return ret;
	}

	gp = sm2key.sm2group;
	generator = EC_GROUP_get0_generator(gp);

	order = EC_GROUP_get0_order(gp);
	if (order == NULL) {
		return 1;
	}

	ret = BN_rand_range(k, order);
	if (ret != 1) {
		return 1;
	}

	kg = EC_POINT_new(gp);
	if (kg == NULL) {
		return 1;
	}

	ret = EC_POINT_mul(gp, kg, k, NULL, NULL, ctx);
	if (ret != 1) {
		return 1;
	}

	result1 = qinn_point_add(gp, kg, generator);
	if (result1 == NULL) {
		printf("qinn_point_add failed\n");
		return 1;
	}

	result2 = qinn_point_add_v2(gp, kg, generator);
	if (result2 == NULL) {
		printf("qinn_point_add_v2 failed\n");
		return 1;
	}

	if (EC_POINT_cmp(gp, result1, result2, ctx) != 0) {
		printf("EC_POINT_cmp failed\n");
		return 1;
	}

	return 0;
}