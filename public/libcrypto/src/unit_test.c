#include "unit_test.h"
#include "crypt_aes.h"
#include "crypt_sm2.h"
#include "crypt_ecc.h"
#include "crypt_rsa.h"
#include "crypt_ecdsa.h"
#include "crypt_ecdh.h"
#include "crypt_ot.h"
#include "base64.h"

#include "crypt_speed_test.h"
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

int crypt_ecc_point_mul_test() {
	int ret;
	sm2_key_st sm2key = { 0 };
	EC_POINT *generator = NULL;
	EC_GROUP *gp = NULL;
	EC_POINT *kg = NULL;
	EC_POINT *result1 = NULL;
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

	result1 = qinn_point_generator_mul(gp, k);
	if (result1 == NULL) {
		printf("qinn_point_generator_mul failed\n");
		return 1;
	}

	if (EC_POINT_cmp(gp, kg, result1, ctx) != 0) {
		printf("EC_POINT_cmp failed\n");
		return 1;
	}

	return 0;
}

int crypt_ecc_point_mul_speed_test() {
	int ret;
	sm2_key_st sm2key = { 0 };
	EC_POINT *generator = NULL;
	EC_GROUP *gp = NULL;
	EC_POINT *kg = NULL;
	EC_POINT *result1 = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL, *order = NULL;
	int loops = 10000;
	time_t t1, t2;
	long costtime;

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

	t1 = time(NULL);
	for (int i = 0; i < loops; i++) {
		ret = EC_POINT_mul(gp, kg, k, NULL, NULL, ctx);
		if (ret != 1) {
			return 1;
		}
	}
	t2 = time(NULL);
	costtime = t2 - t1;

	printf("EC_POINT_mul invoked %d times, cost %ld seconds, average \
		%.2f times/seconds\n", loops, costtime, (float)loops/costtime);
	
	t1 = t2 = 0;
	t1 = time(NULL);
	for (int i = 0; i < loops; i++) {
		result1 = qinn_point_generator_mul(gp, k);
		if (result1 == NULL) {
			printf("qinn_point_generator_mul failed\n");
			return 1;
		}
	}
	t2 = time(NULL);
	costtime = t2 - t1;

	printf("qinn_point_generator_mul invoked %d times, cost %ld seconds, average \
		%.2f times/seconds\n", loops, costtime, (float)loops/costtime);

	if (EC_POINT_cmp(gp, kg, result1, ctx) != 0) {
		printf("EC_POINT_cmp failed\n");
		return 1;
	}

	return 0;
}

int qinn_ot_test() {
	int ret;
	unsigned char *prikey1 = NULL;
	unsigned char *prikey2 = NULL;
	unsigned char *pubkey1 = NULL;
	unsigned char *pubkey2 = NULL;
	unsigned char msg1[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	unsigned char msg2[16] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char aeskey[32] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
	unsigned char cipherkey[256] = { 0 };
	unsigned char plainkey1[32] = { 0 };
	unsigned char plainkey2[32] = { 0 };
	unsigned char ciphermsg1[32] = { 0 };
	unsigned char ciphermsg2[32] = { 0 };
	unsigned char plainmsg1[16] = { 0 };
	unsigned char plainmsg2[16] = { 0 };
	unsigned char paddingbuf[128] = { 0 };
	unsigned char plainkey1padbuf[128] = { 0 };
	unsigned char plainkey2padbuf[128] = { 0 };
	int cipherkeylen;
	int plainkey1len = sizeof(plainkey1);
	int plainkey2len = sizeof(plainkey2);
	int prikey1len, prikey2len;
	int pubkey1len, pubkey2len;
	int ciphermsg1len, ciphermsg2len;
	int plainmsg1len, plainmsg2len;
	int plainkey1padbuflen, plainkey2padbuflen;
	int paddinglen;

	//模拟用户a产生两个秘钥对
	ret = qinn_sender_gen_keypair(&prikey1, &prikey1len, 
		&pubkey1, &pubkey1len,
		&prikey2, &prikey2len, 
		&pubkey2, &pubkey2len);
	if (ret != 0) {
		printf("qinn_sender_gen_keypair failed\n");
		return 1;
	}

	//add padding
	memcpy(paddingbuf, aeskey, sizeof(aeskey));
	paddinglen = sizeof(paddingbuf) - sizeof(aeskey);
	for (int i = sizeof(aeskey); i < sizeof(paddingbuf); i++) {
		paddingbuf[i] = paddinglen;
	}
	//模拟用户b随机挑选用户a的一个公钥加密AES密钥
	ret = qinn_receiver_enc_key(pubkey1, pubkey1len,
		paddingbuf, sizeof(paddingbuf), cipherkey, &cipherkeylen);
	if (ret != 0) {
		printf("qinn_receiver_enc_key failed\n");
		return 1;
	}

	//模拟用户a使用自己的两个私钥分别解密AES密钥密文
	ret = qinn_sender_dec_key(prikey1, prikey1len,
		prikey2, prikey2len, cipherkey, cipherkeylen,
		plainkey1padbuf, &plainkey1padbuflen,
		plainkey2padbuf, &plainkey2padbuflen);
	if (ret != 0) {
		printf("qinn_sender_dec_key failed\n");
		return 1;
	}

	//remove padding
	memcpy(plainkey1, plainkey1padbuf, sizeof(plainkey1));
	memcpy(plainkey2, plainkey2padbuf, sizeof(plainkey2));
	
	//模拟用户a分别使用解密出来的两个AES密钥加密自己的两条消息
	ret = qinn_sender_enc_msg(plainkey1, plainkey1len,
		plainkey2, plainkey2len, msg1, sizeof(msg1),
		msg2, sizeof(msg2), ciphermsg1, &ciphermsg1len,
		ciphermsg2, &ciphermsg2len);
	if (ret != 0) {
		printf("qinn_sender_enc_msg failed\n");
		return 1;
	}

	//模拟用户b使用AES密钥分别解密用户a发送的两条密文消息
	ret = qinn_receiver_dec_msg(aeskey, sizeof(aeskey),
		ciphermsg1, ciphermsg1len, ciphermsg2, ciphermsg2len,
		plainmsg1, &plainmsg1len, plainmsg2, &plainmsg2len);
	if (ret != 0) {
		printf("qinn_receiver_dec_msg failed\n");
		return 1;
	}

	//验证用户b是否正确获得用户a的其中一条消息
	if (memcmp(msg1, plainmsg1) == 0 || memcmp(msg2, plainmsg1) == 0) {
		printf("plainmsg1 equal with one of user a msg\n");
		return 0;
	}
	if (memcmp(msg1, plainmsg2) == 0 || memcmp(msg2, plainmsg2) == 0) {
		printf("plainmsg2 equal with one of user a msg\n");
		return 0;
	}

	printf("oblivious transfer failed\n");
	return 1;
}

int rsa_mul_homo_enc_test() {
	int ret;
	//RSA *rsa = NULL;
	BIGNUM *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL;
	BIGNUM *e = NULL, *n = NULL;
	BIGNUM *c1 = NULL, *c2 = NULL, *c3 = NULL, *c4 = NULL;
	uint8_t plain1[128] = { 0 };
	uint8_t plain2[128] = { 0 };
	uint8_t plain3[256] = { 0 };
	uint8_t plain4[128] = { 0 };
	uint8_t cipher1[128] = { 0 };
	uint8_t cipher2[128] = { 0 };
	uint8_t cipher3[128] = { 0 };
	uint8_t cipher4[128] = { 0 };
	int cipher1len, cipher2len, cipher3len, cipher4len;
	int plain3len, plain4len;
	BN_CTX *ctx = NULL;
	qinn_rsa_st rsa_key = { 0 };

	//rsa = RSA_new();
	ctx = BN_CTX_new();

	BN_CTX_start(ctx);
	p1 = BN_CTX_get(ctx);
	p2 = BN_CTX_get(ctx);
	p3 = BN_CTX_get(ctx);
	p4 = BN_CTX_get(ctx);
	e = BN_CTX_get(ctx);
	c1 = BN_CTX_get(ctx);
	c2 = BN_CTX_get(ctx);
	c3 = BN_CTX_get(ctx);
	c4 = BN_CTX_get(ctx);

	BN_set_word(e, 65537);
	/*ret = RSA_generate_key_ex(rsa, 1024, e, NULL);
	if (ret != 1) {
		printf("RSA_generate_key_ex failed\n");
		return 1;
	}*/

	/*n = RSA_get0_n(rsa);
	if (n == NULL) {
		return 1;
	}*/

	qinn_rsa_gen_key(1024, );

	RAND_bytes(plain1, sizeof(plain1));
	RAND_bytes(plain2, sizeof(plain2));

	//模拟对明文p1进行加密 c1 = rsa_enc(plain1)
	cipher1len = RSA_public_encrypt(sizeof(plain1), plain1, cipher1, rsa, RSA_NO_PADDING);
	if (cipher1len <= -1) {
		return 1;
	}

	//模拟对明文p2进行加密 c2 = rsa_enc(plain2)
	cipher2len = RSA_public_encrypt(sizeof(plain2), plain2, cipher2, rsa, RSA_NO_PADDING);
	if (cipher2len <= -1) {
		return 1;
	}

	//对加密结果进行乘法运算  c3 = c1*c2
	if (BN_bin2bn(cipher1, cipher1len, c1) == NULL) {
		return 1;
	}
	if (BN_bin2bn(cipher2, cipher2len, c2) == NULL) {
		return 1;
	}
	ret = BN_mod_mul(c3, c1, c2, n, ctx);
	if (ret != 1) {
		return 1;
	}
	cipher3len = BN_bn2bin(c3, cipher3);
	if (cipher3len <= 1) {
		return 1;
	}

	//计算p3 = p1*p2
	if (BN_bin2bn(plain1, sizeof(plain1), p1) == NULL) {
		return 1;
	}
	if (BN_bin2bn(plain2, sizeof(plain2), p2) == NULL) {
		return 1;
	}
	ret = BN_mul(p3, p1, p2, ctx);
	if (ret != 1) {
		return 1;
	}

	//对p3进行加密 c4 = rsa_enc(p3)
	plain3len = BN_bn2bin(p3, plain3);
	if (plain3len <= 0) {
		return 1;
	}
	cipher4len = RSA_public_encrypt(plain3len, plain3, cipher4, rsa, RSA_NO_PADDING);
	if (cipher4len <= 0) {
		return 1;
	}

	//比较c3 c4是否相等
	if (cipher3len != cipher4len || memcmp(cipher3, cipher4, cipher3len) != 0) {
		printf("cipher text not equal\n");
		return 1;
	}


	//对c3进行解密 p4 = rsa_dec(c3)
	plain4len = RSA_private_decrypt(cipher3len, cipher3, plain4, rsa, RSA_NO_PADDING);
	if (plain4len <= 0) {
		return 1;
	}

	//比较p3 p4是否相等
	if (plain3len != plain4len || memcmp(plain3, plain4, plain3len) != 0) {
		printf("plain text not equal\n");
		return 1;
	}

	printf("rsa mutiply homo test successed\n");
	return 0;
}