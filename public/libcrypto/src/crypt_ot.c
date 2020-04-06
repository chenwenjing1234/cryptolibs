#include "crypt_ot.h"
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int qinn_sender_gen_keypair(unsigned char **prikey1, int *prikeylen1,
	unsigned char **pubkey1, int *pubkeylen1,
	unsigned char **prikey2, int *prikeylen2,
	unsigned char **pubkey2, int *pubkeylen2
) {
	int ret;
	RSA *rsa1 = NULL, *rsa2 = NULL;
	BIGNUM *e = NULL;


	rsa1 = RSA_new();
	rsa2 = RSA_new();
	e = BN_new();

	BN_set_word(e, 65537);
	ret = RSA_generate_key_ex(rsa1, 1024, e, NULL);
	if (ret != 1) {
		return 1;
	}

	ret = RSA_generate_key_ex(rsa2, 1024, e, NULL);
	if (ret != 1) {
		return 1;
	}

	*prikeylen1 = i2d_RSAPrivateKey(rsa1, prikey1);
	*pubkeylen1 = i2d_RSAPublicKey(rsa1, pubkey1);
	*prikeylen2 = i2d_RSAPrivateKey(rsa2, prikey2);
	*pubkeylen2 = i2d_RSAPublicKey(rsa2, pubkey2);

	return 0;
}

int qinn_receiver_enc_key(unsigned char *pubkey, int pubkeylen,
	unsigned char *plainkey, int plainkeylen,
	unsigned char *cipherkey, int *cipherkeylen) {

	RSA *rsa = NULL;
	unsigned char *p = pubkey;

	if (d2i_RSAPublicKey(&rsa, &p, pubkeylen) == NULL) {
		return 1;
	}

	//加密不能带填充，否则解密的时候移除填充会失败
	*cipherkeylen = RSA_public_encrypt(plainkeylen, plainkey,
		cipherkey, rsa, RSA_NO_PADDING);
	return 0;
}

int qinn_sender_dec_key(unsigned char *prikey1, int prikeylen1,
	unsigned char *prikey2, int prikeylen2,
	unsigned char *cipherkey, int cipherkeylen,
	unsigned char *plainkey1, int *keylen1,
	unsigned char *plainkey2, int *keylen2
) {
	RSA *rsa1 = NULL, *rsa2 = NULL;
	unsigned char *p1 = prikey1;
	unsigned char *p2 = prikey2;

	if (d2i_RSAPrivateKey(&rsa1, &p1, prikeylen1) == NULL) {
		return 1;
	}

	if (d2i_RSAPrivateKey(&rsa2, &p2, prikeylen2) == NULL) {
		return 1;
	}

	//此处不能带填充，否则由于解密出来的数据是无意义的导致移除填充的时候会出错
	*keylen1 = RSA_private_decrypt(cipherkeylen, cipherkey,
		plainkey1, rsa1, RSA_NO_PADDING);
	*keylen2 = RSA_private_decrypt(cipherkeylen, cipherkey,
		plainkey2, rsa2, RSA_NO_PADDING);
	
	return 0;
}

int qinn_sender_enc_msg(unsigned char *key1, int keylen1,
	unsigned char *key2, int keylen2,
	unsigned char *plain1, int plainlen1,
	unsigned char *plain2, int plainlen2,
	unsigned char *cipher1, int *cipherlen1,
	unsigned char *cipher2, int *cipherlen2) {

	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char buffer[128] = { 0 };
	int len1, len2;

	ctx = EVP_CIPHER_CTX_new();

	EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, key1, NULL, 1);
	EVP_CipherUpdate(ctx, buffer, &len1, plain1, plainlen1);
	EVP_CipherFinal_ex(ctx, buffer + len1, &len2);
	*cipherlen1 = len1 + len2;
	memcpy(cipher1, buffer, *cipherlen1);

	EVP_CIPHER_CTX_cleanup(ctx);
	memset(buffer, 0, sizeof(buffer));
	len1 = len2 = 0;

	EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, key2, NULL, 1);
	EVP_CipherUpdate(ctx, buffer, &len1, plain2, plainlen2);
	EVP_CipherFinal_ex(ctx, buffer + len1, &len2);
	*cipherlen2 = len1 + len2;
	memcpy(cipher2, buffer, *cipherlen2);

	return 0;
}

int qinn_receiver_dec_msg(unsigned char *key, int keylen,
	unsigned char *cipher1, int cipherlen1,
	unsigned char *cipher2, int cipherlen2,
	unsigned char *plain1, int *plainlen1,
	unsigned char *plain2, int *plainlen2) {

	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char buffer[128] = { 0 };
	int len1, len2;

	ctx = EVP_CIPHER_CTX_new();

	EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL, 0);
	EVP_CipherUpdate(ctx, buffer, &len1, cipher1, cipherlen1);
	EVP_CipherFinal_ex(ctx, buffer + len1, &len2);
	*plainlen1 = len1 + len2;
	memcpy(plain1, buffer, *plainlen1);

	EVP_CIPHER_CTX_cleanup(ctx);
	memset(buffer, 0, sizeof(buffer));
	len1 = len2 = 0;

	EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL, 0);
	EVP_CipherUpdate(ctx, buffer, &len1, cipher1, cipherlen1);
	EVP_CipherFinal_ex(ctx, buffer + len1, &len2);
	*plainlen2 = len1 + len2;
	memcpy(plain2, buffer, *plainlen2);

	return 0;
}