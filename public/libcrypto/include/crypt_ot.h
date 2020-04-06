#ifndef __CRYPT_OBLIVIOUS_TRANSFER_H
#define __CRYPT_OBLIVIOUS_TRANSFER_H

#include <openssl/bn.h>

int qinn_sender_gen_keypair(unsigned char **prikey1, int *prikeylen1,
	unsigned char **pubkey1, int *pubkeylen1,
	unsigned char **prikey2, int *prikeylen2,
	unsigned char **pubkey2, int *pubkeylen2);

int qinn_sender_dec_key(unsigned char *prikey1, int prikeylen1,
	unsigned char *prikey2, int prikeylen2,
	unsigned char *cipherkey, int cipherkeylen,
	unsigned char *plainkey1, int *keylen1,
	unsigned char *plainkey2, int *keylen2);

int qinn_sender_enc_msg(unsigned char *key1, int keylen1,
	unsigned char *key2, int keylen2,
	unsigned char *plain1, int plainlen1, 
	unsigned char *plain2, int plainlen2,
	unsigned char *cipher1, int *cipherlen1,
	unsigned char *cipher2, int *cipherlen2);

int qinn_receiver_enc_key(unsigned char *pubkey, int pubkeylen,
	unsigned char *plainkey, int plainkeylen,
	unsigned char *cipherkey, int *cipherkeylen);

int qinn_receiver_dec_msg(unsigned char *key, int keylen,
	unsigned char *cipher1, int cipherlen1, 
	unsigned char *cipher2, int cipherlen2,
	unsigned char *plain1, int *plainlen1,
	unsigned char *plain2, int *plainlen2);

#endif