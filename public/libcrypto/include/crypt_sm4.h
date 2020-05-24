#ifndef __CRYPT_SM4_H
#define __CRYPT_SM4_H

#include <stdint.h>

typedef struct _sm4_key_st {
	uint32_t round_key[32];
} sm4_key_st;

void qinn_sm4_init_key(unsigned char *key, int key_len, sm4_key_st *sm4_key);

int qinn_sm4_block_encrypt(sm4_key_st *sm4_key, unsigned char *in,
	int inlen, unsigned char *out);

int qinn_sm4_block_decrypt(sm4_key_st *sm4_key, unsigned char *in,
	int inlen, unsigned char *out);

#endif