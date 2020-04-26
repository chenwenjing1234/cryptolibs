#ifndef __CRYPT_SRP_H
#define __CRYPT_SRP_H

#include <openssl/bn.h>

int qinn_srp_calx(unsigned char *salt, int saltlen, char *username, char *password, BIGNUM *ret);

int qinn_srp_calV(BIGNUM *g, BIGNUM *x, BIGNUM *N, BIGNUM *ret);

int qinn_srp_calA(BIGNUM *g, BIGNUM *a, BIGNUM *N, BIGNUM *ret);

int qinn_srp_calB(BIGNUM *k, BIGNUM *v, BIGNUM *g, BIGNUM *b, BIGNUM *N, BIGNUM *ret);

int qinn_srp_calu(BIGNUM *A, BIGNUM *B, BIGNUM *ret);

int qinn_srp_calk(BIGNUM *N, BIGNUM *g, BIGNUM *ret);

int qinn_srp_cal_clientS(BIGNUM *B, BIGNUM *k, BIGNUM *g, BIGNUM *x, BIGNUM *a, 
	BIGNUM *u, BIGNUM *N, BIGNUM *ret);

int qinn_srp_cal_serverS(BIGNUM *A, BIGNUM *v, BIGNUM *u, BIGNUM *b, BIGNUM *N, BIGNUM *ret);

int qinn_srp_calM1(BIGNUM *A, BIGNUM *B, BIGNUM *S, BIGNUM *ret);

int qinn_srp_calM2(BIGNUM *A, BIGNUM *M1, BIGNUM *S, BIGNUM *ret);

int qinn_srp_calK(BIGNUM *S, BIGNUM *ret);

#endif