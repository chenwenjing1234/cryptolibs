#ifndef __CRYPT_ECC_H
#define __CRYPT_ECC_H

#include <openssl/ec.h>

EC_POINT* qinn_point_add(EC_GROUP *gp, EC_POINT *p1, EC_POINT *p2);

EC_POINT* qinn_point_double(EC_GROUP *gp, EC_POINT *a);

EC_POINT* qinn_point_double_v2(EC_GROUP *gp, EC_POINT *a);

int std_ecc_verify(uint8_t *msg, int msglen, char *pubkey, uint8_t *sig, int siglen);

int std_ecc_gen_keypair(uint8_t *prikey, int *prikey_len, uint8_t *pubkey, int *pubkey_len);

int std_ecc_sign(uint8_t *msg, int msglen, unsigned char *prikey, int prikey_len, uint8_t *sig, int *siglen);

EC_POINT* qinn_point_add_v2(EC_GROUP *gp, EC_POINT *a, EC_POINT *b);


#endif