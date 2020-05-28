#ifndef __CRYPT_GF_MULTIPLY_H
#define __CRYPT_GF_MULTIPLY_H

#include <stdint.h>

uint8_t gf_multiply(uint8_t a, uint8_t b);

void gf_build_table(uint8_t table[256][256]);

#endif