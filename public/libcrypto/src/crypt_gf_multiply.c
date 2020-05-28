#include "crypt_gf_multiply.h"
#include <stdlib.h>

//既约多项式x^8+x^4+x^3+x+1 左移1位，如果最高位为1
//则异或多项式除最高位(x^8)以外的值 即0x1b
uint8_t mutiply_by_2(uint8_t a) {
	return (a << 1) ^ ((a & 0x80) ? 0x1b : 0);
}

//GF(2^8)乘法运算
uint8_t gf_multiply(uint8_t a, uint8_t b) {
	uint8_t array[8] = { 0 };
	uint8_t result = 0;

	array[0] = a;

	//对a移位7次 分别计算a<<1,a<<2,.....a<<7
	for (int i = 1; i < 8; i++) {
		array[i] = mutiply_by_2(array[i-1]);
	}

	//寻找b的二进制为1的位，乘以a左移之后的值
	for (int i = 0; i < 8; i++) {
		result ^= (((b >> i) & 0x01) * array[i]);
	}

	return result;
}

void gf_build_table(uint8_t table[256][256]) {

	for (int i = 0; i < 256; i++) {
		for (int j = 0; j < 256; j++) {
			table[i][j] = gf_multiply(i, j);
		}
	}
}