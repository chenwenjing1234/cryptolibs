
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "unit_test.h"

int main(int argc, char *argv[]) {
	int ret;
	
	printf("main invoked\n");

	//ret = qinn_srp_agreement_test();

	//ret = rsa_mul_homo_enc_test();

	//ret = qinn_ot_test();

	//ret = crypt_ecc_point_mul_speed_test();

	//ret = crypt_ecc_point_mul_test();

	//ret = crypt_ecc_point_add_test();

	//ret = std_ecc_gen_keypair_test();

	//ret = crypt_ecc_speed_test_case();

	//ret = std_ecc_verify_test_v2();

	//ret = std_ecc_verify_test();

	//ret = base64_test();
	
	//ret = crypt_rsa_gen_keypair_speed_test();

	//ret = crypt_ecdh_test_case();

	//ret = crypt_ecdsa_test_case();

	//ret = crypt_rsa_test_case();

	//ret = crypt_ecc_test_case();

	//ret = crypt_test_case();

	//ret = aes_test();
		
	//ret = qinn_sm4_test();

	ret = crypt_gf_multiply_test();

	return 0;
}