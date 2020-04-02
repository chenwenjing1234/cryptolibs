#include "crypt_speed_test.h"
#include <stdio.h>
#include <time.h>

int qinn_rsa_gen_keypaire_speed() {
	int ret;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
	int loops = 1000;
	time_t t1, t2;
	long cost_time;

	rsa = RSA_new();
	e = BN_new();

	BN_set_word(e, 65537);

	time(&t1);
	for (int i = 0; i < loops; i++) {
		ret = RSA_generate_key_ex(rsa, 1024, e, NULL);
		if (ret != 1) {
			printf("RSA_generate_key_ex failed\n");
			ret = 0;
			goto exit;
		}
	}
	time(&t2);

	cost_time = t2 - t1;
	printf("RSA_generate_key_ex %d times, cost %ld seconds, average %.2f keypairs/seconds\n", 
		loops, cost_time, (float)loops/cost_time);
	
	ret = 1;
exit:
	return ret;
}