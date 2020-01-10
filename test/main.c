#include "crypto/rsa.h"
#include "stdio.h"

int main(int argc, char *argv[]) {
	int a = 10;
	int b = 20;
	int c = test_add(a, b);
	
	printf("c = %d\n", c);
	return 0;
	
}