#include "sha.h"

void SHA256_gen(char str[], unsigned char *sha256_str){
	SHA256_CTX sha256;

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str, strlen(str));
	SHA256_Final(sha256_str, &sha256);
}
