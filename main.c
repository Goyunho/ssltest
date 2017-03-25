#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha.h"
#include "aes.h"

#define FAIL -1
#define SUCC 0


unsigned char key_sha256[SHA_DIGEST_LENGTH];

int main(int argc, char *args[]){
	int i =0;
	char *key_str = "hello";
	char *file = args[1];
	char rsa_buff[4048]={};

	SHA256_gen(key_str, key_sha256);

	if( argc != 2 ){
		printf("[Usage] %s fs_src_file\n", args[0]);
		return FAIL;
	}


	if( fs_encrypt_aes(key_sha256, file, "file.enc") == SUCC){
		fs_decrypt_aes(key_sha256, "file.enc", "file.dec");
		printf("result:[%s]\n", "file.dec");
	}

	generate_key();
	fs_process(PUBLIC|ENCRYPT, "hi, rsa test!", strlen("hi, rsa test!"), "public.pem", rsa_buff);
	printf("%s", rsa_buff);
	fs_process(PRIVATE|DECRYPT, rsa_buff, strlen(rsa_buff), "private.pem", rsa_buff);
	printf("%s", rsa_buff);

	return 0;
}
