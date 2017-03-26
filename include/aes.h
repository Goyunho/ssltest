#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

int fs_encrypt_aes(unsigned char *key, char *in_file, char *out_file);
int fs_decrypt_aes(unsigned char *key, char *in_file, char *out_file);
