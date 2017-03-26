#include "rsa.h"

int padding = RSA_PKCS1_PADDING;

bool generate_key()
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL, *bp_private = NULL;

    int             bits = 2048;
    unsigned long   e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if(ret != 1){
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }

    // 2. save public key
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSA_PUBKEY(bp_public, r);
    if(ret != 1){
        goto free_all;
    }

    // 3. save private key
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    // 4. free
free_all:
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return (ret == 1);
}

RSA * createRSA(unsigned char * key, int public) // public => 1: public key, 0: private_key
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);

    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    return rsa;
}

// public_enc
int public_encrypt(unsigned char * data, int data_len, char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}
int private_decrypt(unsigned char * enc_data, int data_len, char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 0);
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

// digital sign
int private_encrypt(unsigned char * data, int data_len, char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}
int public_decrypt(unsigned char * enc_data, int data_len, char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 1);
    int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

void printLastError(char *msg)
{
    char * err = malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

bool fs_process(int type, unsigned char * source_data, int source_data_len, char* key_path, unsigned char *crypted_buff){
    int result_length=-1;

    FILE *key_fs=fopen(key_path, "r");
    int fs_size=0;

    char *key;

    // key load
    fseek(key_fs, 0L, SEEK_END);
    fs_size = ftell(key_fs);
    fseek(key_fs, 0L, SEEK_SET);
    key=(char*)malloc(sizeof(char)*fs_size);
    fread(key, sizeof(char), fs_size, key_fs);

    switch(type){
        case PUBLIC|ENCRYPT:
        result_length= public_encrypt(source_data, source_data_len, key, crypted_buff);
        break;
        case PRIVATE|DECRYPT:
        result_length = private_decrypt(source_data, source_data_len, key, crypted_buff);
        break;
        case PRIVATE|ENCRYPT:
        result_length= private_encrypt(source_data, source_data_len, key, crypted_buff);
        break;
        case PUBLIC|DECRYPT:
        result_length = public_decrypt(source_data, source_data_len, key, crypted_buff);
        break;
    }

    fclose(key_fs);
    free(key);

    if(result_length == -1)
        return false;

    return true;
}
