#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

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
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        goto free_all;
    }

    // 3. save private key
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    // 4. free
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

// 공개키 암호화
int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}
int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 0);
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

// 디지털 서명
int private_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}
int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 1);
    int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

int main(){

    char plainText[2048/8] = "Hello this is Ravi"; //key length : 2048

    FILE publicKey_fs=open("public.pem", "r");
    FILE privateKey_fs=open("private.pem", "r");
    int fs_size=0;

    unsigned char encrypted[4098]={};
    unsigned char decrypted[4098]={};

    char *publicKey;
    char *privateKey;

    if(publicKey_fs == -1 && privateKey_fs == -1){
        generate_key();
    }

    // public.pem 가져오기
    fseek(publicKey_fs, 0L, SEEK_END);
    fs_size = ftell(publicKey_fs);
    fseek(publicKey_fs, 0L, SEEK_SET);
    fread(publicKey, sizeof(char), fs_size, publicKey_fs);
    fclose(publicKey_fs);

    // private.pem 가져오기
    fseek(privateKey_fs, 0L, SEEK_END);
    fs_size = ftell(publicKey_fs);
    fseek(privateKey_fs, 0L, SEEK_SET);
    fread(privateKey, sizeof(char), fs_size, privateKey_fs);
    fclose(privateKey_fs);

    int encrypted_length= public_encrypt(plainText, strlen(plainText), publicKey, encrypted);
    if(encrypted_length == -1)
    {
        printLastError("Public Encrypt failed ");
        exit(0);
    }
    printf("Encrypted length =%d\n", encrypted_length);

    int decrypted_length = private_decrypt(encrypted, encrypted_length, privateKey, decrypted);
    if(decrypted_length == -1)
    {
        printLastError("Private Decrypt failed ");
        exit(0);
    }
    printf("Decrypted Text =%s\n", decrypted);
    printf("Decrypted Length =%d\n", decrypted_length);


    encrypted_length= private_encrypt(plainText, strlen(plainText), privateKey, encrypted);
    if(encrypted_length == -1)
    {
        printLastError("Private Encrypt failed");
        exit(0);
    }
    printf("Encrypted length =%d\n", encrypted_length);

    decrypted_length = public_decrypt(encrypted, encrypted_length, publicKey, decrypted);
    if(decrypted_length == -1)
    {
        printLastError("Public Decrypt failed");
        exit(0);
    }
    printf("Decrypted Text =%s\n", decrypted);
    printf("Decrypted Length =%d\n", decrypted_length);

}
