#define PUBLIC  0x00
#define PRIVATE 0b10
#define ENCRYPT 0b01
#define DECRYPT 0b00

bool generate_key();
RSA * createRSA(unsigned char * key, int public);

// public_enc
int public_encrypt(unsigned char * data, int data_len, char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data, int data_len, char * key, unsigned char *decrypted);

// digital sign
int private_encrypt(unsigned char * data, int data_len, char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data, int data_len, char * key, unsigned char *decrypted);

bool fs_process(int type, unsigned char * source_data, int source_data_len, char* key_path, unsigned char *crypted_buff);
