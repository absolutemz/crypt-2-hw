#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>

#include <openssl/rsa.h>

#include "crypt.h"

std::string sha256_hash(const std::string hashing_string) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hashing_string.c_str(), hashing_string.size());
    SHA256_Final(hash, &sha256);
    std::stringstream sha256_string;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sha256_string << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return sha256_string.str();
}

RSA * create_RSA(RSA * keypair, int pem_type, char *file_name) {
    RSA   *rsa = NULL;
    FILE  *fp  = NULL;

    if (pem_type == PUBLIC_KEY_PEM) {
        fp = fopen(file_name, "w");
        PEM_write_RSAPublicKey(fp, keypair);
        fclose(fp);

        fp = fopen(file_name, "rb");
        PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
        fclose(fp);
    } else if (pem_type == PRIVATE_KEY_PEM) {
        fp = fopen(file_name, "w");
        PEM_write_RSAPrivateKey(fp, keypair, NULL, NULL, NULL, NULL, NULL);
        fclose(fp);

        fp = fopen(file_name, "rb");
        PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
        fclose(fp);
    }
    return rsa;
}

int private_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {
    int result = RSA_private_encrypt(flen, from, to, key, padding);
    return result;
}

int public_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {

    int result = RSA_public_decrypt(flen, from, to, key, padding);
    return result;
}

void create_encrypted_file(char* encrypted, RSA* key_pair) {
    FILE* encrypted_file = fopen("encrypted_file.bin", "w");
    fwrite(encrypted, sizeof(*encrypted), RSA_size(key_pair), encrypted_file);
    fclose(encrypted_file);
}

int data_encrypt(RSA* private_key, const char* msg, char *encrypt) {
    int len_of_enc = private_encrypt(strlen(msg) + 1, (unsigned char*)msg, (unsigned char*)encrypt, private_key, RSA_PKCS1_PADDING);
    if (len_of_enc == -1) {
        std::cout << "error" << std::endl;
    }
    create_encrypted_file(encrypt, private_key);
    return len_of_enc;
}

void data_decrypt(RSA* public_key, int *len_of_enc, char *decrypt, char *encrypt) {
    int decrypt_length = public_decrypt(*len_of_enc, (unsigned char*)encrypt, (unsigned char*)decrypt, public_key, RSA_PKCS1_PADDING);
    if (decrypt_length == -1) {
        std::cout << "error" << std::endl;
    }
    FILE *decrypted_file = fopen("decrypted_file.txt", "w");
    fwrite(decrypt, sizeof(*decrypt), decrypt_length - 1, decrypted_file);
    fclose(decrypted_file);
}