#pragma once

#include <iostream>
#include <openssl/pem.h>

#define KEY_LENGTH       2048
#define PUBLIC_EXPONENT  59
#define PUBLIC_KEY_PEM   1
#define PRIVATE_KEY_PEM  0

std::string sha256_hash(const std::string hashing_string);  // SHA256 hash

RSA * create_RSA(RSA *keypair, int pem_type, char *file_name);  // RSA keys

int private_encrypt(int flen, unsigned char* from, unsigned char *to, RSA* key, int padding);  // encrypt по приватному ключу

int public_decrypt(int flen, unsigned char* from, unsigned char *to, RSA* key, int padding);  // decrypt по публичному ключу

void create_encrypted_file(char* encrypted, RSA* key_pair);  // запись шифрованных данных в файл

int data_encrypt(RSA* key, const char* msg, char *enc);  // функция зашифровки

void data_decrypt(RSA* key, int *len_of_enc, char *dec, char *enc);  // функция расшифровки