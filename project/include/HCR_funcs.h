#pragma once

#include <openssl/pem.h>

char *handshake(char *sign);  // handshake метод

std::string challange(char *start_msg, RSA *public_key, int *len_of_enc, char *decrypt, char *c_handshake_data);  // challange метод

std::string response(std::string response_data, std::string challange_data, std::string start_massage);  // response метод

std::string generate_challange();  // генерация проверочного сообщения