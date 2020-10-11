#pragma once

#include <openssl/pem.h>

 char *generate_sig(char *document, RSA *private_key, char *encrypt, int *len_of_enc);  // создания ЭЦП

std::string verify_sig(char *document, RSA *public_key, int *len_of_enc, char *decrypt, char *encrypt);  // проверка ЭЦП
