#include <iostream>

#include "crypt.h"

char *generate_sig(char *document, RSA *private_key, char *encrypt, int *len_of_enc) {
    *len_of_enc = data_encrypt(private_key,  sha256_hash(document).c_str(), encrypt);
    return encrypt;
}

std::string verify_sig(char *document, RSA *public_key, int *len_of_enc, char *decrypt, char *encrypt) {
    data_decrypt(public_key, len_of_enc, decrypt, encrypt);
    if (decrypt != sha256_hash(document)) {
        return "ERROR";
    }
    return (sha256_hash(document));
}

