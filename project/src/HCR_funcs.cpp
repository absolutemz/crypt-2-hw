#include <iostream>

#include "crypt.h"
#include "sig.h"

char *handshake(char *sign) {
    return sign;
}

std::string challange(char *start_msg, RSA *public_key, int *len_of_enc, char *decrypt, char *c_handshake_data) {
    return verify_sig(start_msg, public_key, len_of_enc, decrypt, c_handshake_data);
}

std::string response(std::string response_data, std::string challange_data, std::string start_massage) {
    if (response_data != sha256_hash(challange_data)) {
        return ("ERROR");
    }
    return ("OK, " + start_massage);
}

std::string generate_challange() {
    return sha256_hash(std::to_string(rand() % 1000000));
}
