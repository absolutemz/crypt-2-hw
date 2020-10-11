#include <iostream>
#include <string>
#include <cstring>

#include "HCR_funcs.h"
#include "sig.h"
#include "crypt.h"

char *priv_key_file_name = "private_key";
char *pub_key_file_name = "public_key";

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "wrong count of params" << std::endl;
        return 1;
    }
    char start_msg[KEY_LENGTH / 8] = "open door";
    for (int param = 0; param < argc; ++param) {  // Передаваемые параметры
        std::string param_from_cons = argv[param];

        switch (param) {
            case 1: {
                if (param_from_cons != "--massage") {
                    std::cout << "wrong format of flag" << std::endl;
                    return 1;
                }
                break;
            }
            case 2: {
                strcpy(start_msg, argv[param]);
                break;
            }
        }
    }

    int len_of_enc = 0;

    char *decrypt = NULL;
    char *encrypt = NULL;

    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUBLIC_EXPONENT, NULL, NULL);  // генерацаия ключей
    RSA *private_key = create_RSA(keypair, PRIVATE_KEY_PEM, priv_key_file_name);
    RSA *public_key = create_RSA(keypair, PUBLIC_KEY_PEM, pub_key_file_name);

    std::cout << "(registration) " << public_key << " - public key generated for trinked, " << "private key generated for trinked" << std::endl;
    std::cout << "__________________________________________" << std::endl;  // сообщение об успешной регистрации

    encrypt = (char*)malloc(RSA_size(private_key));

    char *handshake_data = handshake(generate_sig(start_msg, private_key, encrypt, &len_of_enc));  // handshake, ЭЦП по hash от данных передается машине

    std::cout << "(handshake) trinket->car send data: " << sha256_hash(start_msg) << " (id command), "
              << std::endl << &handshake_data << &public_key << " (challenge for car)" << std::endl;
    std::cout << "__________________________________________" << std::endl;  // сообщение о передаче данных, подписи и ключе для расшифровки

    decrypt = (char *)malloc(len_of_enc);  // challange, генерация сообщения для ключа для проверки его подлинности, расшифровка переданной подписи
    std::string challange_data = generate_challange();
    std::string confirm_challange_data = challange(start_msg, public_key, &len_of_enc, decrypt, handshake_data);
    if (confirm_challange_data == "ERROR") {
        std::cout << "wrong massage or public key" << std::endl;
        return 1;
    }

    std::cout << "(challenge) car->trinket send data: " << challange_data << " (challenge for trinket), "  // сообщение о переданном сообщении и успешной расфшивровке
        << confirm_challange_data << " (confirm challenge for car)" << std::endl;
    std::cout << "__________________________________________" << std::endl;

    char *c_challange_data = &challange_data[0];  // response, сгенерированное сообщение шифруется по закрытому ключу и передается к машине
    std::string response_data = generate_sig(c_challange_data, private_key, encrypt, &len_of_enc);

    std::cout << "(response) trinket->car send data: " << &response_data << " (confirm challenge for trinket) " << std::endl;
    std::cout << "__________________________________________" << std::endl;  // сообщение о передаче зашифрованного сообщения

    std::string check_response_data = verify_sig(c_challange_data, public_key, &len_of_enc, decrypt, encrypt); // расфировка сообщения открытым ключем
    if (check_response_data == "ERROR") {
        std::cout << "wrong massage or public key" << std::endl;
    }

    std::cout << "(action) car: check response - " << response(check_response_data, challange_data, start_msg) << std::endl;  // проверка полученных данных

    RSA_free(keypair);
    free(private_key);
    free(public_key);
    free(encrypt);
    free(decrypt);
    return 0;
}
