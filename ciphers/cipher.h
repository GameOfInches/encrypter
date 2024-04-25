#ifndef CIPHER_H
#define CIPHER_H

#include <string>

// Base class representing a cipher
class Cipher {
public:

    enum class Ciphers {
        AES,
        RSA,
        SAF,
        NUMZ
    };

    virtual std::string encrypt(const std::string& plaintext, Ciphers type) = 0;
    virtual std::string decrypt(const std::string& ciphertext, Ciphers type) = 0;
};

#endif // CIPHER_H
