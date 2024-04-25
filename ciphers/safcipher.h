#ifndef SAFCIPHER_H
#define SAFCIPHER_H

#include "customcipher.h"

// Subclass of KeyedCipher representing the AES encryption algorithm
class SAFCipher : public CustomCipher {
public:
    SAFCipher();
    virtual std::string encrypt(const std::string& plaintext, Ciphers type) override;
    virtual std::string decrypt(const std::string& ciphertext, Ciphers type) override;

private:
    int ciphertextEnd;
    char generateRandomChar();
};

#endif // SAFCIPHER_H

