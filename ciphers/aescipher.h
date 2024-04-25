#ifndef AESCIPHER_H
#define AESCIPHER_H

#include "keyedcipher.h"

// Subclass of KeyedCipher representing the AES encryption algorithm
class AESCipher : public KeyedCipher {
public:
   AESCipher();
    virtual std::string encrypt(const std::string& plaintext, Ciphers type) override;
    virtual std::string decrypt(const std::string& ciphertext, Ciphers type) override;
};

#endif // AESCIPHER_H

