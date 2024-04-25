#ifndef NUMZCIPHER_H
#define NUMZCIPHER_H

#include "customcipher.h"
#include <iostream>
#include <unordered_map>

class NUMZCipher : public CustomCipher {
public:
    NUMZCipher();

    virtual std::string encrypt(const std::string& plaintext, Ciphers type) override;

    virtual std::string decrypt(const std::string& ciphertext, Ciphers type) override;

    char findCharacter(int num);


protected:
    std::unordered_map<char, int> characterMap;

};

#endif // NUMZCIPHER_H
