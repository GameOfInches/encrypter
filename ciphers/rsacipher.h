#ifndef RSACIPHER_H
#define RSACIPHER_H

#include "keyedcipher.h"

// Subclass of KeyedCipher representing the RSA encryption algorithm
class RSACipher : public KeyedCipher {
public:
    RSACipher();
    virtual std::string encrypt(const std::string& plaintext, Ciphers type) override;
    virtual std::string decrypt(const std::string& ciphertext, Ciphers type) override;

    // Function to read RSA private key from file
    CryptoPP::RSA::PrivateKey ReadRSAPrivateKeyFromFile(const QString& filePath);

    // Function to read RSA public key from file
    CryptoPP::RSA::PublicKey ReadRSAPublicKeyFromFile(const QString& filePath);

};

#endif // RSACIPHER_H

