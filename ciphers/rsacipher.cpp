#include "rsacipher.h"
#include <QDir>
#include <QTextStream>
#include <iostream>
#include <stdexcept>

// Constructor
RSACipher::RSACipher() : KeyedCipher(Ciphers::RSA)
{
    try {
        // Check if the directory exists
        QDir dir("keys");
        if (!dir.exists()) {
            std::cerr << "Directory does not exist!" << std::endl;
            return;
        }

        // Read RSA private key from file
        QString rsaPrivateKeyFilePath = dir.filePath("rsa_private_" + sessionID + ".pem");
        rsaPrivateKey = ReadRSAPrivateKeyFromFile(rsaPrivateKeyFilePath);

        // Read RSA public key from file
        QString rsaPublicKeyFilePath = dir.filePath("rsa_public_" + sessionID + ".pem");
        rsaPublicKey = ReadRSAPublicKeyFromFile(rsaPublicKeyFilePath);
    }
    catch (const std::exception& e) {
        std::cerr << "RSA secrets are possibly long. Consider enough memory allocation." << std::endl;
    }
}

// Read RSA private key from file
CryptoPP::RSA::PrivateKey RSACipher::ReadRSAPrivateKeyFromFile(const QString& filePath)
{
    QFile keyFile(filePath);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        std::cerr << "Failed to open " << filePath.toStdString() << " for reading" << std::endl;
        throw std::runtime_error("Failed to open file");
    }

    QTextStream in(&keyFile);
    QString privateKeyString = in.readAll();

    keyFile.close();

    CryptoPP::RSA::PrivateKey privateKey;
    // Load private key from string
    privateKey.Load(CryptoPP::StringSource(privateKeyString.toStdString(), true).Ref());
    return privateKey;
}

// Read RSA public key from file
CryptoPP::RSA::PublicKey RSACipher::ReadRSAPublicKeyFromFile(const QString& filePath)
{
    QFile keyFile(filePath);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        std::cerr << "Failed to open " << filePath.toStdString() << " for reading" << std::endl;
        throw std::runtime_error("Failed to open file");
    }

    QTextStream in(&keyFile);
    QString publicKeyString = in.readAll();

    keyFile.close();

    CryptoPP::RSA::PublicKey publicKey;
    // Load public key from string
    publicKey.Load(CryptoPP::StringSource(publicKeyString.toStdString(), true).Ref());
    return publicKey;
}

// Encrypt plaintext using RSA
std::string RSACipher::encrypt(const std::string& plaintext, Ciphers type) {
    if (type == Ciphers::RSA) {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Encrypt the plaintext
            std::string ciphertext;
            CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(rsaPublicKey);
            CryptoPP::StringSource(plaintext, true, new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(ciphertext)));

            // Convert ciphertext to Base64 without new lines
            std::string base64Ciphertext;
            CryptoPP::StringSource ss(ciphertext, true,
                new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64Ciphertext), false));

            return base64Ciphertext;
        }
        catch (const CryptoPP::Exception& e) {
            throw std::runtime_error(std::string("CryptoPP Exception caught: ") + e.what());
        }
        catch (...) {
            throw std::runtime_error("Unknown Exception caught");
        }
    }
}

// Decrypt base64 encoded ciphertext using RSA
std::string RSACipher::decrypt(const std::string& base64Ciphertext, Ciphers type) {
    if (type == Ciphers::RSA) {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Decode Base64 ciphertext
            std::string ciphertext;
            CryptoPP::StringSource ss(base64Ciphertext, true,
                new CryptoPP::Base64Decoder(new CryptoPP::StringSink(ciphertext)));

            // Decrypt the ciphertext
            std::string decryptedtext;
            CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivateKey);
            CryptoPP::StringSource(ciphertext, true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decryptedtext)));

            return decryptedtext;
        }
        catch (const CryptoPP::Exception& e) {
            throw std::runtime_error(std::string("CryptoPP Exception caught: ") + e.what());
        }
        catch (...) {
            throw std::runtime_error("Unknown Exception caught");
        }
    }
}

