#ifndef KEYEDCIPHER_H
#define KEYEDCIPHER_H

#include "cipher.h"
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <QFile>
#include <QFont>
#include <QTextStream>
#include <QMessageBox>
#include <QDir>

class KeyedCipher : public Cipher {
public:

    // Constructor
    KeyedCipher(Ciphers type) {
        // Generate session ID and initialize based on the provided type
        sessionID = generate_session_id();
        if (type == Ciphers::AES)
            KeyedCipherAES();
        else if(type == Ciphers::RSA)
            KeyedCipherRSA();
    }

    ~KeyedCipher() = default;

    virtual std::string encrypt(const std::string& plaintext, Ciphers type) override = 0;
    virtual std::string decrypt(const std::string& ciphertext, Ciphers type) override = 0;

    // Getters for AES key and IV
    const std::vector<CryptoPP::byte>& getAESKey() const { return aesKey; }
    const std::vector<CryptoPP::byte>& getAESIV() const { return aesIV; }

    // Generate session ID
    QString generate_session_id() {
        // Generate a session ID string using a combination of timestamp and random value
        QString timestamp = QString::number(QDateTime::currentMSecsSinceEpoch());
        QString randomValue = QString::number(rand());
        return timestamp + "_" + randomValue;
    }

    // Save RSA private key to file
    void SaveRSAPrivateKeyToFile(const QString& filePath, const CryptoPP::RSA::PrivateKey& privateKey)
    {
        QFile keyFile(filePath);
        if (!keyFile.open(QIODevice::WriteOnly)) {
            QMessageBox::warning(nullptr, "Error", "Failed to open " + filePath + " for writing");
            abort();
        }

        // Serialize private key
        CryptoPP::ByteQueue privateKeyBytes;
        privateKey.Save(privateKeyBytes);

        // Base64 encode the private key
        CryptoPP::Base64Encoder encoder;
        privateKeyBytes.CopyTo(encoder);
        encoder.MessageEnd();

        QByteArray encodedKey;
        size_t size = encoder.MaxRetrievable();
        encodedKey.resize(size);
        encoder.Get(reinterpret_cast<CryptoPP::byte*>(encodedKey.data()), size);

        QString encodedKeyString(encodedKey);
        encodedKeyString.remove('\n'); // Remove newlines

        // Write encoded key to file
        QTextStream out(&keyFile);
        out << encodedKeyString;

        keyFile.close();
    }

    // Save RSA public key to file
    void SaveRSAPublicKeyToFile(const QString& filePath, const CryptoPP::RSA::PublicKey& publicKey)
    {
        QFile keyFile(filePath);
        if (!keyFile.open(QIODevice::WriteOnly)) {
            QMessageBox::warning(nullptr, "Error", "Failed to open " + filePath + " for writing");
            abort();
        }

        // Serialize public key
        CryptoPP::ByteQueue publicKeyBytes;
        publicKey.Save(publicKeyBytes);

        // Base64 encode the public key
        CryptoPP::Base64Encoder encoder;
        publicKeyBytes.CopyTo(encoder);
        encoder.MessageEnd();

        QByteArray encodedKey;
        size_t size = encoder.MaxRetrievable();
        encodedKey.resize(size);
        encoder.Get(reinterpret_cast<CryptoPP::byte*>(encodedKey.data()), size);

        QString encodedKeyString(encodedKey);
        encodedKeyString.remove('\n'); // Remove newlines

        // Write encoded key to file
        QTextStream out(&keyFile);
        out << encodedKeyString;

        keyFile.close();
    }


protected:
    std::vector<CryptoPP::byte> aesKey;
    std::vector<CryptoPP::byte> aesIV;
    CryptoPP::RSA::PrivateKey rsaPrivateKey;
    CryptoPP::RSA::PublicKey rsaPublicKey;
    QString sessionID;

private:
    // KeyedCipherAES method for AES key generation
    void KeyedCipherAES() {

        QDir dir("keys");
        if (!dir.exists()) {
            QMessageBox::warning(nullptr, "Error", "Directory does not exist!");
            abort();
        }

        // Generate AES key and IV
        CryptoPP::AutoSeededRandomPool prng;
        aesKey.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
        prng.GenerateBlock(aesKey.data(), aesKey.size());

        aesIV.resize(CryptoPP::AES::BLOCKSIZE);
        prng.GenerateBlock(aesIV.data(), aesIV.size());

        // Write the encrypted key to file
        QFile keyFile(dir.filePath("aes_key_" + sessionID + ".txt"));
        if (!keyFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(nullptr, "Error", "Failed to open aes_key_" + sessionID + ".txt for writing");
            abort();
        }
        QByteArray keyData(reinterpret_cast<const char*>(aesKey.data()), aesKey.size());
        QTextStream outKey(&keyFile);
        outKey << keyData.toHex();
        keyFile.close();

        // Write the encrypted IV to file
        QFile ivFile(dir.filePath("aes_iv_" + sessionID + ".txt"));
        if (!ivFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(nullptr, "Error", "Failed to open aes_iv_" + sessionID + ".txt for writing");
            abort();
        }
        QByteArray ivData(reinterpret_cast<const char*>(aesIV.data()), aesIV.size());
        QTextStream outIV(&ivFile);
        outIV << ivData.toHex();
        ivFile.close();
    }

    // KeyedCipherRSA method for RSA key generation
    void KeyedCipherRSA() {
        try {
            QDir dir("keys");
            if (!dir.exists()) {
                QMessageBox::warning(nullptr, "Error", "Directory does not exist!");
                abort();
            }

            // Generate RSA key pair
            CryptoPP::AutoSeededRandomPool prng;
            CryptoPP::InvertibleRSAFunction rsaParams;
            rsaParams.GenerateRandomWithKeySize(prng, 1024);

            rsaPrivateKey = CryptoPP::RSA::PrivateKey(rsaParams);
            rsaPublicKey = CryptoPP::RSA::PublicKey(rsaParams);

            // Save RSA keys to files
            SaveRSAPrivateKeyToFile(dir.filePath("rsa_private_" + sessionID + ".pem"), rsaPrivateKey);
            SaveRSAPublicKeyToFile(dir.filePath("rsa_public_" + sessionID + ".pem"), rsaPublicKey);

        }
        catch (const CryptoPP::Exception& e) {
            // Handle CryptoPP exceptions
            std::cerr << "CryptoPP Exception caught: " << e.what() << std::endl;
            // You might want to log the exception and handle it accordingly
        }
        catch (const std::exception& e) {
            // Handle other standard exceptions
            std::cerr << "Standard Exception caught: " << e.what() << std::endl;
            // You might want to log the exception and handle it accordingly
        }
        catch (...) {
            // Handle any other unexpected exceptions
            std::cerr << "Unknown Exception caught" << std::endl;
            // You might want to log the exception and handle it accordingly
        }
    }

};

#endif // KEYEDCIPHER_H
