#include "aescipher.h"
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>

AESCipher::AESCipher() : KeyedCipher(Ciphers::AES)
{
    // Initialize AES key and IV from KeyedCipher constructor
    aesKey = getAESKey();
    aesIV = getAESIV();
}

std::string AESCipher::encrypt(const std::string& plaintext, Ciphers type) {
    if (type == Ciphers::AES) {
        try {
            std::cout << "aes_encrypt: Received text is:" << plaintext << std::endl;
            std::string encryptedText;

            CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const unsigned char*>(aesKey.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
            CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, reinterpret_cast<const unsigned char*>(aesIV.data()));
            CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(encryptedText), CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);
            stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
            stfEncryptor.MessageEnd();

            // Encode ciphertext to hexadecimal
            std::string hexEncoded;
            CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexEncoded));
            encoder.Put(reinterpret_cast<const unsigned char*>(encryptedText.data()), encryptedText.size());
            encoder.MessageEnd();

            std::cout << "\n\nCipher Text size is (" << encryptedText.size() << " bytes)" << std::endl;
            for (int i = 0; i < encryptedText.size(); i++) {
                std::cout << "0x" << std::hex << (0xFF & static_cast<unsigned char>(encryptedText[i])) << " ";
            }

            return hexEncoded;
        }
        catch (const CryptoPP::Exception& e) {
            // Handle CryptoPP exceptions
            throw std::runtime_error(std::string("CryptoPP Exception caught: ") + e.what());
        }
        catch (const std::exception& e) {
            // Handle other standard exceptions
            throw std::runtime_error(std::string("Standard Exception caught: ") + e.what());
        }
        catch (...) {
            // Handle any other unexpected exceptions
            throw std::runtime_error("Unknown Exception caught");
        }
    }

}

std::string AESCipher::decrypt(const std::string& hexCiphertext, Ciphers type) {
    if (type == Ciphers::AES) {
        try {
            // Decode hexadecimal ciphertext
            std::string ciphertext;
            CryptoPP::StringSource(hexCiphertext, true,
                new CryptoPP::HexDecoder(
                    new CryptoPP::StringSink(ciphertext)
                )
            );

            std::string decryptedText;
            std::cout << "aes_decrypt: Received text is:" << ciphertext << std::endl;
            CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const unsigned char*>(aesKey.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
            CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const unsigned char*>(aesIV.data()));
            CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText), CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);
            stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size());
            stfDecryptor.MessageEnd();

            std::cout << "\n\naes_decrypt: Decrypted Text is " << "\n\n";
            std::cout << "\n\n" << decryptedText << "\n\n";

            return decryptedText;
        }
        catch (const CryptoPP::Exception& e) {
            // Handle CryptoPP exceptions
            throw std::runtime_error(std::string("CryptoPP Exception caught: ") + e.what());
        }
        catch (const std::exception& e) {
            // Handle other standard exceptions
            throw std::runtime_error(std::string("Standard Exception caught: ") + e.what());
        }
        catch (...) {
            // Handle any other unexpected exceptions
            throw std::runtime_error("Unknown Exception caught");
        }
    }
}