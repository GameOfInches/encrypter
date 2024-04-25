#include "safcipher.h"
#include <iostream>

SAFCipher::SAFCipher() : CustomCipher(Ciphers::SAF)
{
    // Initialize AES key and IV from KeyedCipher constructor
    shifts = getShifts();
}

std::string SAFCipher::encrypt(const std::string& plaintext, Ciphers type) {
    if (type == Ciphers::SAF) {
        try {
            std::cout << "Received text is:" << plaintext << std::endl;
            std::string encryptedText;

            for (char c : plaintext) {
                encryptedText += static_cast<char>(c + shifts);
            }

            ciphertextEnd = plaintext.size();

            // Append additional characters to make the output longer than the input
            int extraChars = rand() % 20 + 20; // Generate random number of extra characters (1 to 10)
            for (int i = 0; i < extraChars; ++i) {
                char extraChar = generateRandomChar();
                encryptedText += extraChar;
            }

            return encryptedText;
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

std::string SAFCipher::decrypt(const std::string& ciphertext, Ciphers type) {
    if (type == Ciphers::SAF) {
        try {
            std::string shortenedText, decryptedText;
            shortenedText = ciphertext.substr(0, ciphertextEnd);

            for (int i = 0; i < shortenedText.length(); ++i) {
                decryptedText += static_cast<char>(shortenedText[i] - shifts);
            }

            return decryptedText;
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

char SAFCipher::generateRandomChar() {
    // Base64 character set (excluding padding characters)
    const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // Generate a random index within the range of Base64 characters
    int index = rand() % chars.size();

    // Return the randomly selected Base64 character
    return chars[index];
}

