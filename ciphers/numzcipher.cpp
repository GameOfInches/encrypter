#include "numzcipher.h"
#include <iostream>
#include <sstream>

NUMZCipher::NUMZCipher() : CustomCipher(Ciphers::NUMZ)
{
    // Initialize AES key and IV from KeyedCipher constructor
    characterMap = getMap();
}

std::string NUMZCipher::encrypt(const std::string& plaintext, Ciphers type) {
    if (type == Ciphers::NUMZ) {
        try {
            std::cout << "Received text is: " << plaintext << std::endl;

            // Convert each character to its corresponding number and concatenate them with '_'
            std::string encryptedText;
            for (char c : plaintext) {
                if (characterMap.find(c) != characterMap.end()) {
                    encryptedText += std::to_string(characterMap[c]) + '_';
                }
                else {
                    // If the character is not in the mapping, ignore it
                    std::cerr << "Warning: Ignoring character '" << c << "'." << std::endl;
                }
            }

            // Remove the trailing '_' if it exists
            if (!encryptedText.empty() && encryptedText.back() == '_') {
                encryptedText.pop_back();
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

std::string NUMZCipher::decrypt(const std::string& ciphertext, Ciphers type) {
    if (type == Ciphers::NUMZ) {
        try {
            std::cout << "Received ciphertext is: " << ciphertext << std::endl;

            // Insert '_' after every two numbers in the ciphertext
            std::string modifiedCiphertext;
            for (size_t i = 0; i < ciphertext.size(); i += 3) {
                modifiedCiphertext += ciphertext.substr(i, 3);
                if (i + 3 < ciphertext.size()) {
                    modifiedCiphertext += "_";
                }
            }

            // Split the modified ciphertext by '_' delimiter
            std::stringstream ss(modifiedCiphertext);
            std::string token;
            std::string decryptedText;
            while (std::getline(ss, token, '_')) {
                // Convert each number to its corresponding character
                int number = std::stoi(token);
                for (auto&& [c, n] : characterMap) {
                    if (n == number) {
                        decryptedText += c;
                        break;
                    }
                }
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

char NUMZCipher::findCharacter(int num) {
    for (const auto& pair : characterMap) {
        if (pair.second == num) {
            return pair.first;
        }
    }
    return '\0';
}