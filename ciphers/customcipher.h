#ifndef CUSTOMCIPHER_H
#define CUSTOMCIPHER_H

#include "cipher.h"
#include <QFile>
#include <QFont>
#include <QTextStream>
#include <QMessageBox>
#include <QDir>
#include <random>
#include <set>
#include <iostream>

class CustomCipher : public Cipher
{
public:

    CustomCipher(Ciphers type) {
        if (type == Ciphers::SAF)
            shifts = 1 + (rand() % 10);
        else if (type == Ciphers::NUMZ) {
            generateRandomCharacterMap();
        }
    }

    ~CustomCipher() = default;

    virtual std::string encrypt(const std::string & plaintext, Ciphers type) override = 0;
    virtual std::string decrypt(const std::string & ciphertext, Ciphers type) override = 0;

    int getShifts() { return shifts; }
    std::unordered_map<char, int> getMap() { return characterMap; };

    void generateRandomCharacterMap() {
        // Initialize random number generator
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(100, 999); // Adjust range as needed

        std::set<int> assignedNumbers; // Set to keep track of assigned numbers

        // Generate random mapping
        for (char c = 32; c <= 126; ++c) {
            // Generate a random number that is not already assigned
            int randomNumber;
            do {
                randomNumber = dis(gen);
            } while (assignedNumbers.find(randomNumber) != assignedNumbers.end());

            characterMap[c] = randomNumber; // Assign random number for each character
            assignedNumbers.insert(randomNumber); // Add assigned number to the set

        }
        std::cout << "Character Map:" << std::endl;
        for (const auto& pair : characterMap) {
            std::cout << pair.first << " -> " << pair.second << std::endl;
        }
    }

protected:
    int shifts;
    std::unordered_map<char, int> characterMap;

};
#endif // CUSTOMCIPHER_H