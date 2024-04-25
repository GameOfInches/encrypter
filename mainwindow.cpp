#include <iostream>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QDir>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <files.h>
#include <string>


MainWindow::MainWindow(QWidget* parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    aesCipher(new AESCipher),
    rsaCipher(new RSACipher),
    safCipher(new SAFCipher),
    numzCipher(new NUMZCipher)

{
    try {
        QDir::setCurrent(QCoreApplication::applicationDirPath());
        ui->setupUi(this);
        ui->inputTextEdit->setFont(QFont("Arial", 12));
        connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::encrypt);
        connect(ui->decryptButton, &QPushButton::clicked, this, &MainWindow::decrypt);

        // Load encryption keys from file
        QFile file("input.txt");
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Error", "Failed to open input.txt! " + file.errorString());
            return;
        }
        QTextStream in(&file);
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (line.startsWith("EncryptionKey:")) {
                QString key = line.mid(15).trimmed();
                ui->algorithmComboBox->addItem(key);
            }
        }
        file.close();

    }
    catch (const CryptoPP::Exception& e) {
        // Handle CryptoPP exceptions
        QMessageBox::warning(this, "Encryption Error", QString("CryptoPP Exception caught: ") + e.what());
    }
    catch (const std::exception& e) {
        // Handle other standard exceptions
        QMessageBox::warning(this, "Encryption Error", QString("Standard Exception caught: ") + e.what());
    }
    catch (...) {
        // Handle any other unexpected exceptions
        QMessageBox::warning(this, "Encryption Error", "Unknown Exception caught");
    }

}

MainWindow::~MainWindow()
{
    // Destructor to clean up dynamically allocated memory
    delete aesCipher;
    delete rsaCipher;
    delete safCipher;
    delete numzCipher;
    delete ui;
}

void MainWindow::encrypt() {
    try {
        // Get plaintext and selected algorithm
        QString plaintext = ui->inputTextEdit->toPlainText();
        QString algorithm = ui->algorithmComboBox->currentText();
        std::cout << "encrypt: Received text is:" << plaintext.toStdString() << std::endl;
        // Perform encryption based on the selected algorithm
        if (algorithm == "AES") {

            // Encrypt plaintext using AES
            std::string encryptedText = aesCipher->encrypt(plaintext.toStdString(), Cipher::Ciphers::AES);
            QString qtEncryptedText = QString::fromStdString(encryptedText);

            std::cout << "encrypt: Encrypted text is:" << qtEncryptedText.toStdString() << std::endl;

            ui->outputTextEdit->setText(qtEncryptedText);
        }
        else if (algorithm == "RSA") {

            // Encrypt plaintext using RSA
            QString encryptedText = QString::fromStdString(rsaCipher->encrypt(plaintext.toStdString(), Cipher::Ciphers::RSA));
            QString qtEncryptedText = encryptedText;

            std::cout << "encrypt(): Encrypted text is:" << qtEncryptedText.toStdString() << std::endl;

            ui->outputTextEdit->setText(qtEncryptedText);

        }
        else if (algorithm == "SAF") {

            // Encrypt plaintext using SAF
            QString encryptedText = QString::fromStdString(safCipher->encrypt(plaintext.toStdString(), Cipher::Ciphers::SAF));
            QString qtEncryptedText = encryptedText;

            std::cout << "encrypt(): Encrypted text is:" << qtEncryptedText.toStdString() << std::endl;

            ui->outputTextEdit->setText(qtEncryptedText);

        }
        else if (algorithm == "NUMZ") {
            // Encrypt plaintext using NUMZ and check if the input first contains any digits, if it does, prompt user to insert new text
            if (!containsDigits(plaintext.toStdString())) {
                QString encryptedText = QString::fromStdString(numzCipher->encrypt(plaintext.toStdString(), Cipher::Ciphers::NUMZ));
                QString qtEncryptedText = encryptedText;
                qtEncryptedText.remove('_');

                std::cout << "encrypt(): Encrypted text is:" << qtEncryptedText.toStdString() << std::endl;

                ui->outputTextEdit->setText(qtEncryptedText);
            }
            else {
                QMessageBox::warning(this, "Input Error", QString("Input for NUMZ encryption cannot contain digits!"));
            }

        }
        else {
            // Handle other encryption algorithms
            ui->outputTextEdit->setText("Encryption for selected algorithm not implemented yet.");
        }
    }
    catch (const CryptoPP::Exception& e) {
        // Handle CryptoPP exceptions
        QMessageBox::warning(this, "Encryption Error", QString("CryptoPP Exception caught: ") + e.what());
    }
    catch (const std::exception& e) {
        // Handle other standard exceptions
        QMessageBox::warning(this, "Encryption Error", QString("Standard Exception caught: ") + e.what());
    }
    catch (...) {
        // Handle any other unexpected exceptions
        QMessageBox::warning(this, "Encryption Error", "Unknown Exception caught");
    }
}

void MainWindow::decrypt() {
    try {
        // Get ciphertext and selected algorithm
        QString ciphertext = ui->inputTextEdit->toPlainText();
        QString algorithm = ui->algorithmComboBox->currentText();
        std::cout << "decrypt: Received text is:" << ciphertext.toStdString() << std::endl;
        // Perform decryption based on the selected algorithm
        if (algorithm == "AES") {
            // Decrypt ciphertext using AES
            std::string decryptedText = aesCipher->decrypt(ciphertext.toStdString(), Cipher::Ciphers::AES);
            QString qtDecryptedText = QString::fromStdString(decryptedText);
            std::cout << "Decrypted text (decrypt()): " << decryptedText << std::endl;
            ui->outputTextEdit->setText(qtDecryptedText);
        }
        else if (algorithm == "RSA") {

            // Decrypt ciphertext using RSA
            QString decryptedText = QString::fromStdString(rsaCipher->decrypt(ciphertext.toStdString(), Cipher::Ciphers::RSA));
            QString qtDecryptedText = decryptedText;
            std::cout << "Decrypted text (decrypt()): " << decryptedText.toStdString() << std::endl;
            ui->outputTextEdit->setText(qtDecryptedText);

        }
        else if (algorithm == "SAF") {

            // Decrypt ciphertext using SAF
            QString decryptedText = QString::fromStdString(safCipher->decrypt(ciphertext.toStdString(), Cipher::Ciphers::SAF));
            QString qtDecryptedText = decryptedText;
            std::cout << "Decrypted text (decrypt()): " << decryptedText.toStdString() << std::endl;
            ui->outputTextEdit->setText(qtDecryptedText);

        }
        else if (algorithm == "NUMZ") {
            // Decrypt ciphertext using NUMZ and check if the input contains any characters. If it doesn't contain only digits, prompt the user to enter different input
            if (containsOnlyDigits(ciphertext.toStdString())) {
                QString decryptedText = QString::fromStdString(numzCipher->decrypt(ciphertext.toStdString(), Cipher::Ciphers::NUMZ));
                QString qtDecryptedText = decryptedText;
                std::cout << "Decrypted text (decrypt()): " << decryptedText.toStdString() << std::endl;
                ui->outputTextEdit->setText(qtDecryptedText);
            }
            else {
                QMessageBox::warning(this, "Input Error", QString("Input for NUMZ decryption can contain only digits!"));
            }

        }
        else {
            // Handle other decryption algorithms
            ui->outputTextEdit->setText("Decryption for selected algorithm not implemented yet.");
        }
    }
    catch (const CryptoPP::Exception& e) {
        // Handle CryptoPP exceptions
        QMessageBox::warning(this, "Decryption Error", QString("CryptoPP Exception caught: ") + e.what());
    }
    catch (const std::exception& e) {
        // Handle other standard exceptions
        QMessageBox::warning(this, "Decryption Error", QString("Standard Exception caught: ") + e.what());
    }
    catch (...) {
        // Handle any other unexpected exceptions
        QMessageBox::warning(this, "Decryption Error", "Unknown Exception caught");
    }
}

bool MainWindow::containsDigits(const std::string& str) {
    // Check if the string contains any digits
    return std::any_of(str.begin(), str.end(), ::isdigit);
}

bool MainWindow::containsOnlyDigits(const std::string& str) {
    // Check if the string contains only digits
    return std::all_of(str.begin(), str.end(), ::isdigit);
}





