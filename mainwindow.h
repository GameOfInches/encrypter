#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <vector>
#include <cryptopp/misc.h>
#include <cryptopp/rsa.h>
#include "ciphers/rsacipher.h"
#include "ciphers/aescipher.h"
#include "ciphers/safcipher.h"
#include "ciphers/numzcipher.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();


private slots:
    void encrypt();
    void decrypt();
    bool containsDigits(const std::string& str);
    bool containsOnlyDigits(const std::string& str);

private:
    Ui::MainWindow* ui;
    AESCipher* aesCipher;
    RSACipher* rsaCipher;
    SAFCipher* safCipher;
    NUMZCipher* numzCipher;
 
};

#endif // MAINWINDOW_H
