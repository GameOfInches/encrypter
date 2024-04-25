/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.15.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QMainWindow *MainWindow;
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QTextEdit *inputTextEdit;
    QTextEdit *outputTextEdit;
    QComboBox *algorithmComboBox;
    QPushButton *encryptButton;
    QPushButton *decryptButton;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (!MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QStringLiteral("MainWindow"));
        MainWindow->resize(400, 338);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName(QStringLiteral("centralwidget"));
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName(QStringLiteral("verticalLayout"));
        inputTextEdit = new QTextEdit(centralwidget);
        inputTextEdit->setObjectName(QStringLiteral("inputTextEdit"));
        verticalLayout->addWidget(inputTextEdit);
        outputTextEdit = new QTextEdit(centralwidget);
        outputTextEdit->setObjectName(QStringLiteral("outputTextEdit"));
        verticalLayout->addWidget(outputTextEdit);
        algorithmComboBox = new QComboBox(centralwidget);
        algorithmComboBox->setObjectName(QStringLiteral("algorithmComboBox"));
        verticalLayout->addWidget(algorithmComboBox);
        encryptButton = new QPushButton(centralwidget);
        encryptButton->setObjectName(QStringLiteral("encryptButton"));
        verticalLayout->addWidget(encryptButton);
        decryptButton = new QPushButton(centralwidget);
        decryptButton->setObjectName(QStringLiteral("decryptButton"));
        verticalLayout->addWidget(decryptButton);
        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName(QStringLiteral("menubar"));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName(QStringLiteral("statusbar"));
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "MainWindow", nullptr));
        encryptButton->setText(QCoreApplication::translate("MainWindow", "Encrypt", nullptr));
        decryptButton->setText(QCoreApplication::translate("MainWindow", "Decrypt", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
