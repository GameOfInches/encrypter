#include <QApplication>
#include <QFile>
#include <QFont>
#include <QTextStream>
#include <QMessageBox>
#include <QDir>
#include "mainwindow.h"




int main(int argc, char* argv[]) {
    try {
        QApplication a(argc, argv);

        // Create the main window
        MainWindow w;

        // Show the main window
        w.show();

        return a.exec();
    }
    catch (const std::exception& e) {
        // Handle any standard exceptions thrown during initialization
        std::cerr << "Standard exception caught in main: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (...) {
        // Handle any other unexpected exceptions
        std::cerr << "Unknown exception caught in main" << std::endl;
        return EXIT_FAILURE;
    }
}

