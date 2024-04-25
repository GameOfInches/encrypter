cmake_minimum_required(VERSION 3.5)

project(EncryptionApp)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 COMPONENTS Widgets REQUIRED)


include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cyphers/cryptopp ${CMAKE_CURRENT_SOURCE_DIR}/cyphers)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dependencies/cryptopp)


set(SOURCES
    main.cpp
    mainwindow.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/aescipher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/rsacipher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/safcipher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/numzcipher.cpp
)

set(HEADERS
    mainwindow.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/cipher.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/rsacipher.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/aescipher.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/keyedcipher.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/customcipher.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/safcipher.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphers/numzcipher.h
)

set(UIS
    mainwindow.ui
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS} ${UIS})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/input.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${PROJECT_NAME} Qt6::Widgets)
target_link_libraries(${PROJECT_NAME} cryptopp)

