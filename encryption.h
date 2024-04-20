#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <string>

std::string hashPassword(const std::string& password);
bool verifyPassword(const std::string& password, const std::string& hashedPassword);
std::string encryptMessage(const std::string& message, const unsigned char* iv);
std::string decryptMessage(const std::string& ciphertext, const unsigned char* iv);


#endif