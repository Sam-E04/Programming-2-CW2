#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;

string hashPassword(const string& password) {
    const EVP_MD* digestFunction = EVP_sha256();
    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (!context) {
        cerr << "Error creating context for hashPassword." << endl;
        return "";
    }

    if (1 != EVP_DigestInit_ex(context, digestFunction, NULL)) {
        cerr << "Error initializing digest for hashPassword." << endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    if (1 != EVP_DigestUpdate(context, password.c_str(), password.size())) {
        cerr << "Error updating digest for hashPassword." << endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;

    if (1 != EVP_DigestFinal_ex(context, hash, &hashLength)) {
        cerr << "Error finalizing digest for hashPassword." << endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    EVP_MD_CTX_free(context);

    string hashedPassword;
    for (unsigned int i = 0; i < hashLength; ++i) {
        hashedPassword += to_string(hash[i]);
    }

    return hashedPassword;
}

bool verifyPassword(const string& password, const string& hashedPassword) {
    string hashedInput = hashPassword(password);
    return hashedInput == hashedPassword;
}

string encryptMessage(const string& message, const unsigned char* iv) {

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) {
        cerr << "Error creating context for encryptMessage." << endl;
        return "";
    }

    if (1 != EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), NULL, NULL, NULL)) {
        cerr << "Error initializing encryption context." << endl;
        EVP_CIPHER_CTX_free(context);
        return "";
    }

    string ciphertext;

    if (1 != EVP_EncryptInit_ex(context, NULL, NULL, (const unsigned char*)"0123456789ABCDEF", iv)) {
        cerr << "Error setting key and IV for encryption." << endl;
        EVP_CIPHER_CTX_free(context);
        return "";
    }

    ciphertext.resize(message.size() + EVP_MAX_BLOCK_LENGTH);

    int encryptedLength = 0;

    if (1 != EVP_EncryptUpdate(context, (unsigned char*)&ciphertext[0], &encryptedLength, (const unsigned char*)message.c_str(), message.size())) {
        cerr << "Error encrypting message." << endl;
        EVP_CIPHER_CTX_free(context);
        return "";
    }

    int finalEncryptedLength = 0;
    if (1 != EVP_EncryptFinal_ex(context, (unsigned char*)&ciphertext[0] + encryptedLength, &finalEncryptedLength)) {
        cerr << "Error finalizing encryption." << endl;
        EVP_CIPHER_CTX_free(context);
        return "";
    }

    encryptedLength += finalEncryptedLength;
    EVP_CIPHER_CTX_free(context);

    ciphertext.resize(encryptedLength);

    return ciphertext;
}

string decryptMessage(const string& ciphertext, const unsigned char* iv) {

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) {
        cerr << "Error creating context for decryptMessage." << endl;
        return "";
    }

    if (1 != EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), NULL, NULL, NULL)) {
        cerr << "Error initializing decryption context." << endl;
        EVP_CIPHER_CTX_free(context);
        return "";
    }

    string plaintext;

    if (1 != EVP_DecryptInit_ex(context, NULL, NULL, (const unsigned char*)"0123456789ABCDEF", iv)) {
        cerr << "Error setting key and IV for decryption." << endl;
        EVP_CIPHER_CTX_free(context);
        return "";
    }

    plaintext.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

    int decryptedLength = 0;

    if (1 != EVP_DecryptUpdate(context, (unsigned char*)&plaintext[0], &decryptedLength, (const unsigned char*)ciphertext.c_str(), ciphertext.size())) {
        cerr << "Error decrypting message." << endl;
        EVP_CIPHER_CTX_free(context);
        return "";
    }

    int finalDecryptedLength = 0;
    if (1 != EVP_DecryptFinal_ex(context, (unsigned char*)&plaintext[0] + decryptedLength, &finalDecryptedLength)) {
        cerr << "Error finalizing decryption." << endl;
        EVP_CIPHER_CTX_free(context);
        return "";
    }

    decryptedLength += finalDecryptedLength;
    EVP_CIPHER_CTX_free(context);

    plaintext.resize(decryptedLength);

    return plaintext;
}