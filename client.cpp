#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <encryption.h>

using namespace std;

int main() {

    int clientSocket;
    int portNum = 1515;
    char buffer[1024];
    struct sockaddr_in serverAddr;
    string text;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        cout << "Error establishing socket..." << endl;
        exit(1);
    }

    cout << "Socket client has been created..." << endl;

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNum);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (1 != RAND_bytes(iv, EVP_MAX_IV_LENGTH)) {
        cerr << "Error generating random initialization vector." << endl;
    }

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cout << "Connection error..." << endl;
        exit(1);
    }

    cout << "Connected to server..." << endl;

    send(clientSocket, iv, EVP_MAX_IV_LENGTH, 0);

    while (true) {
        cout << "Client: ";
        memset(buffer, 0, sizeof(buffer));
        cin.getline(buffer, sizeof(buffer));
        text = encryptMessage(buffer, iv);
        send(clientSocket, text.c_str(), strlen(text.c_str()), 0);

        if (strcmp(buffer, "#") == 0) {
            cout << "Connection terminated by client..." << endl;
            break;
        }

        memset(buffer, 0, sizeof(buffer));
        recv(clientSocket, buffer, sizeof(buffer), 0);
        text = decryptMessage(buffer, iv);
        cout << "Server: " << text << endl;

        if (text == "#") {
            cout << "Connection terminated by server..." << endl;
            break;
        }
    }

    close(clientSocket);

    return 0;
}

