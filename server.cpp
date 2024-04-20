#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <encryption.h>

using namespace std;

int main() {
    int serverSocket, clientSocket;
    int portNum = 1515;
    bool isExit = false;
    char buffer[1024];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    string text;

    struct sockaddr_in serverAddr, clientAddr;
    socklen_t size;

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        cout << "Error establishing socket..." << endl;
        exit(1);
    }

    cout << "Socket server has been created..." << endl;

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(portNum);
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cout << "Error binding connection..." << endl;
        exit(1);
    }

    listen(serverSocket, 1);

    cout << "Listening for connections on port " << portNum << "..." << endl;

    size = sizeof(clientAddr);
    
    clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &size);
    if (clientSocket < 0) {
        cout << "Error on accepting..." << endl;
        exit(1);
    }

    cout << "Connected with client..." << endl;

    memset(iv, 0, sizeof(iv));
    recv(clientSocket, iv, sizeof(iv), 0);

    while (true) {
        memset(buffer, 0, sizeof(buffer)); 
        recv(clientSocket, buffer, sizeof(buffer), 0);
        text = decryptMessage(buffer, iv);
        cout << "Client: " << text << endl;

        if (text == "#") {
            cout << "Connection terminated by client..." << endl;
            break;
        }

        cout << "Server: ";
        cin.getline(buffer, sizeof(buffer));
        text = encryptMessage(buffer, iv);
        send(clientSocket, text.c_str(), strlen(text.c_str()), 0);

        if (strcmp(buffer, "#") == 0) {
            cout << "Connection terminated by server..." << endl;
            break;
        }
    }

    close(clientSocket);
    close(serverSocket);

    return 0;
}

