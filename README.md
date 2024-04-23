# How R User (Safe Advanced Chat Application)

## Description
This project is an encrypted chat application in C++ as part of the coursework for Programming and Algorithms 2. 
It is designed to securely send and retrieve passwords and create, edit, save and delete accounts.


<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#explanation">Explanation</a>
      <ul>
        <li><a href="#made-with">Made With</a></li>
        <li><a href="#files">Files</a></li>
        <li><a href="#features">Features</a></li>
      </ul>
    </li>
    <li><a href="#contact">Made By:</a></li>
  </ol>
</details>


## Explanation

### Made With

<img style="width:400px;height:450px;" src="https://upload.wikimedia.org/wikipedia/commons/thumb/1/18/ISO_C%2B%2B_Logo.svg/1200px-ISO_C%2B%2B_Logo.svg.png">

### File Structure

```bash
Programming2-CW1/
├── client.cpp/
├── server.cpp/
├── client.exe/
├── server.exe/
├── auth.cpp/
├── auth.h/
├── encryption.cpp/
├── encryption.h/
├── accounts.txt/
└── README.md
```

### Features

+ Simultaneous messaging between two users
+ End to end encryption with AES-256 algorithms to keep messages safe from man-in-the-middle attacks
+ Creates users and allows edit and delete functions
+ Handles passwords for multiple unique users
+ Encrypts saved password files using the SHA-256 hashing algorithm
+ Fast login system using a hashtable

### Functions

+ client.cpp
+ hear
+ talk
+ main
+ hashPassword
+ encryptMessage
+ decryptMessage
+ hash
+ deleteAllAccounts
+ HashTable
+ ~HashTable
+ addAccount
+ authenticate
+ updatePassword
+ removeAccount
+ saveToFile
+ loadFromFile


## Made By:

Ismail Ahmed Mohamed

im2200078@tkh.edu.eg

<p align="right">(<a href="#readme-top">back to top</a>)</p>
