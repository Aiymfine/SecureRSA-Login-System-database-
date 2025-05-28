# SecureRSA-Login-System-database-
This is a Python Tkinter application that implements a secure login and registration system using RSA encryption. Usernames and passwords are encrypted and stored securely in an SQLite database, and only the owner (with the private RSA key) can decrypt and read them. After logging in, users can encrypt and decrypt messages using RSA.

Features
User registration and login with encrypted credentials

RSA key pair generation and storage (public.pem and private.pem)

User data stored in SQLite database (users.db) as encrypted hex strings

Encryption and decryption of messages after successful login

User-friendly Tkinter GUI


How It Works
1. RSA Key Generation
When the app runs the first time, it generates a pair of RSA keys:

public.pem (used to encrypt data)

private.pem (used to decrypt data)

Keys are saved locally and reused in future runs.
![image](https://github.com/user-attachments/assets/9445bd2d-e75f-4809-bf8c-c4491f3ddfee)


