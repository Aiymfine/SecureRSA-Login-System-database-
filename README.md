# SecureRSA-Login-System-database-
This is a Python Tkinter application that implements a secure login and registration system using RSA encryption. Usernames and passwords are encrypted and stored securely in an SQLite database, and only the owner (with the private RSA key) can decrypt and read them. After logging in, users can encrypt and decrypt messages using RSA.

Features : 

-User registration and login with encrypted credentials

-RSA key pair generation and storage (public.pem and private.pem)

-User data stored in SQLite database (users.db) as encrypted hex strings

-Encryption and decryption of messages after successful login

-User-friendly Tkinter GUI


How It Works :

1. RSA Key Generation

When the app runs the first time, it generates a pair of RSA keys:

public.pem (used to encrypt data)

private.pem (used to decrypt data)



Keys are saved locally and reused in future runs.
![image](https://github.com/user-attachments/assets/9445bd2d-e75f-4809-bf8c-c4491f3ddfee)




2. Registration :
   
Users enter username and password.

These credentials are encrypted using the RSA public key.

Encrypted credentials are saved as hex strings in the SQLite database.

![image](https://github.com/user-attachments/assets/c68795f0-2199-4a80-b795-0080b7bf841b)  
![image](https://github.com/user-attachments/assets/cb403b31-fd54-4cea-9600-1966233b1ee9)


3. Login :
   
User enters username and password.

The app decrypts all stored credentials using the RSA private key.

It compares the decrypted credentials to the entered ones.

If a match is found, login is successful and message encryption features unlock.


4. Message Encryption/Decryption :
   
After login, users can encrypt any message with the RSA public key.

The encrypted message is shown as hex.

The app can decrypt the message back to plaintext with the private key.

![image](https://github.com/user-attachments/assets/674ae7f9-eef6-4a27-8af7-1f3fc9d7d7d2)



Files and Structure :

Main Python program with GUI and logic

SQLite database storing encrypted users

RSA public key (encrypt data)

RSA private key (decrypt data)

![image](https://github.com/user-attachments/assets/442f21ad-44a2-4c16-90a7-280d118b83b2)



Libraries Used :

tkinter :

Python’s built-in library for creating graphical user interfaces (GUI).
Used to build the login, registration, and message encryption windows.

sqlite3 :

Python’s built-in library for working with SQLite databases.
Used to store encrypted usernames and passwords persistently.

os :

Provides a way to interact with the operating system.
Used to check the existence of key and database files.

cryptography.hazmat.primitives.asymmetric.rsa :

Part of the cryptography library for RSA key generation and encryption/decryption.

cryptography.hazmat.primitives.asymmetric.padding :

Provides padding schemes like OAEP used in RSA encryption for security.

cryptography.hazmat.primitives.serialization :

Used for saving and loading RSA keys to/from files in PEM format.

cryptography.hazmat.primitives.hashes :

Provides cryptographic hash functions like SHA256, used in padding schemes.

![image](https://github.com/user-attachments/assets/d82cc810-afd3-4c22-bee9-7c781fcf4c09)









Encrypting Credentials Before Saving :        

![image](https://github.com/user-attachments/assets/cf7a8cd8-12b5-457e-9660-0bc8948877aa)    

Decrypting Credentials During Login :

![image](https://github.com/user-attachments/assets/6bd7ad0f-cf65-42aa-a10e-18f8fb9e44a6)

Security Notes :

Passwords and usernames are encrypted before storage, so only someone with the private RSA key can read them.

Message encryption uses RSA with OAEP padding and SHA256, ensuring strong cryptographic security.

For production use, consider adding password hashing alongside encryption for layered security.





