# 🔐 Secure Password Manager

A **Secure Password Manager** built using **Python** that protects user credentials with modern cryptographic techniques and secure communication protocols.  
This project demonstrates the application of **encryption, digital signatures, and TLS** to ensure data confidentiality, integrity, and secure synchronization — following a **zero-knowledge design** where the server never sees your plaintext passwords.

---

## 🧩 Features

- 🛡️ **AES-GCM Encryption** for data confidentiality  
- ✍️ **Ed25519 Digital Signatures** for data integrity  
- 🌐 **TLS Secure Communication** between client and server  
- 🧠 **Zero-Knowledge Architecture** – server stores only encrypted data  
- 🔑 **Local Encryption** before synchronization  
- 💾 **Secure Password Storage** using derived keys from a master password  
- 🔁 **Cross-Device Syncing** with encryption  
- 🧰 **User-Friendly Interface** for managing credentials  

---

## 🏗️ Project Structure

SecurePasswordManager/
│
├── client/ # Client-side code (encryption, UI)
│ ├── main.py # Main program entry point
│ ├── crypto_utils.py # Encryption, signing, key derivation functions
│ ├── ui.py # Command-line or GUI interface
│ ├── config.json # Client configuration (server URL, settings)
│ └── requirements.txt # Client dependencies
│
├── server/ # Server-side code (API, storage, verification)
│ ├── server.py # Flask/FastAPI server handling requests
│ ├── database.py # Encrypted storage logic
│ └── requirements.txt # Server dependencies
│
├── docs/ # Documentation and screenshots
│ ├── architecture_diagram.png
│ ├── encryption_flow.png
│ └── ui_screenshot.png

Architecture_diagram:

<img width="1095" height="730" alt="image" src="https://github.com/user-attachments/assets/d30cb4e8-7884-47c8-b0b9-798202ec09b7" />



Install dependencies

pip install -r client/requirements.txt
pip install -r server/requirements.txt

🚀 Usage

Start the Server

cd server
python server.py


Run the Client

cd client
python main.py


Create an Account and Add Credentials

Enter a strong master password.
<img width="929" height="791" alt="image" src="https://github.com/user-attachments/assets/afa0bb49-1ecf-4bbd-a92f-beff8f6f90ad" />

Add credentials (website, username, password).

<img width="435" height="324" alt="image" src="https://github.com/user-attachments/assets/6c4e0027-195d-4d03-aa05-d1627b24c7ce" />
<img width="447" height="327" alt="image" src="https://github.com/user-attachments/assets/2507d62e-6119-4314-b86f-9aad94506437" />
<img width="445" height="315" alt="image" src="https://github.com/user-attachments/assets/7fde4f5c-31fd-44d2-b87c-26e849b16252" />
<img width="447" height="327" alt="image" src="https://github.com/user-attachments/assets/a13f3a11-d624-429b-9ec2-55b071d2a0ce" />


All data will be encrypted and synced securely.

<img width="533" height="392" alt="image" src="https://github.com/user-attachments/assets/ddef52fa-8cbd-4b3c-a6e6-37cc86d6551c" />


Retrieve Stored Passwords

<img width="1024" height="791" alt="image" src="https://github.com/user-attachments/assets/20157383-1739-40c6-9a4b-9acd18243b88" />


Authenticate with your master password.

View or copy decrypted credentials locally (never sent to the server unencrypted).

{"db2": {"username": "teja", "password": "efnGuAJ0Ze8Ivrxv2qpRmkltIl/DkDFVPYt1A0uyitc=", "signature": "OpB3RIO9Hn51LD/84a49TZDLX14PpLKrYxuWjVBJDqkeUWjVmKnE40+1viUVazTQUyVFmxiKAITa9NFIOmlNCA=="}, "m1": {"username": "teja", "password": "Mp2MDW5/z7msYXsBwcj/i1bwP1U+wuKB6IzLC9jRDpk=", "signature": "NbHhce7pPvy3OvQ2xtOl5zeEV1a4ZCu7TXjTiq+FK51xmKH62ZAerAYOWEJnjoXXOOiASwmZzC+AQGtXMGhHAg=="}}

Certificate is generated successfully: 

<img width="488" height="636" alt="Screenshot 2025-10-26 202936" src="https://github.com/user-attachments/assets/26f7de45-cb85-40de-9c1c-86dc0543f518" />


🔐 Security Details

Encryption Algorithm: AES-256-GCM for authenticated encryption

Key Derivation: PBKDF2 or Argon2 from user’s master password

Digital Signature: Ed25519 for tamper detection

Transport Security: TLS for encrypted communication

Zero-Knowledge Design: Server never stores or processes plaintext data

Data Integrity: Every encrypted record includes a digital signature
