**🔐 Secure Password Manager**

A robust, local password manager built with Python and Tkinter. It uses strong AES encryption (Fernet) to securely store your credentials locally on your machine.

**🚀 Features**

* **AES-128 Encryption:** Uses the `cryptography` library to encrypt data using a Master Password.
* **Password Strength Meter:** Real-time visual feedback on password complexity (Very Weak to Very Strong).
* **Auto-Lock Timeout:** Automatically locks the session and closes the app after 30 seconds of inactivity.
* **Secure Storage:** Uses a unique salt for every user (`salt.key`) to prevent Rainbow Table attacks.
* **Zero-Knowledge:** Your master password is never stored; it is only used to derive the encryption key in memory.
* **CSV Export:** Backup your data to a CSV file (saved in plain text, use with caution!).
* **Clipboard Integration:** One-click copy for usernames and passwords.

**🛠️ Prerequisites**

* Python 3.x
* `cryptography` library

**⚡ Usage**

1.  Run the application:
    python main.py
    
3.  **First Run:** You will be asked to create a **Master Password**.
    * *Warning:* Do not forget this password! If you lose it, you lose access to your vault forever.
      
4.  **Login:** Enter your Master Password to unlock the vault.

**🛡️ Security Note**

This application generates two files locally:
* `vault.dat`: The encrypted database.
* `salt.key`: The random salt used for encryption.

**NEVER share or upload these two files.** They are strictly for your local machine.

**📜 License**

This project is open-source and available under the MIT License.

**Developed by Abdul Rehman Ali**

**Linkedin:** https://www.linkedin.com/in/abdul-rehman-ali-24964735b/
