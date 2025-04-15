# 🔐 SecureVault – A Python-Based Secrets Management CLI Tool

> Securely store, retrieve, and manage sensitive credentials using strong encryption and a simple command-line interface. Built with a security-first mindset using Python.

---

## 🚀 Overview

**SecureVault** is a lightweight secrets management tool designed for developers and security enthusiasts. It enables you to securely encrypt, store, and retrieve API keys, passwords, and tokens using symmetric encryption — all from the comfort of your terminal.

This project demonstrates best practices in **application security**, **secure programming**, and **cybersecurity tooling** with Python.

---

## 🛠️ Core Features

### ✅ Encrypted Secrets Storage
- Uses the `cryptography` library (Fernet symmetric encryption) to store secrets safely. 

### 🔐 Master Password Authentication
- Access to your vault is protected by a master password. 

### 🔎 Secure Retrieval with Clipboard Support
- Retrieve secrets by key name without displaying them in plaintext.
- Optionally copy secret values directly to the clipboard for safe usage (`pyperclip`).

### 📜 Audit Logging
- All access attempts (successful or failed) are logged with timestamps.
- Helps detect unusual access patterns or brute-force attempts.

### 🧹 Secure Deletion
- Permanently remove a secret and overwrite sensitive memory to prevent recovery.
- Supports soft-delete and shred mode for additional security.

---

## 🧠 Learning Goals & Skills Demonstrated

- ✅ Symmetric encryption and secure data storage
- ✅ Hashing and password-based access control
- ✅ Defensive coding (input validation, error handling)
- ✅ Secure user input handling via `getpass`
- ✅ Audit trails and basic logging for forensic purposes
- ✅ Secret hygiene and secure memory handling

---

## 📦 Tech Stack

- **Python 3.10+**
- `cryptography` – Encryption & key management
- `getpass` – Secure password entry
- `pyperclip`  – Clipboard integration

---

## 📸 Demo

```bash
$ python securevault.py  
🔐 Secret copied to clipboard.
