# 🔐 Cryptographic Design (CRYPTO.md)

This document describes the cryptographic architecture and design decisions used in **Messager**.

---

## 🔑 Cryptographic Goals

- Confidentiality of messages
- Server-side zero knowledge
- Integrity and authenticity of ciphertext
- Use of modern, standardized primitives
- Minimal custom cryptography

---

## 🧠 Primitives Used

| Purpose | Algorithm |
|------|----------|
| Key Agreement | ECDH (P-256) |
| Key Derivation | HKDF (SHA-256) |
| Symmetric Encryption | AES-GCM |
| Randomness | Web Crypto RNG |

---

## 🔐 Key Lifecycle

### Key Generation
- Generated client-side using Web Crypto API
- Asymmetric ECDH key pair
- Private key marked as **non-extractable**
- Stored in IndexedDB

### Public Key Handling
- Public key is uploaded to the server
- Used by other clients to derive shared secrets

---

## ✉️ Message Encryption Flow

1. Sender fetches recipient public key
2. ECDH derives shared secret
3. HKDF derives symmetric key
4. Message encrypted with AES-GCM
5. Nonce generated per message
6. Ciphertext + nonce sent to server

---

## 🔓 Decryption Flow

1. Recipient fetches encrypted message
2. Shared secret derived via ECDH
3. Symmetric key derived via HKDF
4. Ciphertext decrypted locally

---

## ⚠️ Known Limitations (v1)

- No forward secrecy
- Static long-term keys
- No key rotation
- No key verification UI

These are intentional MVP limitations.

---

## ✅ Security Notes

- No plaintext ever reaches the server
- AES-GCM provides integrity and confidentiality
- Cryptographic operations rely solely on Web Crypto API

---

Created by **Taha Vaziry**
