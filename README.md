# 🔐 Messager — End-to-End Encrypted Web Messenger

**Messager** is a security-focused web messaging MVP implementing **End-to-End Encryption (E2EE)** using modern, standards-based cryptography.  
The system follows a **zero-trust server model**: the backend never has access to plaintext messages or private keys.

This project is intentionally minimal and auditable, designed to demonstrate **secure system design**, **correct cryptographic primitives**, and **clear threat boundaries**.

---

## 🎯 Project Goals

- Demonstrate a correct and practical E2EE architecture
- Minimize attack surface through simplicity
- Use browser-native cryptography (Web Crypto API)
- Maintain a clear and documented threat model
- Serve as a strong technical portfolio project

---

## ✨ Key Features

- End-to-End Encryption (client-side only)
- Zero-knowledge server (ciphertext storage only)
- Client-side key generation and management
- Deterministic, auditable crypto flow
- Polling-based message delivery (MVP)
- No native dependencies or opaque crypto libraries

---

## 🧱 Technology Stack

### Backend
- Node.js
- TypeScript
- Fastify
- JSON-based storage (MVP layer)

### Frontend
- React
- Vite
- TypeScript

### Cryptography
- Web Crypto API
- ECDH (P-256)
- HKDF (SHA-256)
- AES-GCM (authenticated encryption)

---

## 🔐 Cryptographic Design

### Key Management

- Each client generates an asymmetric ECDH key pair locally.
- Public keys are uploaded to the server.
- Private keys are **never transmitted**.
- Private keys are stored as **non-extractable CryptoKey objects** in IndexedDB.

### Message Encryption Flow

1. Sender fetches recipient public key.
2. Shared secret is derived using ECDH.
3. Symmetric key is derived via HKDF.
4. Message is encrypted using AES-GCM.
5. Ciphertext + nonce + metadata are sent to the server.
6. Recipient derives the same key and decrypts locally.

> The server cannot decrypt messages, even if fully compromised.

---

## 🧠 Threat Model (Summary)

### In Scope
- Passive network attackers
- Malicious or compromised server
- Database leakage
- Replay attacks (mitigated via nonces & message IDs)

### Out of Scope (v1)
- Device compromise
- Malicious client-side JavaScript injection
- Social engineering
- Advanced traffic analysis

---

## 📐 High-Level Architecture

```
Client (Encrypt) ──▶ Server (Store Only) ──▶ Client (Decrypt)
``>

- No plaintext at rest
- No plaintext in transit
- No server-side cryptographic material

---

## 🗂️ Data Model (MVP)

### User
- id
- username
- public_key
- created_at

### Message
- id (client-generated UUID)
- sender_id
- recipient_id
- ciphertext
- nonce
- created_at
- delivered_at

---

## 🚀 Local Development

### Requirements
- Node.js 18+

### Install

```bash
cd server
npm install
cd ../client
npm install
```

### Run

```bash
cd server
npm run dev
cd ../client
npm run dev
```

Open:
```
http://localhost:5173
```

---

## ⚠️ Security Considerations

- Username-only authentication is **not secure** and used only for MVP simplicity.
- No forward secrecy yet (static ECDH keys).
- No key rotation implemented.
- No message verification UI (fingerprints / QR).

These limitations are documented intentionally and planned for future iterations.

---

## 🛣️ Roadmap

- Forward secrecy (per-message keys)
- Key verification & fingerprint UI
- WebSocket-based real-time delivery
- Proper authentication & identity binding
- Message expiration & self-destruct
- Formal threat model documentation

---

## 🧪 Disclaimer

This project is provided for **educational and demonstration purposes**.
It must undergo further security review before any production use.

---

## 📄 License

MIT License

---

## 👤 Author

Created by **Taha Vaziry**

This project is intentionally designed to be readable, auditable, and security-review friendly.
