# 🧠 Threat Model (THREAT_MODEL.md)

This document outlines the threat model for **Messager**.

---

## 🎯 Security Objectives

- Prevent server access to plaintext messages
- Protect messages from passive network attackers
- Maintain confidentiality in case of database compromise

---

## 👤 Actors

### Legitimate Users
- Use supported browsers
- Control their own devices

### Adversaries
- Passive network attackers
- Malicious or compromised server
- Database exfiltration attacker

---

## 🔍 In-Scope Threats

- Network eavesdropping
- Server compromise
- Database leaks
- Replay attacks

---

## ❌ Out-of-Scope Threats

- Compromised client device
- Malicious browser extensions
- XSS or supply-chain attacks
- Social engineering

---

## 🛡️ Mitigations

| Threat | Mitigation |
|-----|-----------|
| Network sniffing | TLS + E2EE |
| Server compromise | Zero-knowledge design |
| Database leak | Encrypted payloads only |
| Replay attacks | Nonces + message IDs |

---

## ⚠️ Known Risks

- Username-only authentication (v1)
- No forward secrecy
- No client verification mechanism

---

## 📌 Assumptions

- Browser crypto is trusted
- TLS is correctly configured
- Users protect their devices

---

Created by **Taha Vaziry**
