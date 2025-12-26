# Messager (Web, E2E)

Messager is a minimal web messenger MVP that demonstrates end-to-end encryption
(E2EE). The server only stores encrypted payloads and never sees plaintext.

Created by: tahapx
License: MIT (change if needed)

## Features (v1)

- Username + password signup/login
- Polling-based message delivery
- End-to-end encryption in the browser
- Server stores ciphertext only
- No native dependencies in the backend
- Personal chats, groups, and channels (max 5 members)
- Encrypted image/audio attachments (base64)
- Admin panel for moderation (ban, limits, delete users/channels)
- User profile logging (IP + device info per username file)

## Tech stack

Backend:
- Node.js
- TypeScript
- Fastify
- JSON file storage (data.json)

Frontend:
- React
- Vite
- TypeScript

Crypto (client-side only):
- Web Crypto API
- ECDH (P-256)
- AES-GCM

## Architecture (high level)

- Client generates a key pair locally.
- Public key is uploaded to the server.
- Sender derives a shared key using recipient public key.
- Message is encrypted in the browser.
- Server stores and returns ciphertext only.

## Requirements

- Node.js 18+
- npm

## Project structure

- `server/` Fastify API
- `client/` React web app

## Setup and run

Install dependencies:

```bash
cd server
npm install
cd ../client
npm install
```

Run backend:

```bash
cd server
npm run dev
```

Run frontend:

```bash
cd client
npm run dev
```

Open `http://localhost:5173`.

## Admin panel

Default admin credentials:

- Username: `myadmin`
- Password: `000123`

Change the admin password after first login in the admin panel.

## Local testing tip

Open two browser profiles (normal + incognito) and sign up with two different
usernames to test encrypted chat between them.

## Security notes (MVP)

- Simple password auth (no MFA).
- Private key is stored in browser storage (not safe for production).
- No forward secrecy or key rotation.
- No key verification (fingerprints/QR).
 - Attachments are stored as encrypted base64 strings (size capped).

## Roadmap

- Strong authentication
- Key verification UI
- WebSocket realtime delivery
- Replace JSON storage with SQLite/Postgres
- Message expiration / cleanup

## License

MIT
