import { useEffect, useMemo, useRef, useState } from "react";
import {
  decryptMessage,
  deriveSharedKey,
  encryptMessage,
  generateKeyPair,
  importPrivateKey,
  importPublicKey
} from "./crypto";
import {
  fetchPublicKey,
  login,
  pollMessages,
  sendMessage,
  setAuthToken,
  signup
} from "./api";

const STORAGE_KEYS = {
  username: "messager.username",
  publicKey: "messager.publicKey",
  privateKey: "messager.privateKey",
  token: "messager.token"
};

type ChatMessage = {
  id: number | string;
  sender: string;
  text: string;
  createdAt: number;
};

export default function App() {
  const [username, setUsername] = useState("");
  const [sessionUsername, setSessionUsername] = useState(
    localStorage.getItem(STORAGE_KEYS.username) || ""
  );
  const [token, setToken] = useState(
    localStorage.getItem(STORAGE_KEYS.token) || ""
  );
  const [publicKey, setPublicKey] = useState(
    localStorage.getItem(STORAGE_KEYS.publicKey) || ""
  );
  const [privateKey, setPrivateKey] = useState(
    localStorage.getItem(STORAGE_KEYS.privateKey) || ""
  );
  const [toUsername, setToUsername] = useState("");
  const [messageText, setMessageText] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const lastPollRef = useRef(0);

  useEffect(() => {
    setAuthToken(token || null);
  }, [token]);

  const privateKeyPromise = useMemo(() => {
    if (!privateKey) {
      return null;
    }
    return importPrivateKey(privateKey);
  }, [privateKey]);

  useEffect(() => {
    if (!token || !privateKeyPromise) {
      return undefined;
    }

    let isMounted = true;
    const poller = async () => {
      try {
        const data = await pollMessages(lastPollRef.current);
        if (!isMounted || !data.messages?.length) {
          return;
        }

        const privKey = await privateKeyPromise;
        const decrypted: ChatMessage[] = [];

        for (const msg of data.messages) {
          try {
            const senderKey = await importPublicKey(msg.sender_public_key);
            const sharedKey = await deriveSharedKey(privKey, senderKey);
            const text = await decryptMessage(
              sharedKey,
              msg.ciphertext,
              msg.nonce
            );
            decrypted.push({
              id: msg.id,
              sender: msg.sender_username,
              text,
              createdAt: msg.created_at
            });
          } catch (error) {
            decrypted.push({
              id: msg.id,
              sender: msg.sender_username,
              text: "[Failed to decrypt]",
              createdAt: msg.created_at
            });
          }
        }

        setMessages((prev) => [...prev, ...decrypted]);
        lastPollRef.current = data.messages[data.messages.length - 1].created_at;
      } catch (error) {
        setStatus((error as Error).message);
      }
    };

    const interval = setInterval(poller, 3000);
    poller();

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [privateKeyPromise, token]);

  const isLoggedIn = Boolean(token && sessionUsername);

  const handleSignup = async () => {
    setStatus(null);
    try {
      const keys = await generateKeyPair();
      const data = await signup(username, keys.publicKey);

      setSessionUsername(data.username);
      setToken(data.token);
      setPublicKey(keys.publicKey);
      setPrivateKey(keys.privateKey);

      localStorage.setItem(STORAGE_KEYS.username, data.username);
      localStorage.setItem(STORAGE_KEYS.token, data.token);
      localStorage.setItem(STORAGE_KEYS.publicKey, keys.publicKey);
      localStorage.setItem(STORAGE_KEYS.privateKey, keys.privateKey);

      setStatus("Signup complete");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleLogin = async () => {
    setStatus(null);
    try {
      if (!privateKey) {
        setStatus("No local private key found. Sign up on this device first.");
        return;
      }

      const data = await login(username);
      setSessionUsername(data.username);
      setToken(data.token);
      localStorage.setItem(STORAGE_KEYS.username, data.username);
      localStorage.setItem(STORAGE_KEYS.token, data.token);

      setStatus("Login complete");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleSend = async () => {
    if (!privateKeyPromise) {
      return;
    }
    setStatus(null);
    try {
      const recipient = await fetchPublicKey(toUsername);
      const recipientKey = await importPublicKey(recipient.publicKey);
      const senderKey = await privateKeyPromise;
      const sharedKey = await deriveSharedKey(senderKey, recipientKey);
      const encrypted = await encryptMessage(sharedKey, messageText);

      await sendMessage(toUsername, encrypted.ciphertext, encrypted.nonce);

      setMessages((prev) => [
        ...prev,
        {
          id: `local-${Date.now()}`,
          sender: sessionUsername,
          text: messageText,
          createdAt: Date.now()
        }
      ]);
      setMessageText("");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleLogout = () => {
    setToken("");
    localStorage.removeItem(STORAGE_KEYS.token);
    setStatus("Logged out");
  };

  return (
    <div className="app">
      <header className="header">
        <h1>Messager</h1>
        <p>Web messenger with end-to-end encryption (polling MVP).</p>
      </header>

      {!isLoggedIn && (
        <section className="card">
          <h2>Start</h2>
          <label>
            Username
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="username"
            />
          </label>
          <div className="row">
            <button onClick={handleSignup} disabled={!username}>
              Sign up (create keys)
            </button>
            <button onClick={handleLogin} disabled={!username}>
              Log in
            </button>
          </div>
          <p className="note">
            This MVP stores the private key only in your browser storage.
          </p>
        </section>
      )}

      {isLoggedIn && (
        <section className="card">
          <div className="row space">
            <h2>Hello, {sessionUsername}</h2>
            <button className="secondary" onClick={handleLogout}>
              Log out
            </button>
          </div>
          <div className="grid">
            <label>
              Send to
              <input
                value={toUsername}
                onChange={(event) => setToUsername(event.target.value)}
                placeholder="recipient username"
              />
            </label>
            <label>
              Message
              <textarea
                value={messageText}
                onChange={(event) => setMessageText(event.target.value)}
                placeholder="Type your message"
              />
            </label>
            <button
              onClick={handleSend}
              disabled={!toUsername || !messageText}
            >
              Send encrypted
            </button>
          </div>
        </section>
      )}

      <section className="card">
        <h2>Messages</h2>
        <div className="messages">
          {messages.length === 0 && <p>No messages yet.</p>}
          {messages.map((msg) => (
            <div key={msg.id} className="message">
              <div className="meta">
                <span>{msg.sender}</span>
                <span>{new Date(msg.createdAt).toLocaleTimeString()}</span>
              </div>
              <div className="text">{msg.text}</div>
            </div>
          ))}
        </div>
      </section>

      {status && <div className="status">{status}</div>}

      <section className="card small">
        <h3>Keys</h3>
        <p>Public key stored on server: {publicKey ? "yes" : "no"}</p>
        <p>Private key stored locally: {privateKey ? "yes" : "no"}</p>
      </section>
    </div>
  );
}
