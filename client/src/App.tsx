import { useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import {
  decryptMessage,
  deriveSharedKey,
  encryptMessage,
  generateKeyPair,
  importPrivateKey,
  importPublicKey
} from "./crypto";
import {
  createConversation,
  fetchMembers,
  listConversations,
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

const MAX_ATTACHMENT_SIZE = 2 * 1024 * 1024;

type Attachment = {
  kind: "image" | "audio";
  name: string;
  data: string;
};

type MessagePayload = {
  text: string;
  attachments: Attachment[];
};

type ChatMessage = {
  id: number | string;
  conversationId: number;
  sender: string;
  payload: MessagePayload;
  createdAt: number;
};

type Conversation = {
  id: number;
  type: "direct" | "group" | "channel";
  name: string | null;
  ownerId: number;
  members: Array<{ username: string; publicKey: string }>;
};

const tabs: Array<Conversation["type"]> = ["group", "channel", "direct"];

function getConversationTitle(conversation: Conversation, self: string): string {
  if (conversation.type === "direct") {
    const other = conversation.members.find((m) => m.username !== self);
    return other ? other.username : "Direct";
  }
  return conversation.name || "Untitled";
}

function parsePayload(text: string): MessagePayload {
  try {
    const parsed = JSON.parse(text) as MessagePayload;
    if (typeof parsed.text === "string" && Array.isArray(parsed.attachments)) {
      return parsed;
    }
  } catch {
    // fall back to plain text
  }
  return { text, attachments: [] };
}

export default function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
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
  const [tab, setTab] = useState<Conversation["type"]>("group");
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversationId, setSelectedConversationId] = useState<
    number | null
  >(null);
  const [messageText, setMessageText] = useState("");
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [directUsername, setDirectUsername] = useState("");
  const [groupName, setGroupName] = useState("");
  const [groupMembers, setGroupMembers] = useState("");

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

  const isLoggedIn = Boolean(token && sessionUsername);

  const refreshConversations = async () => {
    try {
      const data = await listConversations();
      setConversations(data.conversations || []);
      if (!selectedConversationId && data.conversations?.length) {
        setSelectedConversationId(data.conversations[0].id);
      }
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  useEffect(() => {
    if (!isLoggedIn) {
      return;
    }
    refreshConversations();
  }, [isLoggedIn]);

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
              conversationId: msg.conversation_id,
              sender: msg.sender_username,
              payload: parsePayload(text),
              createdAt: msg.created_at
            });
          } catch {
            decrypted.push({
              id: msg.id,
              conversationId: msg.conversation_id,
              sender: msg.sender_username,
              payload: { text: "[Failed to decrypt]", attachments: [] },
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

  const handleSignup = async () => {
    setStatus(null);
    try {
      const keys = await generateKeyPair();
      const data = await signup(username, password, keys.publicKey);

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

      const data = await login(username, password);
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
    if (!privateKeyPromise || !selectedConversationId) {
      return;
    }

    const conversation = conversations.find(
      (item) => item.id === selectedConversationId
    );
    if (!conversation) {
      return;
    }

    setStatus(null);
    try {
      let members = conversation.members;
      if (!members.length) {
        const memberData = await fetchMembers(conversation.id);
        members = memberData.members || [];
      }

      const payload: MessagePayload = {
        text: messageText,
        attachments
      };

      const senderKey = await privateKeyPromise;
      const payloads: Array<{
        toUsername: string;
        ciphertext: string;
        nonce: string;
      }> = [];

      for (const member of members) {
        if (member.username === sessionUsername) {
          continue;
        }
        const recipientKey = await importPublicKey(member.publicKey);
        const sharedKey = await deriveSharedKey(senderKey, recipientKey);
        const encrypted = await encryptMessage(
          sharedKey,
          JSON.stringify(payload)
        );
        payloads.push({
          toUsername: member.username,
          ciphertext: encrypted.ciphertext,
          nonce: encrypted.nonce
        });
      }

      if (payloads.length === 0) {
        setStatus("No recipients available in this conversation.");
        return;
      }

      await sendMessage(conversation.id, payloads);

      setMessages((prev) => [
        ...prev,
        {
          id: `local-${Date.now()}`,
          conversationId: conversation.id,
          sender: sessionUsername,
          payload,
          createdAt: Date.now()
        }
      ]);
      setMessageText("");
      setAttachments([]);
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleLogout = () => {
    setToken("");
    localStorage.removeItem(STORAGE_KEYS.token);
    setStatus("Logged out");
  };

  const handleCreateConversation = async () => {
    setStatus(null);
    try {
      if (tab === "direct") {
        await createConversation("direct", null, [directUsername]);
        setDirectUsername("");
      } else {
        const members = groupMembers
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean);
        await createConversation(tab, groupName, members);
        setGroupName("");
        setGroupMembers("");
      }
      await refreshConversations();
      setStatus("Conversation created");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleAttachmentChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) {
      return;
    }

    const next: Attachment[] = [];

    for (const file of Array.from(files)) {
      if (file.size > MAX_ATTACHMENT_SIZE) {
        setStatus(`File ${file.name} is too large (max 2MB).`);
        continue;
      }

      if (!file.type.startsWith("image/") && !file.type.startsWith("audio/")) {
        setStatus(`Unsupported file type: ${file.type}`);
        continue;
      }

      const data = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result as string);
        reader.onerror = () => reject(new Error("Failed to read file"));
        reader.readAsDataURL(file);
      });

      next.push({
        kind: file.type.startsWith("image/") ? "image" : "audio",
        name: file.name,
        data
      });
    }

    setAttachments((prev) => [...prev, ...next]);
    event.target.value = "";
  };

  const filteredConversations = conversations.filter(
    (conv) => conv.type === tab
  );

  const activeMessages = messages.filter(
    (msg) => msg.conversationId === selectedConversationId
  );

  const selectedConversation = conversations.find(
    (item) => item.id === selectedConversationId
  );

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <h1>Messager</h1>
          <p>Secure chats with E2E encryption (MVP).</p>
        </div>
        {isLoggedIn && (
          <div className="user-pill">
            <span>{sessionUsername}</span>
            <button className="secondary" onClick={handleLogout}>
              Log out
            </button>
          </div>
        )}
      </header>

      {!isLoggedIn && (
        <section className="card auth-card">
          <h2>Access</h2>
          <label>
            Username
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="username"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="password"
            />
          </label>
          <div className="row">
            <button onClick={handleSignup} disabled={!username || !password}>
              Sign up (create keys)
            </button>
            <button onClick={handleLogin} disabled={!username || !password}>
              Log in
            </button>
          </div>
          <p className="note">
            This MVP stores the private key only in your browser storage.
          </p>
        </section>
      )}

      {isLoggedIn && (
        <div className="layout">
          <aside className="sidebar card">
            <div className="tabs">
              {tabs.map((item) => (
                <button
                  key={item}
                  className={item === tab ? "active" : ""}
                  onClick={() => setTab(item)}
                >
                  {item === "direct" ? "Personal" : item}
                </button>
              ))}
            </div>

            <div className="conversation-list">
              {filteredConversations.length === 0 && (
                <p className="muted">No conversations yet.</p>
              )}
              {filteredConversations.map((conv) => (
                <button
                  key={conv.id}
                  className={
                    conv.id === selectedConversationId
                      ? "conversation active"
                      : "conversation"
                  }
                  onClick={() => setSelectedConversationId(conv.id)}
                >
                  <div className="title">
                    {getConversationTitle(conv, sessionUsername)}
                  </div>
                  <div className="meta">
                    {conv.members.map((member) => member.username).join(", ")}
                  </div>
                </button>
              ))}
            </div>

            <div className="divider" />

            <div className="create-block">
              {tab === "direct" ? (
                <>
                  <h3>New direct chat</h3>
                  <input
                    value={directUsername}
                    onChange={(event) => setDirectUsername(event.target.value)}
                    placeholder="username"
                  />
                </>
              ) : (
                <>
                  <h3>New {tab}</h3>
                  <input
                    value={groupName}
                    onChange={(event) => setGroupName(event.target.value)}
                    placeholder="name"
                  />
                  <textarea
                    value={groupMembers}
                    onChange={(event) => setGroupMembers(event.target.value)}
                    placeholder="members (comma separated, max 4)"
                  />
                </>
              )}
              <button
                onClick={handleCreateConversation}
                disabled={
                  tab === "direct"
                    ? !directUsername
                    : !groupName || !groupMembers
                }
              >
                Create
              </button>
            </div>
          </aside>

          <main className="main card">
            {!selectedConversation && (
              <div className="empty">Select a conversation to start.</div>
            )}
            {selectedConversation && (
              <>
                <div className="thread-header">
                  <h2>{getConversationTitle(selectedConversation, sessionUsername)}</h2>
                  <span className="thread-type">
                    {selectedConversation.type}
                  </span>
                </div>

                <div className="messages">
                  {activeMessages.length === 0 && (
                    <p className="muted">No messages yet.</p>
                  )}
                  {activeMessages.map((msg) => (
                    <div key={msg.id} className="message">
                      <div className="meta">
                        <span>{msg.sender}</span>
                        <span>{new Date(msg.createdAt).toLocaleTimeString()}</span>
                      </div>
                      {msg.payload.text && (
                        <div className="text">{msg.payload.text}</div>
                      )}
                      {msg.payload.attachments.map((attachment, index) => (
                        <div key={`${msg.id}-${index}`} className="attachment">
                          {attachment.kind === "image" && (
                            <img src={attachment.data} alt={attachment.name} />
                          )}
                          {attachment.kind === "audio" && (
                            <audio controls src={attachment.data} />
                          )}
                          <div className="file-name">{attachment.name}</div>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>

                <div className="composer">
                  <textarea
                    value={messageText}
                    onChange={(event) => setMessageText(event.target.value)}
                    placeholder="Type your message"
                  />
                  <div className="composer-actions">
                    <label className="file-input">
                      Add image/audio
                      <input
                        type="file"
                        multiple
                        accept="image/*,audio/*"
                        onChange={handleAttachmentChange}
                      />
                    </label>
                    <button
                      onClick={handleSend}
                      disabled={
                        (!messageText && attachments.length === 0) ||
                        !selectedConversationId
                      }
                    >
                      Send
                    </button>
                  </div>
                  {attachments.length > 0 && (
                    <div className="attachments-preview">
                      {attachments.map((file, index) => (
                        <span key={`${file.name}-${index}`}>{file.name}</span>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </main>
        </div>
      )}

      {status && <div className="status">{status}</div>}

      {isLoggedIn && (
        <section className="card small">
          <h3>Keys</h3>
          <p>Public key stored on server: {publicKey ? "yes" : "no"}</p>
          <p>Private key stored locally: {privateKey ? "yes" : "no"}</p>
        </section>
      )}
    </div>
  );
}
