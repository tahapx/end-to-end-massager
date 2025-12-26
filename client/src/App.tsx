
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent
} from "react";
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
  fetchTyping,
  listConversations,
  login,
  markRead,
  pollMessages,
  pollSentStatuses,
  sendMessage,
  setAuthToken,
  setTyping,
  signup,
  deleteMessage
} from "./api";

const STORAGE_KEYS = {
  username: "messager.username",
  publicKey: "messager.publicKey",
  privateKey: "messager.privateKey",
  token: "messager.token",
  pinnedPrefix: "messager.pinned.",
  starredPrefix: "messager.starred."
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
  groupId: string;
  conversationId: number;
  sender: string;
  payload: MessagePayload;
  createdAt: number;
  deletedAt: number | null;
};

type Conversation = {
  id: number;
  type: "direct" | "group" | "channel";
  name: string | null;
  ownerId: number;
  members: Array<{ username: string; publicKey: string }>;
};

type StatusRow = {
  deliveredAt: number | null;
  readAt: number | null;
  deletedAt: number | null;
};

const tabs: Array<Conversation["type"]> = ["group", "channel", "direct"];

function getConversationTitle(conversation: Conversation, self: string): string {
  if (conversation.type === "direct") {
    const other = conversation.members.find((m) => m.username !== self);
    return other ? other.username : "Direct";
  }
  return conversation.name || "Untitled";
}

function getPreview(payload: MessagePayload): string {
  const trimmed = payload.text.trim();
  if (trimmed) {
    return trimmed.length > 40 ? `${trimmed.slice(0, 40)}...` : trimmed;
  }
  if (payload.attachments.length === 0) {
    return "";
  }
  const first = payload.attachments[0].kind;
  const label = first === "image" ? "Image" : "Audio";
  if (payload.attachments.length === 1) {
    return `[${label}]`;
  }
  return `[${label} +${payload.attachments.length - 1}]`;
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

function matchesQuery(value: string, query: string): boolean {
  return value.toLowerCase().includes(query.toLowerCase());
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
  const [conversationQuery, setConversationQuery] = useState("");
  const [messageQuery, setMessageQuery] = useState("");
  const [typingUsers, setTypingUsers] = useState<string[]>([]);
  const [lightboxSrc, setLightboxSrc] = useState<string | null>(null);
  const [audioDurations, setAudioDurations] = useState<Record<string, number>>(
    {}
  );
  const [pinnedIds, setPinnedIds] = useState<Set<string>>(new Set());
  const [starredIds, setStarredIds] = useState<Set<string>>(new Set());
  const [unreadByConversation, setUnreadByConversation] = useState<
    Record<number, number>
  >({});
  const [lastMessageByConversation, setLastMessageByConversation] = useState<
    Record<number, { sender: string; payload: MessagePayload; createdAt: number }>
  >({});
  const [statusByGroupId, setStatusByGroupId] = useState<
    Record<string, StatusRow>
  >({});

  const lastPollRef = useRef(0);
  const lastStatusPollRef = useRef(0);
  const selectedConversationRef = useRef<number | null>(null);
  const typingTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    setAuthToken(token || null);
  }, [token]);

  useEffect(() => {
    if (!sessionUsername) {
      return;
    }
    const pinnedRaw = localStorage.getItem(
      `${STORAGE_KEYS.pinnedPrefix}${sessionUsername}`
    );
    const starredRaw = localStorage.getItem(
      `${STORAGE_KEYS.starredPrefix}${sessionUsername}`
    );
    setPinnedIds(new Set(pinnedRaw ? JSON.parse(pinnedRaw) : []));
    setStarredIds(new Set(starredRaw ? JSON.parse(starredRaw) : []));
  }, [sessionUsername]);

  useEffect(() => {
    selectedConversationRef.current = selectedConversationId;
    if (selectedConversationId) {
      setUnreadByConversation((prev) => ({
        ...prev,
        [selectedConversationId]: 0
      }));
      markRead(selectedConversationId).catch(() => undefined);
    }
  }, [selectedConversationId]);

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
          if (msg.deleted_at) {
            decrypted.push({
              id: msg.id,
              groupId: msg.group_id,
              conversationId: msg.conversation_id,
              sender: msg.sender_username,
              payload: { text: "[Deleted]", attachments: [] },
              createdAt: msg.created_at,
              deletedAt: msg.deleted_at
            });
            continue;
          }

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
              groupId: msg.group_id,
              conversationId: msg.conversation_id,
              sender: msg.sender_username,
              payload: parsePayload(text),
              createdAt: msg.created_at,
              deletedAt: msg.deleted_at
            });
          } catch {
            decrypted.push({
              id: msg.id,
              groupId: msg.group_id,
              conversationId: msg.conversation_id,
              sender: msg.sender_username,
              payload: { text: "[Failed to decrypt]", attachments: [] },
              createdAt: msg.created_at,
              deletedAt: msg.deleted_at
            });
          }
        }

        setMessages((prev) => [...prev, ...decrypted]);
        setUnreadByConversation((prev) => {
          const next = { ...prev };
          for (const msg of decrypted) {
            if (msg.conversationId !== selectedConversationRef.current) {
              next[msg.conversationId] = (next[msg.conversationId] || 0) + 1;
            }
          }
          return next;
        });
        setLastMessageByConversation((prev) => {
          const next = { ...prev };
          for (const msg of decrypted) {
            next[msg.conversationId] = {
              sender: msg.sender,
              payload: msg.payload,
              createdAt: msg.createdAt
            };
          }
          return next;
        });
        if (
          selectedConversationRef.current &&
          decrypted.some(
            (msg) => msg.conversationId === selectedConversationRef.current
          )
        ) {
          markRead(selectedConversationRef.current).catch(() => undefined);
        }
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

  useEffect(() => {
    if (!token) {
      return undefined;
    }

    let isMounted = true;
    const poller = async () => {
      try {
        const data = await pollSentStatuses(lastStatusPollRef.current);
        if (!isMounted || !data.statuses?.length) {
          return;
        }

        setStatusByGroupId((prev) => {
          const next = { ...prev };
          for (const row of data.statuses) {
            next[row.group_id] = {
              deliveredAt: row.delivered_at ?? null,
              readAt: row.read_at ?? null,
              deletedAt: row.deleted_at ?? null
            };
          }
          return next;
        });

        lastStatusPollRef.current =
          data.statuses[data.statuses.length - 1].updated_at;
      } catch (error) {
        setStatus((error as Error).message);
      }
    };

    const interval = setInterval(poller, 4000);
    poller();

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [token]);

  useEffect(() => {
    if (!selectedConversationId || !token) {
      setTypingUsers([]);
      return undefined;
    }

    let isMounted = true;
    const poller = async () => {
      try {
        const data = await fetchTyping(selectedConversationId);
        if (!isMounted) {
          return;
        }
        setTypingUsers(data.users || []);
      } catch {
        // ignore
      }
    };

    const interval = setInterval(poller, 2000);
    poller();

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [selectedConversationId, token]);
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
        messageId: string;
        toUsername: string;
        ciphertext: string;
        nonce: string;
      }> = [];
      const messageId = crypto.randomUUID
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random()}`;

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
          messageId,
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
          groupId: messageId,
          conversationId: conversation.id,
          sender: sessionUsername,
          payload,
          createdAt: Date.now(),
          deletedAt: null
        }
      ]);
      setLastMessageByConversation((prev) => ({
        ...prev,
        [conversation.id]: {
          sender: sessionUsername,
          payload,
          createdAt: Date.now()
        }
      }));
      setStatusByGroupId((prev) => ({
        ...prev,
        [messageId]: {
          deliveredAt: null,
          readAt: null,
          deletedAt: null
        }
      }));
      setMessageText("");
      setAttachments([]);
      setTyping(conversation.id, false).catch(() => undefined);
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

  const handleTyping = () => {
    if (!selectedConversationId) {
      return;
    }
    setTyping(selectedConversationId, true).catch(() => undefined);
    if (typingTimeoutRef.current) {
      window.clearTimeout(typingTimeoutRef.current);
    }
    typingTimeoutRef.current = window.setTimeout(() => {
      setTyping(selectedConversationId, false).catch(() => undefined);
    }, 2000);
  };

  const handleTogglePinned = (messageId: string) => {
    setPinnedIds((prev) => {
      const next = new Set(prev);
      if (next.has(messageId)) {
        next.delete(messageId);
      } else {
        next.add(messageId);
      }
      localStorage.setItem(
        `${STORAGE_KEYS.pinnedPrefix}${sessionUsername}`,
        JSON.stringify(Array.from(next))
      );
      return next;
    });
  };

  const handleToggleStarred = (messageId: string) => {
    setStarredIds((prev) => {
      const next = new Set(prev);
      if (next.has(messageId)) {
        next.delete(messageId);
      } else {
        next.add(messageId);
      }
      localStorage.setItem(
        `${STORAGE_KEYS.starredPrefix}${sessionUsername}`,
        JSON.stringify(Array.from(next))
      );
      return next;
    });
  };

  const handleDelete = async (message: ChatMessage) => {
    try {
      if (message.sender === sessionUsername) {
        await deleteMessage({ scope: "all", groupId: message.groupId });
      } else if (typeof message.id === "number") {
        await deleteMessage({ scope: "self", messageId: message.id });
      }
      setMessages((prev) =>
        prev.map((item) =>
          item.id === message.id
            ? {
                ...item,
                payload: { text: "[Deleted]", attachments: [] },
                deletedAt: Date.now()
              }
            : item
        )
      );
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const filteredConversations = conversations.filter((conv) => {
    if (!conversationQuery) {
      return conv.type === tab;
    }
    if (conv.type !== tab) {
      return false;
    }
    const title = getConversationTitle(conv, sessionUsername);
    const members = conv.members.map((member) => member.username).join(", ");
    return (
      matchesQuery(title, conversationQuery) ||
      matchesQuery(members, conversationQuery)
    );
  });

  const sortedConversations = filteredConversations.sort((a, b) => {
    const aTime = lastMessageByConversation[a.id]?.createdAt ?? 0;
    const bTime = lastMessageByConversation[b.id]?.createdAt ?? 0;
    return bTime - aTime;
  });

  const selectedConversation = conversations.find(
    (item) => item.id === selectedConversationId
  );

  const activeMessages = messages.filter(
    (msg) => msg.conversationId === selectedConversationId
  );

  const searchedMessages = messageQuery
    ? activeMessages.filter((msg) => {
        const textMatch = matchesQuery(msg.payload.text || "", messageQuery);
        const attachmentMatch = msg.payload.attachments.some((attachment) =>
          matchesQuery(attachment.name, messageQuery)
        );
        return textMatch || attachmentMatch;
      })
    : activeMessages;

  const pinnedMessages = activeMessages.filter((msg) =>
    pinnedIds.has(String(msg.id))
  );

  const getStatusMark = (groupId: string) => {
    const statusRow = statusByGroupId[groupId];
    if (!statusRow) {
      return "";
    }
    if (statusRow.readAt) {
      return "RR";
    }
    if (statusRow.deliveredAt) {
      return "D";
    }
    return ".";
  };

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

            <input
              className="search"
              value={conversationQuery}
              onChange={(event) => setConversationQuery(event.target.value)}
              placeholder="Search conversations"
            />

            <div className="conversation-list">
              {sortedConversations.length === 0 && (
                <p className="muted">No conversations yet.</p>
              )}
              {sortedConversations.map((conv) => (
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
                    <span className="time">
                      {lastMessageByConversation[conv.id]
                        ? new Date(
                            lastMessageByConversation[conv.id].createdAt
                          ).toLocaleTimeString()
                        : ""}
                    </span>
                  </div>
                  <div className="meta">
                    <span className="preview">
                      {lastMessageByConversation[conv.id]
                        ? `${lastMessageByConversation[conv.id].sender}: ${getPreview(
                            lastMessageByConversation[conv.id].payload
                          )}`
                        : conv.members.map((member) => member.username).join(", ")}
                    </span>
                    {unreadByConversation[conv.id] ? (
                      <span className="badge">{unreadByConversation[conv.id]}</span>
                    ) : null}
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
                  <div>
                    <h2>
                      {getConversationTitle(selectedConversation, sessionUsername)}
                    </h2>
                    {typingUsers.length > 0 && (
                      <p className="typing">
                        {typingUsers.join(", ")} typing...
                      </p>
                    )}
                  </div>
                  <span className="thread-type">
                    {selectedConversation.type}
                  </span>
                </div>

                <input
                  className="search"
                  value={messageQuery}
                  onChange={(event) => setMessageQuery(event.target.value)}
                  placeholder="Search in messages"
                />

                {pinnedMessages.length > 0 && (
                  <div className="pinned">
                    <h4>Pinned</h4>
                    {pinnedMessages.map((msg) => (
                      <div key={`pin-${msg.id}`} className="pinned-item">
                        <span>{msg.sender}:</span>
                        <span>{getPreview(msg.payload)}</span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="messages">
                  {searchedMessages.length === 0 && (
                    <p className="muted">No messages yet.</p>
                  )}
                  {searchedMessages.map((msg) => (
                    <div key={msg.id} className="message">
                      <div className="meta">
                        <span>{msg.sender}</span>
                        <span className="meta-right">
                          <span>{new Date(msg.createdAt).toLocaleTimeString()}</span>
                          {msg.sender === sessionUsername && (
                            <span className="tick">{getStatusMark(msg.groupId)}</span>
                          )}
                        </span>
                      </div>
                      {msg.payload.text && (
                        <div className="text">{msg.payload.text}</div>
                      )}
                      {msg.payload.attachments.map((attachment, index) => (
                        <div key={`${msg.id}-${index}`} className="attachment">
                          {attachment.kind === "image" && (
                            <img
                              src={attachment.data}
                              alt={attachment.name}
                              onClick={() => setLightboxSrc(attachment.data)}
                            />
                          )}
                          {attachment.kind === "audio" && (
                            <audio
                              controls
                              src={attachment.data}
                              onLoadedMetadata={(event) => {
                                const key = `${msg.id}-${index}`;
                                setAudioDurations((prev) => ({
                                  ...prev,
                                  [key]: event.currentTarget.duration
                                }));
                              }}
                            />
                          )}
                          {attachment.kind === "audio" &&
                            audioDurations[`${msg.id}-${index}`] && (
                              <div className="file-name">
                                {attachment.name} - {audioDurations[
                                  `${msg.id}-${index}`
                                ].toFixed(1)}s
                              </div>
                            )}
                          {attachment.kind === "image" && (
                            <div className="file-name">{attachment.name}</div>
                          )}
                        </div>
                      ))}
                      <div className="message-actions">
                        <button
                          className={
                            pinnedIds.has(String(msg.id))
                              ? "action active"
                              : "action"
                          }
                          onClick={() => handleTogglePinned(String(msg.id))}
                        >
                          Pin
                        </button>
                        <button
                          className={
                            starredIds.has(String(msg.id))
                              ? "action active"
                              : "action"
                          }
                          onClick={() => handleToggleStarred(String(msg.id))}
                        >
                          Star
                        </button>
                        <button
                          className="action danger"
                          onClick={() => handleDelete(msg)}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="composer">
                  <textarea
                    value={messageText}
                    onChange={(event) => {
                      setMessageText(event.target.value);
                      handleTyping();
                    }}
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

      {lightboxSrc && (
        <div className="lightbox" onClick={() => setLightboxSrc(null)}>
          <img src={lightboxSrc} alt="Preview" />
        </div>
      )}
    </div>
  );
}
