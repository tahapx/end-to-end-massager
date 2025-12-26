
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent
} from "react";
import {
  adminDeleteConversation,
  adminDeleteUser,
  adminListConversations,
  adminListUsers,
  adminLogin,
  adminResetUserPassword,
  adminUpdatePassword,
  adminUpdateUserFlags,
  createConversation,
  deleteMessage,
  fetchMembers,
  fetchProfile,
  fetchPublicProfile,
  fetchTyping,
  listConversations,
  login,
  markRead,
  pollMessages,
  pollSentStatuses,
  sendMessage,
  setAdminToken,
  setAuthToken,
  setTyping,
  signup,
  updateProfile
} from "./api";
import {
  decryptMessage,
  deriveSharedKey,
  encryptMessage,
  generateKeyPair,
  importPrivateKey,
  importPublicKey
} from "./crypto";

const STORAGE_KEYS = {
  username: "messager.username",
  publicKey: "messager.publicKey",
  privateKey: "messager.privateKey",
  token: "messager.token",
  pinnedPrefix: "messager.pinned.",
  starredPrefix: "messager.starred.",
  settingsPrefix: "messager.settings."
};

const MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024;

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

type UserFlags = {
  banned: boolean;
  canSend: boolean;
  canCreate: boolean;
  allowDirect: boolean;
  allowGroupInvite: boolean;
};

type AdminUser = {
  id: number;
  username: string;
  createdAt: number;
  banned: boolean;
  canSend: boolean;
  canCreate: boolean;
  allowDirect: boolean;
  allowGroupInvite: boolean;
  avatar: string | null;
  bio: string | null;
  profilePublic: boolean;
  profile: {
    last_ip: string;
    last_user_agent: string;
    last_platform: string;
    last_language: string;
    last_device_model: string;
    last_seen_at: number;
  } | null;
};

type AdminConversation = {
  id: number;
  type: string;
  name: string | null;
  ownerId: number;
  createdAt: number;
  members: string[];
};

type ProfileState = {
  avatar: string | null;
  bio: string;
  profilePublic: boolean;
  allowDirect: boolean;
  allowGroupInvite: boolean;
};

type PublicProfile = {
  avatar: string | null;
  bio: string | null;
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

function getDeviceInfo() {
  const anyNavigator = navigator as typeof navigator & {
    userAgentData?: { platform?: string; model?: string };
  };

  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    deviceModel: anyNavigator.userAgentData?.model || ""
  };
}

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit"
  });
}

function getInitials(username: string): string {
  return username.slice(0, 2).toUpperCase();
}

export default function App() {
  const [adminRoute, setAdminRoute] = useState(
    window.location.hash === "#admin"
  );
  const [showSettings, setShowSettings] = useState(false);

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
  const [userFlags, setUserFlags] = useState<UserFlags>({
    banned: false,
    canSend: true,
    canCreate: true,
    allowDirect: true,
    allowGroupInvite: true
  });
  const [profileState, setProfileState] = useState<ProfileState>({
    avatar: null,
    bio: "",
    profilePublic: true,
    allowDirect: true,
    allowGroupInvite: true
  });
  const [profileSaving, setProfileSaving] = useState(false);
  const [publicProfiles, setPublicProfiles] = useState<
    Record<string, PublicProfile>
  >({});

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

  const [adminUsername, setAdminUsername] = useState("");
  const [adminPassword, setAdminPassword] = useState("");
  const [adminTokenState, setAdminTokenState] = useState<string | null>(null);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [adminConversations, setAdminConversations] = useState<
    AdminConversation[]
  >([]);
  const [newAdminPassword, setNewAdminPassword] = useState("");

  const lastPollRef = useRef(0);
  const lastStatusPollRef = useRef(0);
  const selectedConversationRef = useRef<number | null>(null);
  const typingTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    const onHashChange = () => {
      setAdminRoute(window.location.hash === "#admin");
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    setAuthToken(token || null);
  }, [token]);

  useEffect(() => {
    setAdminToken(adminTokenState || null);
  }, [adminTokenState]);

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
  const isAdmin = Boolean(adminTokenState);

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

  const refreshAdminData = async () => {
    try {
      const [usersData, conversationsData] = await Promise.all([
        adminListUsers(),
        adminListConversations()
      ]);
      setAdminUsers(usersData.users || []);
      setAdminConversations(conversationsData.conversations || []);
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
    if (!isAdmin) {
      return;
    }
    refreshAdminData();
  }, [isAdmin]);
  useEffect(() => {
    if (!isLoggedIn) {
      return;
    }
    fetchProfile()
      .then((data) => {
        setProfileState({
          avatar: data.avatar ?? null,
          bio: data.bio || "",
          profilePublic: Boolean(data.profilePublic),
          allowDirect: Boolean(data.allowDirect),
          allowGroupInvite: Boolean(data.allowGroupInvite)
        });
      })
      .catch(() => undefined);
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
  useEffect(() => {
    if (!conversations.length) {
      return;
    }
    const directUsers = conversations
      .filter((conv) => conv.type === "direct")
      .map((conv) => getConversationTitle(conv, sessionUsername))
      .filter((name) => name && name !== "Direct" && name !== sessionUsername);

    directUsers.forEach((name) => {
      if (publicProfiles[name]) {
        return;
      }
      fetchPublicProfile(name)
        .then((data) => {
          setPublicProfiles((prev) => ({
            ...prev,
            [name]: {
              avatar: data.avatar ?? null,
              bio: data.bio ?? null
            }
          }));
        })
        .catch(() => undefined);
    });
  }, [conversations, sessionUsername, publicProfiles]);

  const handleSignup = async () => {
    setStatus(null);
    try {
      const keys = await generateKeyPair();
      const data = await signup(username, password, keys.publicKey, getDeviceInfo());

      setSessionUsername(data.username);
      setToken(data.token);
      setPublicKey(keys.publicKey);
      setPrivateKey(keys.privateKey);
      setUserFlags({
        banned: data.banned,
        canSend: data.canSend,
        canCreate: data.canCreate,
        allowDirect: data.allowDirect,
        allowGroupInvite: data.allowGroupInvite
      });
      setProfileState({
        avatar: data.avatar ?? null,
        bio: data.bio || "",
        profilePublic: Boolean(data.profilePublic),
        allowDirect: Boolean(data.allowDirect),
        allowGroupInvite: Boolean(data.allowGroupInvite)
      });

      localStorage.setItem(STORAGE_KEYS.username, data.username);
      localStorage.setItem(STORAGE_KEYS.token, data.token);
      localStorage.setItem(STORAGE_KEYS.publicKey, keys.publicKey);
      localStorage.setItem(STORAGE_KEYS.privateKey, keys.privateKey);

      setStatus("Signup complete");
      setShowSettings(false);
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

      const data = await login(username, password, getDeviceInfo());
      setSessionUsername(data.username);
      setToken(data.token);
      setUserFlags({
        banned: data.banned,
        canSend: data.canSend,
        canCreate: data.canCreate,
        allowDirect: data.allowDirect,
        allowGroupInvite: data.allowGroupInvite
      });
      setProfileState({
        avatar: data.avatar ?? null,
        bio: data.bio || "",
        profilePublic: Boolean(data.profilePublic),
        allowDirect: Boolean(data.allowDirect),
        allowGroupInvite: Boolean(data.allowGroupInvite)
      });
      localStorage.setItem(STORAGE_KEYS.username, data.username);
      localStorage.setItem(STORAGE_KEYS.token, data.token);

      setStatus("Login complete");
      setShowSettings(false);
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleAdminLogin = async () => {
    setStatus(null);
    try {
      const data = await adminLogin(adminUsername, adminPassword);
      setAdminTokenState(data.token);
      setAdminToken(data.token);
      setAdminUsername(data.username);
      setAdminPassword("");
      setStatus("Admin login complete");
      await refreshAdminData();
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleAdminLogout = () => {
    setAdminTokenState(null);
    setAdminToken(null);
    setAdminUsers([]);
    setAdminConversations([]);
    setStatus("Admin logged out");
  };

  const handleAdminPasswordChange = async () => {
    setStatus(null);
    try {
      await adminUpdatePassword(newAdminPassword);
      setNewAdminPassword("");
      setStatus("Admin password updated");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleAdminToggle = async (
    user: AdminUser,
    key: "banned" | "canSend" | "canCreate" | "allowDirect" | "allowGroupInvite"
  ) => {
    setStatus(null);
    try {
      const payload = {
        banned: key === "banned" ? !user.banned : user.banned,
        canSend: key === "canSend" ? !user.canSend : user.canSend,
        canCreate: key === "canCreate" ? !user.canCreate : user.canCreate,
        allowDirect:
          key === "allowDirect" ? !user.allowDirect : user.allowDirect,
        allowGroupInvite:
          key === "allowGroupInvite" ? !user.allowGroupInvite : user.allowGroupInvite
      };
      await adminUpdateUserFlags(user.id, payload);
      await refreshAdminData();
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleAdminResetPassword = async (userId: number) => {
    const nextPassword = window.prompt("New password for user:");
    if (!nextPassword) {
      return;
    }
    setStatus(null);
    try {
      await adminResetUserPassword(userId, nextPassword);
      setStatus("Password updated");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleAdminDeleteUser = async (userId: number) => {
    if (!window.confirm("Delete this user and all data?")) {
      return;
    }
    setStatus(null);
    try {
      await adminDeleteUser(userId);
      await refreshAdminData();
      setStatus("User deleted");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleAdminDeleteConversation = async (conversationId: number) => {
    if (!window.confirm("Delete this conversation?")) {
      return;
    }
    setStatus(null);
    try {
      await adminDeleteConversation(conversationId);
      await refreshAdminData();
      setStatus("Conversation deleted");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleProfileSave = async () => {
    setProfileSaving(true);
    setStatus(null);
    try {
      await updateProfile({
        avatar: profileState.avatar,
        bio: profileState.bio,
        profilePublic: profileState.profilePublic,
        allowDirect: profileState.allowDirect,
        allowGroupInvite: profileState.allowGroupInvite
      });
      setUserFlags((prev) => ({
        ...prev,
        allowDirect: profileState.allowDirect,
        allowGroupInvite: profileState.allowGroupInvite
      }));
      setStatus("Profile updated");
    } catch (error) {
      setStatus((error as Error).message);
    } finally {
      setProfileSaving(false);
    }
  };

  const handleAvatarChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setStatus("Avatar too large (max 2MB).");
      return;
    }
    const data = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = () => reject(new Error("Failed to read file"));
      reader.readAsDataURL(file);
    });
    setProfileState((prev) => ({ ...prev, avatar: data }));
    event.target.value = "";
  };

  const handleClearAvatar = () => {
    setProfileState((prev) => ({ ...prev, avatar: null }));
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
        setStatus(`File ${file.name} is too large (max 10MB).`);
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
          <p>Encrypted chat, WhatsApp-style.</p>
        </div>
        {isLoggedIn && !adminRoute && (
          <button className="ghost" onClick={() => setShowSettings((v) => !v)}>
            {showSettings ? "Back to chats" : "Settings"}
          </button>
        )}
      </header>

      {adminRoute && !isAdmin && (
        <section className="card auth-card">
          <h2>Admin Access</h2>
          <label>
            Username
            <input
              value={adminUsername}
              onChange={(event) => setAdminUsername(event.target.value)}
              placeholder="admin username"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={adminPassword}
              onChange={(event) => setAdminPassword(event.target.value)}
              placeholder="admin password"
            />
          </label>
          <div className="row">
            <button onClick={handleAdminLogin} disabled={!adminUsername || !adminPassword}>
              Admin login
            </button>
          </div>
          <p className="note">Default admin: myadmin / 000123</p>
        </section>
      )}

      {adminRoute && isAdmin && (
        <section className="admin-panel card">
          <div className="admin-header">
            <div>
              <h2>Admin Panel</h2>
              <p className="muted">Moderation, users, and conversations.</p>
            </div>
            <div className="row">
              <input
                value={newAdminPassword}
                onChange={(event) => setNewAdminPassword(event.target.value)}
                placeholder="new admin password"
                type="password"
              />
              <button
                onClick={handleAdminPasswordChange}
                disabled={!newAdminPassword}
              >
                Change password
              </button>
              <button className="secondary" onClick={refreshAdminData}>
                Refresh
              </button>
              <button className="secondary" onClick={handleAdminLogout}>
                Log out
              </button>
            </div>
          </div>

          <div className="admin-grid">
            <div className="admin-block">
              <h3>Users</h3>
              <div className="admin-list">
                {adminUsers.map((user) => (
                  <div key={user.id} className="admin-item">
                    <div className="admin-main">
                      <div>
                        <strong>{user.username}</strong>
                        <span className="muted">
                          ID {user.id} | {new Date(user.createdAt).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="admin-tags">
                        <span className={user.banned ? "tag danger" : "tag"}>
                          {user.banned ? "Banned" : "Active"}
                        </span>
                        <span className={user.canSend ? "tag" : "tag warn"}>
                          Send {user.canSend ? "On" : "Off"}
                        </span>
                        <span className={user.canCreate ? "tag" : "tag warn"}>
                          Create {user.canCreate ? "On" : "Off"}
                        </span>
                        <span className={user.allowDirect ? "tag" : "tag warn"}>
                          Direct {user.allowDirect ? "On" : "Off"}
                        </span>
                        <span className={user.allowGroupInvite ? "tag" : "tag warn"}>
                          Invites {user.allowGroupInvite ? "On" : "Off"}
                        </span>
                      </div>
                    </div>
                    {user.profile && (
                      <div className="admin-meta">
                        <span>IP: {user.profile.last_ip}</span>
                        <span>Device: {user.profile.last_device_model || "unknown"}</span>
                        <span>Platform: {user.profile.last_platform || "unknown"}</span>
                        <span>Seen: {new Date(user.profile.last_seen_at).toLocaleString()}</span>
                      </div>
                    )}
                    <div className="admin-actions">
                      <button onClick={() => handleAdminToggle(user, "banned")}>
                        {user.banned ? "Unban" : "Ban"}
                      </button>
                      <button onClick={() => handleAdminToggle(user, "canSend")}>
                        {user.canSend ? "Disable Send" : "Enable Send"}
                      </button>
                      <button onClick={() => handleAdminToggle(user, "canCreate")}>
                        {user.canCreate ? "Disable Create" : "Enable Create"}
                      </button>
                      <button onClick={() => handleAdminToggle(user, "allowDirect")}>
                        {user.allowDirect ? "Disable Direct" : "Enable Direct"}
                      </button>
                      <button onClick={() => handleAdminToggle(user, "allowGroupInvite")}>
                        {user.allowGroupInvite ? "Disable Invites" : "Enable Invites"}
                      </button>
                      <button
                        className="secondary"
                        onClick={() => handleAdminResetPassword(user.id)}
                      >
                        Reset Password
                      </button>
                      <button
                        className="danger"
                        onClick={() => handleAdminDeleteUser(user.id)}
                      >
                        Delete User
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="admin-block">
              <h3>Conversations</h3>
              <div className="admin-list">
                {adminConversations.map((conv) => (
                  <div key={conv.id} className="admin-item">
                    <div className="admin-main">
                      <div>
                        <strong>{conv.name || "Untitled"}</strong>
                        <span className="muted">
                          {conv.type} | ID {conv.id} | Members {conv.members.length}
                        </span>
                      </div>
                      <button
                        className="danger"
                        onClick={() => handleAdminDeleteConversation(conv.id)}
                      >
                        Delete
                      </button>
                    </div>
                    <div className="admin-meta">
                      <span>Members: {conv.members.join(", ")}</span>
                      <span>Created: {new Date(conv.createdAt).toLocaleString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>
      )}

      {!adminRoute && !isLoggedIn && (
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

      {!adminRoute && isLoggedIn && (
        <div className="layout">
          <aside className="sidebar card">
            <div className="profile-card">
              <div className="avatar">
                {profileState.avatar ? (
                  <img src={profileState.avatar} alt="avatar" />
                ) : (
                  <span>{getInitials(sessionUsername)}</span>
                )}
              </div>
              <div>
                <div className="profile-name">{sessionUsername}</div>
                <div className="muted">{profileState.bio || "No bio yet"}</div>
              </div>
            </div>

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
              placeholder="Search chats"
            />

            <div className="conversation-list">
              {sortedConversations.length === 0 && (
                <p className="muted">No conversations yet.</p>
              )}
              {sortedConversations.map((conv) => {
                const title = getConversationTitle(conv, sessionUsername);
                const profile = publicProfiles[title];
                return (
                  <button
                    key={conv.id}
                    className={
                      conv.id === selectedConversationId
                        ? "conversation active"
                        : "conversation"
                    }
                    onClick={() => setSelectedConversationId(conv.id)}
                  >
                    <div className="conversation-left">
                      <div className="avatar small">
                        {profile?.avatar ? (
                          <img src={profile.avatar} alt={title} />
                        ) : (
                          <span>{getInitials(title)}</span>
                        )}
                      </div>
                      <div>
                        <div className="title">{title}</div>
                        <div className="meta">
                          {lastMessageByConversation[conv.id]
                            ? `${lastMessageByConversation[conv.id].sender}: ${getPreview(
                                lastMessageByConversation[conv.id].payload
                              )}`
                            : conv.members.map((member) => member.username).join(", ")}
                        </div>
                      </div>
                    </div>
                    <div className="conversation-right">
                      <span className="time">
                        {lastMessageByConversation[conv.id]
                          ? formatTime(
                              lastMessageByConversation[conv.id].createdAt
                            )
                          : ""}
                      </span>
                      {unreadByConversation[conv.id] ? (
                        <span className="badge">{unreadByConversation[conv.id]}</span>
                      ) : null}
                    </div>
                  </button>
                );
              })}
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

            <button className="secondary" onClick={handleLogout}>
              Log out
            </button>
          </aside>

          <main className="main card">
            {showSettings && (
              <div className="settings">
                <h2>Profile & Settings</h2>
                <div className="settings-grid">
                  <div className="avatar-panel">
                    <div className="avatar large">
                      {profileState.avatar ? (
                        <img src={profileState.avatar} alt="avatar" />
                      ) : (
                        <span>{getInitials(sessionUsername)}</span>
                      )}
                    </div>
                    <div className="row">
                      <label className="file-input">
                        Upload
                        <input type="file" accept="image/*" onChange={handleAvatarChange} />
                      </label>
                      <button className="secondary" onClick={handleClearAvatar}>
                        Remove
                      </button>
                    </div>
                  </div>
                  <div className="settings-form">
                    <label>
                      Bio
                      <textarea
                        value={profileState.bio}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            bio: event.target.value
                          }))
                        }
                        placeholder="Tell people about you"
                      />
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={profileState.profilePublic}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            profilePublic: event.target.checked
                          }))
                        }
                      />
                      <span>Profile is public</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={profileState.allowDirect}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            allowDirect: event.target.checked
                          }))
                        }
                      />
                      <span>Allow direct messages</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={profileState.allowGroupInvite}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            allowGroupInvite: event.target.checked
                          }))
                        }
                      />
                      <span>Allow group invites</span>
                    </label>
                    <button onClick={handleProfileSave} disabled={profileSaving}>
                      {profileSaving ? "Saving..." : "Save settings"}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {!showSettings && !selectedConversation && (
              <div className="empty">Select a conversation to start.</div>
            )}
            {!showSettings && selectedConversation && (
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
                    <div
                      key={msg.id}
                      className={
                        msg.sender === sessionUsername
                          ? "message own"
                          : "message"
                      }
                    >
                      <div className="meta">
                        <span>{msg.sender}</span>
                        <span className="meta-right">
                          <span>{formatTime(msg.createdAt)}</span>
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
                    placeholder="Type a message"
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

      {lightboxSrc && (
        <div className="lightbox" onClick={() => setLightboxSrc(null)}>
          <img src={lightboxSrc} alt="Preview" />
        </div>
      )}
    </div>
  );
}
