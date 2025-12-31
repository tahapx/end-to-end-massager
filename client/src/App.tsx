
import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent
} from "react";
import {
  adminDownloadUserMetadata,
  adminDeleteConversation,
  adminDeleteUser,
  adminListConversations,
  adminListUsers,
  adminLogin,
  adminResetUserPassword,
  adminUpdatePassword,
  adminUpdateUserFlags,
  addConversationMember,
  answerCall,
  createConversation,
  createInviteLink,
  deleteMessage,
  disableTwoFactor,
  endCall,
  enableTwoFactor,
  fetchKeyBundle,
  fetchMembers,
  fetchProfile,
  fetchPublicProfile,
  fetchRoster,
  fetchUserStatus,
  fetchTyping,
  listConversations,
  listDevices,
  listInviteLinks,
  login,
  logoutAllDevices,
  logoutDevice,
  markRead,
  pollCalls,
  publishKeyBundle,
  pollMessages,
  pollSentStatuses,
  redeemInviteLink,
  removeConversationMember,
  revokeInviteLink,
  sendIceCandidate,
  sendMessage,
  setAdminToken,
  setAuthToken,
  setTyping,
  signup,
  startCall,
  updateConversationRole,
  updateContactPrivacy,
  updateProfile
} from "./api";
import {
  decryptSignalMessage,
  encryptSignalMessage,
  ensureLocalKeys,
  ensureSession,
  isSignalSupported,
  exportSignalState,
  importSignalState,
  resetSignalState
} from "./signal";

const STORAGE_KEYS = {
  username: "messager.username",
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
  encrypted?: {
    ciphertext: string;
    nonce: string;
    senderDeviceId: number;
  };
};

type Conversation = {
  id: number;
  type: "direct" | "group" | "channel";
  name: string | null;
  ownerId: number;
  visibility: "public" | "private";
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

type PrivacySettings = {
  hide_online: boolean;
  hide_last_seen: boolean;
  hide_profile_photo: boolean;
  disable_read_receipts: boolean;
  disable_typing_indicator: boolean;
};

type AdminUser = {
  id: number;
  username: string;
  phone: string;
  firstName: string;
  lastName: string;
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
  visibility?: "public" | "private";
};

type ProfileState = {
  avatar: string | null;
  bio: string;
  profilePublic: boolean;
  allowDirect: boolean;
  allowGroupInvite: boolean;
  privacy: PrivacySettings;
};

type PublicProfile = {
  avatar: string | null;
  bio: string | null;
};

type DeviceInfo = {
  deviceId: string;
  deviceName: string;
  ip: string;
  lastSeenAt: number;
  createdAt: number;
  current: boolean;
};

type RosterMember = {
  id: number;
  username: string;
  role: "owner" | "admin" | "member";
  permissions: { manage_members?: boolean; manage_invites?: boolean } | null;
};

type InviteLink = {
  token: string;
  maxUses: number;
  uses: number;
  expiresAt: number | null;
  revoked: boolean;
  createdAt: number;
};

type CallEvent = {
  id: number;
  callId: string;
  type: "offer" | "answer" | "ice" | "end";
  payload: {
    fromUsername?: string;
    fromDeviceId?: string;
    media?: "audio" | "video";
    offer?: string;
    answer?: string;
    candidate?: string;
    conversationId?: number;
  };
};

type CallState = {
  status: "idle" | "outgoing" | "incoming" | "active";
  callId: string | null;
  peerUsername: string | null;
  media: "audio" | "video";
  conversationId: number | null;
};

type TabFilter = "all" | Conversation["type"];

const tabs: TabFilter[] = ["all", "group", "channel", "direct"];

const defaultPrivacy: PrivacySettings = {
  hide_online: false,
  hide_last_seen: false,
  hide_profile_photo: false,
  disable_read_receipts: false,
  disable_typing_indicator: false
};

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

type SignalEnvelope =
  | { kind: "chat"; payload: MessagePayload }
  | {
      kind: "sender-key";
      senderKey: string;
    };

function parseSignalEnvelope(text: string): SignalEnvelope | null {
  try {
    const parsed = JSON.parse(text) as SignalEnvelope;
    if (parsed?.kind === "chat" && parsed.payload) {
      return parsed;
    }
    if (
      parsed?.kind === "sender-key" &&
      typeof parsed.senderKey === "string"
    ) {
      return parsed;
    }
  } catch {
    return null;
  }
  return null;
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

function getDeviceId(): string {
  const key = "messager.deviceId";
  const existing = localStorage.getItem(key);
  if (existing) {
    return existing;
  }
  const generated = crypto.randomUUID
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random()}`;
  localStorage.setItem(key, generated);
  return generated;
}

function getDeviceName(): string {
  const anyNavigator = navigator as typeof navigator & {
    userAgentData?: { platform?: string; model?: string };
  };
  const platform = anyNavigator.userAgentData?.platform || navigator.platform;
  const model = anyNavigator.userAgentData?.model || "";
  return `${platform}${model ? ` ${model}` : ""}`.trim() || "Browser";
}

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit"
  });
}

function formatDateLabel(timestamp: number): string {
  return new Date(timestamp).toLocaleDateString([], {
    weekday: "short",
    month: "short",
    day: "numeric"
  });
}

function formatLastSeen(value: number | null): string {
  if (!value) {
    return "Last seen recently";
  }
  return `Last seen ${new Date(value).toLocaleString()}`;
}

function formatDuration(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${seconds.toString().padStart(2, "0")}`;
}

function getInitials(username: string): string {
  return username.slice(0, 2).toUpperCase();
}

export default function App() {
  const [adminRoute, setAdminRoute] = useState(
    window.location.hash === "#admin"
  );
  const [showSettings, setShowSettings] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [theme, setTheme] = useState(
    localStorage.getItem("messager.theme") || "dark"
  );

  const [phone, setPhone] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [enable2fa, setEnable2fa] = useState(false);
  const [sessionUsername, setSessionUsername] = useState(
    localStorage.getItem(STORAGE_KEYS.username) || ""
  );
  const [token, setToken] = useState(
    localStorage.getItem(STORAGE_KEYS.token) || ""
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
    allowGroupInvite: true,
    privacy: { ...defaultPrivacy }
  });
  const [profileSaving, setProfileSaving] = useState(false);
  const [publicProfiles, setPublicProfiles] = useState<
    Record<string, PublicProfile>
  >({});
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(false);

  const [tab, setTab] = useState<TabFilter>("all");
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
  const [groupVisibility, setGroupVisibility] = useState<"public" | "private">(
    "public"
  );
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
  const [statusByUser, setStatusByUser] = useState<
    Record<string, { online: boolean; lastSeen: number | null }>
  >({});
  const [showContactPrivacy, setShowContactPrivacy] = useState(false);
  const [contactPrivacy, setContactPrivacy] = useState<PrivacySettings>({
    ...defaultPrivacy
  });
  const [showManagePanel, setShowManagePanel] = useState(false);
  const [roster, setRoster] = useState<RosterMember[]>([]);
  const [inviteLinks, setInviteLinks] = useState<InviteLink[]>([]);
  const [manageUsername, setManageUsername] = useState("");
  const [inviteMaxUses, setInviteMaxUses] = useState(1);
  const [inviteExpiresMinutes, setInviteExpiresMinutes] = useState(60);
  const [inviteToken, setInviteToken] = useState("");
  const [pendingInviteToken, setPendingInviteToken] = useState<string | null>(null);

  const [adminUsername, setAdminUsername] = useState("");
  const [adminPassword, setAdminPassword] = useState("");
  const [adminTokenState, setAdminTokenState] = useState<string | null>(null);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [adminConversations, setAdminConversations] = useState<
    AdminConversation[]
  >([]);
  const [newAdminPassword, setNewAdminPassword] = useState("");
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [twoFactorPassword, setTwoFactorPassword] = useState("");
  const [callState, setCallState] = useState<CallState>({
    status: "idle",
    callId: null,
    peerUsername: null,
    media: "audio",
    conversationId: null
  });
  const [incomingCall, setIncomingCall] = useState<CallEvent | null>(null);
  const [callError, setCallError] = useState<string | null>(null);
  const [importingKeys, setImportingKeys] = useState(false);
  const [micMuted, setMicMuted] = useState(false);
  const signalSupported = isSignalSupported();

  const lastPollRef = useRef(0);
  const lastStatusPollRef = useRef(0);
  const lastCallPollRef = useRef(0);
  const selectedConversationRef = useRef<number | null>(null);
  const typingTimeoutRef = useRef<number | null>(null);
  const pollDelayRef = useRef(2500);
  const messageEndRef = useRef<HTMLDivElement | null>(null);
  const messagesRef = useRef<ChatMessage[]>([]);
  const retryDecryptRef = useRef(false);
  const callPeerRef = useRef<RTCPeerConnection | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const remoteStreamRef = useRef<MediaStream | null>(null);
  const localVideoRef = useRef<HTMLVideoElement | null>(null);
  const remoteVideoRef = useRef<HTMLVideoElement | null>(null);
  const callStateRef = useRef<CallState>(callState);
  const pendingIceRef = useRef<RTCIceCandidateInit[]>([]);
  const callTimeoutRef = useRef<number | null>(null);
  const callStartRef = useRef<number | null>(null);
  const callConversationRef = useRef<number | null>(null);

  useEffect(() => {
    const onHashChange = () => {
      const hash = window.location.hash || "";
      if (hash.startsWith("#invite=")) {
        const tokenValue = hash.replace("#invite=", "").trim();
        setAdminRoute(false);
        if (tokenValue) {
          setInviteToken(tokenValue);
          setPendingInviteToken(tokenValue);
        }
        return;
      }
      setAdminRoute(hash === "#admin");
    };
    window.addEventListener("hashchange", onHashChange);
    onHashChange();
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("messager.theme", theme);
  }, [theme]);

  useEffect(() => {
    callStateRef.current = callState;
  }, [callState]);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

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

  useEffect(() => {
    setShowContactPrivacy(false);
    setShowManagePanel(false);
    const convo = conversations.find((item) => item.id === selectedConversationId);
    if (convo?.type === "direct") {
      setContactPrivacy({ ...defaultPrivacy });
    }
  }, [selectedConversationId, conversations]);

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
    if (!isLoggedIn || !pendingInviteToken) {
      return;
    }
    const run = async () => {
      try {
        const data = await redeemInviteLink(pendingInviteToken);
        await refreshConversations();
        if (typeof data.conversationId === "number") {
          setSelectedConversationId(data.conversationId);
        }
        setStatus("Joined with invite");
      } catch (error) {
        setStatus((error as Error).message);
      } finally {
        setPendingInviteToken(null);
        window.history.replaceState(
          null,
          "",
          window.location.pathname + window.location.search
        );
      }
    };
    run();
  }, [isLoggedIn, pendingInviteToken]);

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
          allowGroupInvite: Boolean(data.allowGroupInvite),
          privacy: {
            ...defaultPrivacy,
            ...(data.privacy || {})
          }
        });
        setTwoFactorEnabled(Boolean(data.twoFactorEnabled));
      })
      .catch(() => undefined);
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn || !signalSupported) {
      return;
    }
    ensureLocalKeys(sessionUsername, false)
      .then((bundle) => {
        if (!bundle) {
          setStatus("No local keys found. Sign up on this device first.");
          return;
        }
        return publishKeyBundle({
          ...bundle,
          sessionDeviceId: getDeviceId()
        }).catch(() => undefined);
      })
      .catch(() => undefined);
  }, [isLoggedIn, sessionUsername]);

  useEffect(() => {
    if (!isLoggedIn || !("Notification" in window)) {
      return;
    }
    if (Notification.permission === "default") {
      Notification.requestPermission().catch(() => undefined);
    }
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn || !showSettings) {
      return;
    }
    setDevicesLoading(true);
    listDevices()
      .then((data) => setDevices(data.devices || []))
      .catch(() => undefined)
      .finally(() => setDevicesLoading(false));
  }, [isLoggedIn, showSettings]);

  useEffect(() => {
    if (!token || !sessionUsername) {
      return undefined;
    }

    let isMounted = true;
    const poller = async () => {
      try {
        const data = await pollMessages(lastPollRef.current, 50);
        if (!isMounted || !data.messages?.length) {
          pollDelayRef.current = Math.min(pollDelayRef.current + 1000, 8000);
          return;
        }

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
            let plaintext = "";
            if (msg.nonce?.startsWith("signal:")) {
              plaintext = await decryptSignalMessage(
                sessionUsername,
                msg.sender_username,
                Number(msg.sender_device_id) || 1,
                msg.ciphertext,
                msg.nonce
              );
            } else {
              plaintext = msg.ciphertext;
            }

            const envelope = parseSignalEnvelope(plaintext);
            if (envelope?.kind === "sender-key") {
              continue;
            }

            const payload =
              envelope?.kind === "chat"
                ? envelope.payload
                : parsePayload(plaintext);

            decrypted.push({
              id: msg.id,
              groupId: msg.group_id,
              conversationId: msg.conversation_id,
              sender: msg.sender_username,
              payload,
              createdAt: msg.created_at,
              deletedAt: msg.deleted_at
            });
          } catch {
            decrypted.push({
              id: msg.id,
              groupId: msg.group_id,
              conversationId: msg.conversation_id,
              sender: msg.sender_username,
              payload: { text: "Encrypted message", attachments: [] },
              createdAt: msg.created_at,
              deletedAt: msg.deleted_at,
              encrypted: {
                ciphertext: msg.ciphertext,
                nonce: msg.nonce,
                senderDeviceId: Number(msg.sender_device_id) || 1
              }
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
        if (
          decrypted.length > 0 &&
          document.visibilityState !== "visible" &&
          "Notification" in window &&
          Notification.permission === "granted"
        ) {
          const latest = decrypted[decrypted.length - 1];
          new Notification(`New message from ${latest.sender}`, {
            body: getPreview(latest.payload) || "New message"
          });
        }
        lastPollRef.current = data.messages[data.messages.length - 1].created_at;
        pollDelayRef.current = 2500;
      } catch (error) {
        setStatus((error as Error).message);
      }
    };

    let timer: number | undefined;
    const schedule = () => {
      timer = window.setTimeout(async () => {
        await poller();
        if (isMounted) {
          schedule();
        }
      }, pollDelayRef.current);
    };
    poller().then(schedule).catch(schedule);

    return () => {
      isMounted = false;
      if (timer) {
        window.clearTimeout(timer);
      }
    };
  }, [sessionUsername, token]);

  useEffect(() => {
    if (!token) {
      return undefined;
    }

    const retryInterval = setInterval(async () => {
      if (retryDecryptRef.current || !sessionUsername) {
        return;
      }
      const encryptedMessages = messagesRef.current.filter(
        (message) => Boolean(message.encrypted)
      );
      if (encryptedMessages.length === 0) {
        return;
      }
      retryDecryptRef.current = true;
      try {
        const updates = new Map<number | string, MessagePayload>();
        for (const message of encryptedMessages) {
          const encrypted = message.encrypted;
          if (!encrypted) {
            continue;
          }
          try {
            const plaintext = await decryptSignalMessage(
              sessionUsername,
              message.sender,
              encrypted.senderDeviceId,
              encrypted.ciphertext,
              encrypted.nonce
            );
            const envelope = parseSignalEnvelope(plaintext);
            const payload =
              envelope?.kind === "chat"
                ? envelope.payload
                : parsePayload(plaintext);
            updates.set(message.id, payload);
          } catch {
            // keep encrypted placeholder
          }
        }
        if (updates.size > 0) {
          setMessages((prev) =>
            prev.map((message) =>
              updates.has(message.id)
                ? {
                    ...message,
                    payload: updates.get(message.id) || message.payload,
                    encrypted: undefined
                  }
                : message
            )
          );
        }
      } finally {
        retryDecryptRef.current = false;
      }
    }, 8000);

    let isMounted = true;
    const poller = async () => {
      try {
        const data = await pollSentStatuses(lastStatusPollRef.current, 50);
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
      clearInterval(retryInterval);
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
    if (!showManagePanel || !selectedConversationId) {
      return;
    }
    const load = async () => {
      try {
        const data = await fetchRoster(selectedConversationId);
        setRoster(data.members || []);
        const invitesData = await listInviteLinks(selectedConversationId);
        setInviteLinks(invitesData.invites || []);
      } catch (error) {
        setStatus((error as Error).message);
      }
    };
    load();
  }, [showManagePanel, selectedConversationId]);

  useEffect(() => {
    if (!token) {
      return undefined;
    }

    let isMounted = true;
    const poller = async () => {
      try {
        const data = await pollCalls(lastCallPollRef.current);
        if (!isMounted || !data.events?.length) {
          return;
        }
        const events = data.events as CallEvent[];
        for (const event of events) {
          if (event.type === "offer") {
            if (callStateRef.current.status !== "idle") {
              continue;
            }
            setIncomingCall(event);
            setCallState({
              status: "incoming",
              callId: event.callId,
              peerUsername: event.payload.fromUsername || null,
              media: event.payload.media || "audio",
              conversationId:
                typeof event.payload.conversationId === "number"
                  ? event.payload.conversationId
                  : null
            });
            if (
              typeof event.payload.conversationId === "number" &&
              event.payload.conversationId !== selectedConversationId
            ) {
              setSelectedConversationId(event.payload.conversationId);
            }
          } else if (event.type === "answer") {
            if (
              event.callId !== callStateRef.current.callId ||
              !callPeerRef.current
            ) {
              continue;
            }
            if (event.payload.answer) {
              await callPeerRef.current.setRemoteDescription(
                new RTCSessionDescription(JSON.parse(event.payload.answer))
              );
              await flushPendingIce();
              setCallState((prev) =>
                prev.status === "outgoing"
                  ? { ...prev, status: "active" }
                  : prev
              );
              callStartRef.current = Date.now();
              if (callTimeoutRef.current) {
                window.clearTimeout(callTimeoutRef.current);
                callTimeoutRef.current = null;
              }
            }
          } else if (event.type === "ice") {
            if (
              event.callId !== callStateRef.current.callId ||
              !callPeerRef.current
            ) {
              continue;
            }
            if (event.payload.candidate) {
              const candidate = JSON.parse(event.payload.candidate);
              if (!callPeerRef.current.remoteDescription) {
                pendingIceRef.current.push(candidate);
              } else {
                await callPeerRef.current.addIceCandidate(
                  new RTCIceCandidate(candidate)
                );
              }
            }
          } else if (event.type === "end") {
            if (event.callId !== callStateRef.current.callId) {
              continue;
            }
            finalizeCallLog();
            resetCallState();
            setStatus("Call ended");
          }
        }
        lastCallPollRef.current = events[events.length - 1].id;
      } catch {
        // ignore
      }
    };

    const interval = setInterval(poller, 1500);
    poller();

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [token]);

  useEffect(() => {
    if (!selectedConversationId || !token) {
      return;
    }
    const conversation = conversations.find(
      (item) => item.id === selectedConversationId
    );
    if (!conversation || conversation.type !== "direct") {
      return;
    }
    const other = conversation.members.find(
      (member) => member.username !== sessionUsername
    );
    if (!other) {
      return;
    }
    let isMounted = true;
    const poller = async () => {
      try {
        const data = await fetchUserStatus(other.username);
        if (!isMounted) {
          return;
        }
        setStatusByUser((prev) => ({
          ...prev,
          [other.username]: {
            online: Boolean(data.online),
            lastSeen: typeof data.lastSeen === "number" ? data.lastSeen : null
          }
        }));
      } catch {
        // ignore
      }
    };
    const interval = setInterval(poller, 8000);
    poller();
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [selectedConversationId, conversations, sessionUsername, token]);

  useEffect(() => {
    const handler = () => {
      if (callStateRef.current.callId) {
        endCall({ callId: callStateRef.current.callId }).catch(() => undefined);
      }
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, []);
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
      const deviceId = getDeviceId();
      const deviceName = getDeviceName();
      if (!phone || !firstName || !lastName || !username) {
        setStatus("Phone, name, and username are required.");
        return;
      }
      if (enable2fa && password.length < 6) {
        setStatus("2FA password must be at least 6 characters.");
        return;
      }
      if (!signalSupported) {
        setStatus("Encryption requires HTTPS. Please use the secure domain.");
        return;
      }
      const bundle = await ensureLocalKeys(username, true);
      if (!bundle) {
        setStatus("Failed to create local keys.");
        return;
      }
      const publicKey = bundle.identityKey;
      const data = await signup(
        phone,
        firstName,
        lastName,
        username,
        enable2fa ? password : null,
        publicKey,
        deviceId,
        deviceName,
        getDeviceInfo()
      );

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
        allowGroupInvite: Boolean(data.allowGroupInvite),
        privacy: {
          ...defaultPrivacy,
          ...(data.privacy || {})
        }
      });
      setTwoFactorEnabled(Boolean(data.twoFactorEnabled));

      setAuthToken(data.token);
      if (signalSupported) {
        await publishKeyBundle({
          ...bundle,
          sessionDeviceId: deviceId
        });
      }

      localStorage.setItem(STORAGE_KEYS.username, data.username);
      localStorage.setItem(STORAGE_KEYS.token, data.token);

      setStatus("Signup complete");
      setShowSettings(false);
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleLogin = async () => {
    setStatus(null);
    try {
      const deviceId = getDeviceId();
      const deviceName = getDeviceName();
      if (!phone) {
        setStatus("Phone is required.");
        return;
      }

      const data = await login(
        phone,
        password,
        deviceId,
        deviceName,
        getDeviceInfo()
      );
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
        allowGroupInvite: Boolean(data.allowGroupInvite),
        privacy: {
          ...defaultPrivacy,
          ...(data.privacy || {})
        }
      });
      setTwoFactorEnabled(Boolean(data.twoFactorEnabled));
      localStorage.setItem(STORAGE_KEYS.username, data.username);
      localStorage.setItem(STORAGE_KEYS.token, data.token);

      setAuthToken(data.token);
      if (!signalSupported) {
        setStatus("Encryption requires HTTPS. Please use the secure domain.");
        return;
      }
      const bundle = await ensureLocalKeys(data.username, true);
      if (!bundle) {
        setStatus("Failed to create local keys.");
        return;
      }
      await publishKeyBundle({
        ...bundle,
        sessionDeviceId: deviceId
      });

      setStatus(
        data.newDevice
          ? "Login complete. New device detected."
          : "Login complete"
      );
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

  const handleAdminDownloadMetadata = async (user: AdminUser) => {
    setStatus(null);
    try {
      const blob = await adminDownloadUserMetadata(user.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${user.username}-metadata.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
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
        allowGroupInvite: profileState.allowGroupInvite,
        privacy: profileState.privacy
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

  const handleResetEncryption = async () => {
    if (
      !window.confirm(
        "Reset encryption keys on this device? Old messages may become unreadable."
      )
    ) {
      return;
    }
    setStatus(null);
    try {
      await resetSignalState();
      const bundle = await ensureLocalKeys(sessionUsername, true);
      if (!bundle) {
        setStatus("Failed to recreate keys.");
        return;
      }
      await publishKeyBundle({
        ...bundle,
        sessionDeviceId: getDeviceId()
      });
      setStatus("Encryption keys reset.");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleExportKeys = async () => {
    setStatus(null);
    try {
      const data = await exportSignalState();
      const blob = new Blob([JSON.stringify(data)], {
        type: "application/json"
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `pakeger-keys-${sessionUsername || "device"}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setStatus("Key backup downloaded.");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleImportKeys = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    setImportingKeys(true);
    setStatus(null);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as Record<string, string>;
      await importSignalState(parsed);
      const bundle = await ensureLocalKeys(sessionUsername, false);
      if (bundle) {
        await publishKeyBundle({
          ...bundle,
          sessionDeviceId: getDeviceId()
        });
      }
      setStatus("Key backup imported.");
    } catch (error) {
      setStatus((error as Error).message);
    } finally {
      setImportingKeys(false);
      event.target.value = "";
    }
  };

  const handleDeviceLogout = async (deviceId: string) => {
    setStatus(null);
    try {
      await logoutDevice(deviceId);
      const data = await listDevices();
      setDevices(data.devices || []);
      setStatus("Device logged out");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleLogoutAllDevices = async () => {
    if (!window.confirm("Log out from all devices?")) {
      return;
    }
    setStatus(null);
    try {
      await logoutAllDevices();
      setDevices([]);
      setToken("");
      localStorage.removeItem(STORAGE_KEYS.token);
      setStatus("Logged out from all devices");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleContactPrivacySave = async () => {
    if (!selectedConversation || selectedConversation.type !== "direct") {
      return;
    }
    const other = selectedConversation.members.find(
      (member) => member.username !== sessionUsername
    );
    if (!other) {
      return;
    }
    setStatus(null);
    try {
      await updateContactPrivacy({
        username: other.username,
        privacy: contactPrivacy
      });
      setStatus("Contact privacy updated");
      setShowContactPrivacy(false);
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleEnableTwoFactor = async () => {
    if (twoFactorPassword.length < 6) {
      setStatus("2FA password must be at least 6 characters.");
      return;
    }
    setStatus(null);
    try {
      await enableTwoFactor(twoFactorPassword);
      setTwoFactorEnabled(true);
      setTwoFactorPassword("");
      setStatus("Two-step verification enabled.");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleDisableTwoFactor = async () => {
    if (!twoFactorPassword) {
      setStatus("Enter current 2FA password to disable.");
      return;
    }
    setStatus(null);
    try {
      await disableTwoFactor(twoFactorPassword);
      setTwoFactorEnabled(false);
      setTwoFactorPassword("");
      setStatus("Two-step verification disabled.");
    } catch (error) {
      setStatus((error as Error).message);
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
    if (!selectedConversationId) {
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

      const envelope = { kind: "chat", payload };
      const payloads: Array<{
        messageId: string;
        toUsername: string;
        toDeviceId: string;
        ciphertext: string;
        nonce: string;
      }> = [];
      const messageId = crypto.randomUUID
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random()}`;

      const recipients = members.filter(
        (member) => member.username !== sessionUsername
      );

      if (!signalSupported) {
        setStatus("Encryption requires HTTPS. Please use the secure domain.");
        return;
      }

      if (conversation.type === "direct") {
        for (const member of recipients) {
          const bundle = await fetchKeyBundle(member.username);
          const devices = bundle.devices || [];
          for (const device of devices) {
            await ensureSession(sessionUsername, member.username, device);
            const encrypted = await encryptSignalMessage(
              sessionUsername,
              member.username,
              device.deviceId,
              JSON.stringify(envelope)
            );
            payloads.push({
              messageId,
              toUsername: member.username,
              toDeviceId: String(device.sessionDeviceId ?? device.deviceId),
              ciphertext: encrypted.ciphertext,
              nonce: encrypted.nonce
            });
          }
        }
      } else {
        const recipientDevices: Array<{
          username: string;
          sessionDeviceId: string;
          bundle: {
            registrationId: number;
            deviceId: number;
            sessionDeviceId: string;
            identityKey: string;
            signedPreKeyId: number;
            signedPreKey: string;
            signedPreKeySig: string;
            oneTimePreKey?: { id: number; key: string } | null;
          };
        }> = [];
        for (const member of recipients) {
          const bundle = await fetchKeyBundle(member.username);
          const devices = bundle.devices || [];
          for (const device of devices) {
            recipientDevices.push({
              username: member.username,
              sessionDeviceId: String(device.sessionDeviceId ?? device.deviceId),
              bundle: device
            });
          }
        }

        for (const entry of recipientDevices) {
          await ensureSession(sessionUsername, entry.username, entry.bundle);
          const encrypted = await encryptSignalMessage(
            sessionUsername,
            entry.username,
            entry.bundle.deviceId,
            JSON.stringify(envelope)
          );
          payloads.push({
            messageId,
            toUsername: entry.username,
            toDeviceId: entry.sessionDeviceId,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce
          });
        }
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
      } else if (tab === "group" || tab === "channel") {
        const members = groupMembers
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean);
        const membersToSend = groupVisibility === "private" ? [] : members;
        await createConversation(tab, groupName, membersToSend, groupVisibility);
        setGroupName("");
        setGroupMembers("");
        setGroupVisibility("public");
      } else {
        setStatus("Select a conversation type first.");
        return;
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
    if (profileState.privacy.disable_typing_indicator) {
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

  const refreshRoster = async (conversationId: number) => {
    const data = await fetchRoster(conversationId);
    setRoster(data.members || []);
    const invitesData = await listInviteLinks(conversationId);
    setInviteLinks(invitesData.invites || []);
  };

  const handleAddMember = async () => {
    if (!selectedConversationId || !manageUsername) {
      return;
    }
    setStatus(null);
    try {
      await addConversationMember(selectedConversationId, manageUsername);
      setManageUsername("");
      await refreshRoster(selectedConversationId);
      setStatus("Member added");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleRemoveMember = async (username: string) => {
    if (!selectedConversationId) {
      return;
    }
    setStatus(null);
    try {
      await removeConversationMember(selectedConversationId, username);
      await refreshRoster(selectedConversationId);
      setStatus("Member removed");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handlePromoteMember = async (username: string) => {
    if (!selectedConversationId) {
      return;
    }
    setStatus(null);
    try {
      await updateConversationRole(selectedConversationId, username, "admin", {
        manage_members: true,
        manage_invites: true
      });
      await refreshRoster(selectedConversationId);
      setStatus("Admin updated");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleDemoteMember = async (username: string) => {
    if (!selectedConversationId) {
      return;
    }
    setStatus(null);
    try {
      await updateConversationRole(selectedConversationId, username, "member");
      await refreshRoster(selectedConversationId);
      setStatus("Admin removed");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleUpdateAdminPerms = async (
    username: string,
    permissions: { manage_members?: boolean; manage_invites?: boolean }
  ) => {
    if (!selectedConversationId) {
      return;
    }
    setStatus(null);
    try {
      await updateConversationRole(
        selectedConversationId,
        username,
        "admin",
        permissions
      );
      await refreshRoster(selectedConversationId);
      setStatus("Permissions updated");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleCreateInvite = async () => {
    if (!selectedConversationId) {
      return;
    }
    setStatus(null);
    try {
      await createInviteLink(
        selectedConversationId,
        Math.max(1, inviteMaxUses),
        Math.max(1, inviteExpiresMinutes)
      );
      await refreshRoster(selectedConversationId);
      setStatus("Invite created");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleRevokeInvite = async (token: string) => {
    setStatus(null);
    try {
      await revokeInviteLink(token);
      if (selectedConversationId) {
        await refreshRoster(selectedConversationId);
      }
      setStatus("Invite revoked");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const handleRedeemInvite = async () => {
    if (!inviteToken) {
      return;
    }
    const tokenValue = inviteToken.includes("#invite=")
      ? inviteToken.split("#invite=")[1]
      : inviteToken;
    const trimmed = tokenValue.trim();
    if (!trimmed) {
      return;
    }
    setStatus(null);
    try {
      const data = await redeemInviteLink(trimmed);
      setInviteToken("");
      await refreshConversations();
      if (typeof data.conversationId === "number") {
        setSelectedConversationId(data.conversationId);
      }
      setStatus("Joined with invite");
    } catch (error) {
      setStatus((error as Error).message);
    }
  };

  const resetCallState = () => {
    if (callTimeoutRef.current) {
      window.clearTimeout(callTimeoutRef.current);
      callTimeoutRef.current = null;
    }
    callPeerRef.current?.close();
    callPeerRef.current = null;
    pendingIceRef.current = [];
    localStreamRef.current?.getTracks().forEach((track) => track.stop());
    remoteStreamRef.current?.getTracks().forEach((track) => track.stop());
    localStreamRef.current = null;
    remoteStreamRef.current = null;
    if (localVideoRef.current) {
      localVideoRef.current.srcObject = null;
    }
    if (remoteVideoRef.current) {
      remoteVideoRef.current.srcObject = null;
    }
    setIncomingCall(null);
    setCallError(null);
    setMicMuted(false);
    setCallState({
      status: "idle",
      callId: null,
      peerUsername: null,
      media: "audio",
      conversationId: null
    });
  };

  const appendCallEndedMessage = (conversationId: number, durationMs: number) => {
    const payload = {
      text: `Call ended (${formatDuration(durationMs)})`,
      attachments: []
    };
    setMessages((prev) => [
      ...prev,
      {
        id: `call-${Date.now()}`,
        groupId: `call-${Date.now()}`,
        conversationId,
        sender: "system",
        payload,
        createdAt: Date.now(),
        deletedAt: null
      }
    ]);
    setLastMessageByConversation((prev) => ({
      ...prev,
      [conversationId]: {
        sender: "system",
        payload,
        createdAt: Date.now()
      }
    }));
  };

  const finalizeCallLog = () => {
    if (callStartRef.current && callConversationRef.current) {
      appendCallEndedMessage(
        callConversationRef.current,
        Date.now() - callStartRef.current
      );
    }
    callStartRef.current = null;
    callConversationRef.current = null;
  };

  const handleToggleMic = () => {
    const stream = localStreamRef.current;
    if (!stream) {
      return;
    }
    const tracks = stream.getAudioTracks();
    if (!tracks.length) {
      return;
    }
    const nextMuted = !micMuted;
    tracks.forEach((track) => {
      track.enabled = !nextMuted;
    });
    setMicMuted(nextMuted);
  };

  const flushPendingIce = async () => {
    if (!callPeerRef.current || !callPeerRef.current.remoteDescription) {
      return;
    }
    const pending = [...pendingIceRef.current];
    pendingIceRef.current = [];
    for (const candidate of pending) {
      try {
        await callPeerRef.current.addIceCandidate(
          new RTCIceCandidate(candidate)
        );
      } catch {
        // ignore invalid candidates
      }
    }
  };

  const createPeerConnection = (callId: string, target: "caller" | "callee") => {
    const peer = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
    });
    peer.onicecandidate = (event) => {
      if (event.candidate) {
        sendIceCandidate({
          callId,
          target,
          candidate: JSON.stringify(event.candidate)
        }).catch(() => undefined);
      }
    };
    peer.ontrack = (event) => {
      if (!remoteStreamRef.current) {
        remoteStreamRef.current = new MediaStream();
      }
      remoteStreamRef.current.addTrack(event.track);
      if (remoteVideoRef.current) {
        remoteVideoRef.current.srcObject = remoteStreamRef.current;
      }
    };
    peer.onconnectionstatechange = () => {
      if (peer.connectionState === "failed") {
        setCallError("Call failed.");
        finalizeCallLog();
        resetCallState();
      }
    };
    peer.oniceconnectionstatechange = () => {
      if (
        peer.iceConnectionState === "failed" ||
        peer.iceConnectionState === "disconnected"
      ) {
        setCallError("Connection lost.");
        finalizeCallLog();
        resetCallState();
      }
    };
    callPeerRef.current = peer;
    return peer;
  };

  const handleStartCall = async (media: "audio" | "video") => {
    if (!selectedConversation || selectedConversation.type !== "direct") {
      return;
    }
    if (callState.status !== "idle") {
      return;
    }
    const other = selectedConversation.members.find(
      (member) => member.username !== sessionUsername
    );
    if (!other) {
      return;
    }
    setCallError(null);
    try {
      if (!navigator.mediaDevices?.getUserMedia) {
        setCallError("Media devices are not available in this browser.");
        return;
      }
      const bundle = await fetchKeyBundle(other.username);
      const devices = bundle.devices || [];
      const target = devices[0];
      if (!target) {
        setStatus("No device available for this user.");
        return;
      }

      const callId = crypto.randomUUID
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random()}`;
      callConversationRef.current = selectedConversation.id;
      const peer = createPeerConnection(callId, "callee");
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: media === "video"
      });
      localStreamRef.current = stream;
      stream.getTracks().forEach((track) => peer.addTrack(track, stream));
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
      }

      const offer = await peer.createOffer();
      await peer.setLocalDescription(offer);
      await startCall({
        callId,
        conversationId: selectedConversation.id,
        toUsername: other.username,
        toDeviceId: String(target.sessionDeviceId ?? target.deviceId),
        media,
        offer: JSON.stringify(offer)
      });
      setCallState({
        status: "outgoing",
        callId,
        peerUsername: other.username,
        media,
        conversationId: selectedConversation.id
      });
      setMicMuted(false);
      if (callTimeoutRef.current) {
        window.clearTimeout(callTimeoutRef.current);
      }
      callTimeoutRef.current = window.setTimeout(() => {
        if (callStateRef.current.status === "outgoing") {
          setCallError("No answer.");
          handleEndCall();
        }
      }, 30000);
    } catch (error) {
      setCallError((error as Error).message);
      resetCallState();
    }
  };

  const handleAcceptCall = async () => {
    if (!incomingCall) {
      return;
    }
    const offerRaw = incomingCall.payload.offer;
    const callId = incomingCall.callId;
    const media = incomingCall.payload.media || "audio";
    const conversationId =
      incomingCall.payload.conversationId ?? selectedConversationId ?? null;
    if (!offerRaw) {
      setCallError("Missing offer.");
      resetCallState();
      return;
    }
    setCallError(null);
    try {
      if (!navigator.mediaDevices?.getUserMedia) {
        setCallError("Media devices are not available in this browser.");
        resetCallState();
        return;
      }
      if (typeof conversationId === "number") {
        callConversationRef.current = conversationId;
      }
      const peer = createPeerConnection(callId, "caller");
      await peer.setRemoteDescription(
        new RTCSessionDescription(JSON.parse(offerRaw))
      );
      await flushPendingIce();
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: media === "video"
      });
      localStreamRef.current = stream;
      stream.getTracks().forEach((track) => peer.addTrack(track, stream));
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
      }
      const answer = await peer.createAnswer();
      await peer.setLocalDescription(answer);
      await answerCall({ callId, answer: JSON.stringify(answer) });
      setCallState({
        status: "active",
        callId,
        peerUsername: incomingCall.payload.fromUsername || null,
        media,
        conversationId: typeof conversationId === "number" ? conversationId : null
      });
      callStartRef.current = Date.now();
      setMicMuted(false);
      if (callTimeoutRef.current) {
        window.clearTimeout(callTimeoutRef.current);
        callTimeoutRef.current = null;
      }
      setIncomingCall(null);
    } catch (error) {
      setCallError((error as Error).message);
      resetCallState();
    }
  };

  const handleDeclineCall = async () => {
    if (!incomingCall) {
      return;
    }
    try {
      await endCall({ callId: incomingCall.callId });
    } catch {
      // ignore
    }
    resetCallState();
  };

  const handleEndCall = async () => {
    if (!callState.callId) {
      return;
    }
    try {
      await endCall({ callId: callState.callId });
    } catch {
      // ignore
    }
    finalizeCallLog();
    resetCallState();
  };

  const filteredConversations = conversations.filter((conv) => {
    if (tab !== "all" && conv.type !== tab) {
      return false;
    }
    if (!conversationQuery) {
      return true;
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
  const directPartner =
    selectedConversation?.type === "direct"
      ? selectedConversation.members.find(
          (member) => member.username !== sessionUsername
        )?.username || null
      : null;
  const directStatus = directPartner ? statusByUser[directPartner] : null;

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

  const orderedMessages = [...searchedMessages].sort(
    (a, b) => a.createdAt - b.createdAt
  );

  const messageItems: Array<
    | { kind: "date"; id: string; label: string }
    | { kind: "message"; message: ChatMessage }
  > = [];
  let lastDateKey = "";
  for (const message of orderedMessages) {
    const dateKey = new Date(message.createdAt).toDateString();
    if (dateKey !== lastDateKey) {
      messageItems.push({
        kind: "date",
        id: `date-${dateKey}`,
        label: formatDateLabel(message.createdAt)
      });
      lastDateKey = dateKey;
    }
    messageItems.push({ kind: "message", message });
  }

  const pinnedMessages = activeMessages.filter((msg) =>
    pinnedIds.has(String(msg.id))
  );

  const getStatusMark = (groupId: string) => {
    const statusRow = statusByGroupId[groupId];
    if (!statusRow) {
      return "";
    }
    if (statusRow.readAt) {
      return "\u2713\u2713";
    }
    if (statusRow.deliveredAt) {
      return "\u2713\u2713";
    }
    return "\u2713";
  };

  useEffect(() => {
    if (!messageEndRef.current) {
      return;
    }
    messageEndRef.current.scrollIntoView({ behavior: "smooth" });
  }, [orderedMessages.length, selectedConversationId]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="logo">P</div>
          <div>
            <h1>Pakeger</h1>
            <p>Secure. Fast. Modern messaging.</p>
          </div>
        </div>
        <div className="topbar-actions">
          <button
            className="ghost"
            onClick={() =>
              setTheme((prev) => (prev === "dark" ? "light" : "dark"))
            }
          >
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
          {isLoggedIn && !adminRoute && (
            <button
              className="ghost"
              onClick={() => setSidebarCollapsed((prev) => !prev)}
            >
              {sidebarCollapsed ? "Show chats" : "Hide chats"}
            </button>
          )}
          {isLoggedIn && !adminRoute && (
            <button
              className="ghost"
              onClick={() => setShowSettings((v) => !v)}
            >
              {showSettings ? "Back to chats" : "Settings"}
            </button>
          )}
        </div>
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
          <p className="note">Default admin: taha / 12345678</p>
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
                        <span className="muted">
                          {user.firstName} {user.lastName} | {user.phone || "No phone"}
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
                        className="secondary"
                        onClick={() => handleAdminDownloadMetadata(user)}
                      >
                        Download JSON
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
                      {conv.visibility && <span>Visibility: {conv.visibility}</span>}
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
          <p className="note">
            OTP is disabled in local mode. Use phone-based login for now.
          </p>
          <label>
            Phone
            <input
              value={phone}
              onChange={(event) => setPhone(event.target.value)}
              placeholder="+98912..."
            />
          </label>
          <label>
            First name
            <input
              value={firstName}
              onChange={(event) => setFirstName(event.target.value)}
              placeholder="First name"
            />
          </label>
          <label>
            Last name
            <input
              value={lastName}
              onChange={(event) => setLastName(event.target.value)}
              placeholder="Last name"
            />
          </label>
          <p className="note">Name/username are only required for signup.</p>
          <label>
            Username
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="username (5-32 chars)"
            />
          </label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={enable2fa}
              onChange={(event) => setEnable2fa(event.target.checked)}
            />
            <span>Enable 2-step verification (password)</span>
          </label>
          <label>
            2FA password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="optional"
            />
          </label>
          <div className="row">
            <button
              onClick={handleSignup}
              disabled={
                !phone ||
                !firstName ||
                !lastName ||
                !username ||
                (enable2fa && password.length < 6)
              }
            >
              Sign up (create keys)
            </button>
            <button onClick={handleLogin} disabled={!phone}>
              Log in
            </button>
          </div>
          <p className="note">
            Your encryption keys stay in this browser (IndexedDB).
          </p>
        </section>
      )}

      {!adminRoute && isLoggedIn && (
        <div className={sidebarCollapsed ? "layout collapsed" : "layout"}>
          <aside className="sidebar card">
            <div className="sidebar-top">
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
              <button
                className="ghost small"
                onClick={() => setSidebarCollapsed((prev) => !prev)}
              >
                {sidebarCollapsed ? "Expand" : "Collapse"}
              </button>
            </div>

            <div className="tabs">
              {tabs.map((item) => (
                <button
                  key={item}
                  className={item === tab ? "active" : ""}
                  onClick={() => setTab(item)}
                >
                  {item === "direct"
                    ? "Personal"
                    : item === "all"
                    ? "All"
                    : item}
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
                const presence =
                  conv.type === "direct" ? statusByUser[title] : null;
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
                      <div className="avatar small avatar-wrap">
                        {profile?.avatar ? (
                          <img src={profile.avatar} alt={title} />
                        ) : (
                          <span>{getInitials(title)}</span>
                        )}
                        {presence && (
                          <span
                            className={
                              presence.online ? "status-dot online" : "status-dot"
                            }
                          />
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
              ) : tab === "all" ? (
                <p className="muted">Choose a tab to create a chat.</p>
              ) : (
                <>
                  <h3>New {tab}</h3>
                  <div className="row">
                    <button
                      type="button"
                      className={groupVisibility === "public" ? "" : "secondary"}
                      onClick={() => setGroupVisibility("public")}
                    >
                      Public
                    </button>
                    <button
                      type="button"
                      className={groupVisibility === "private" ? "" : "secondary"}
                      onClick={() => setGroupVisibility("private")}
                    >
                      Private
                    </button>
                  </div>
                  <input
                    value={groupName}
                    onChange={(event) => setGroupName(event.target.value)}
                    placeholder="name"
                  />
                  {groupVisibility === "public" ? (
                    <textarea
                      value={groupMembers}
                      onChange={(event) => setGroupMembers(event.target.value)}
                      placeholder="members (comma separated)"
                    />
                  ) : (
                    <p className="note">
                      Private chats use invite links. Create the group first,
                      then generate a one-time link in the manage panel.
                    </p>
                  )}
                </>
              )}
              <button
                onClick={handleCreateConversation}
                disabled={
                  tab === "all"
                    ? true
                    : tab === "direct"
                    ? !directUsername
                    : !groupName || (groupVisibility === "public" && !groupMembers)
                }
              >
                Create
              </button>
            </div>

            <div className="divider" />

            <div className="create-block">
              <h3>Join with invite</h3>
              <input
                value={inviteToken}
                onChange={(event) => setInviteToken(event.target.value)}
                placeholder="invite token"
              />
              <button onClick={handleRedeemInvite} disabled={!inviteToken}>
                Join
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
                    <div className="divider" />
                    <h4>Privacy</h4>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={profileState.privacy.hide_online}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            privacy: {
                              ...prev.privacy,
                              hide_online: event.target.checked
                            }
                          }))
                        }
                      />
                      <span>Hide online status</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={profileState.privacy.hide_last_seen}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            privacy: {
                              ...prev.privacy,
                              hide_last_seen: event.target.checked
                            }
                          }))
                        }
                      />
                      <span>Hide last seen</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={profileState.privacy.hide_profile_photo}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            privacy: {
                              ...prev.privacy,
                              hide_profile_photo: event.target.checked
                            }
                          }))
                        }
                      />
                      <span>Hide profile photo</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={profileState.privacy.disable_read_receipts}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            privacy: {
                              ...prev.privacy,
                              disable_read_receipts: event.target.checked
                            }
                          }))
                        }
                      />
                      <span>Disable read receipts</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={profileState.privacy.disable_typing_indicator}
                        onChange={(event) =>
                          setProfileState((prev) => ({
                            ...prev,
                            privacy: {
                              ...prev.privacy,
                              disable_typing_indicator: event.target.checked
                            }
                          }))
                        }
                      />
                      <span>Disable typing indicator</span>
                    </label>
                    <div className="divider" />
                    <h4>Two-step verification</h4>
                    <label>
                      {twoFactorEnabled ? "Current 2FA password" : "New 2FA password"}
                      <input
                        type="password"
                        value={twoFactorPassword}
                        onChange={(event) => setTwoFactorPassword(event.target.value)}
                        placeholder="min 6 characters"
                      />
                    </label>
                    {twoFactorEnabled ? (
                      <button className="secondary" onClick={handleDisableTwoFactor}>
                        Disable 2FA
                      </button>
                    ) : (
                      <button onClick={handleEnableTwoFactor}>
                        Enable 2FA
                      </button>
                    )}
                    <button onClick={handleProfileSave} disabled={profileSaving}>
                      {profileSaving ? "Saving..." : "Save settings"}
                    </button>
                    <div className="row">
                      <button className="secondary" onClick={handleExportKeys}>
                        Export keys
                      </button>
                      <label className="file-input secondary">
                        Import keys
                        <input
                          type="file"
                          accept="application/json"
                          onChange={handleImportKeys}
                          disabled={importingKeys}
                        />
                      </label>
                    </div>
                    <button className="danger" onClick={handleResetEncryption}>
                      Reset encryption keys
                    </button>
                  </div>
                </div>
                <div className="divider" />
                <div className="devices">
                  <h3>Devices</h3>
                  {devicesLoading && <p className="muted">Loading devices...</p>}
                  {!devicesLoading && devices.length === 0 && (
                    <p className="muted">No active devices found.</p>
                  )}
                  <div className="device-list">
                    {devices.map((device) => (
                      <div key={device.deviceId} className="device-item">
                        <div>
                          <strong>{device.deviceName}</strong>
                          <div className="muted">
                            {device.ip} • Last seen{" "}
                            {new Date(device.lastSeenAt).toLocaleString()}
                          </div>
                        </div>
                        <div className="row">
                          {device.current ? (
                            <span className="badge">This device</span>
                          ) : (
                            <button
                              className="secondary"
                              onClick={() => handleDeviceLogout(device.deviceId)}
                            >
                              Log out
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                  <button className="danger" onClick={handleLogoutAllDevices}>
                    Log out all devices
                  </button>
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
                    {directStatus && (
                      <p className="presence">
                        <span
                          className={
                            directStatus.online ? "dot online" : "dot offline"
                          }
                        />
                        {directStatus.online
                          ? "Online"
                          : formatLastSeen(directStatus.lastSeen)}
                      </p>
                    )}
                    {typingUsers.length > 0 && (
                      <p className="typing">
                        {typingUsers.join(", ")} typing...
                      </p>
                    )}
                  </div>
                  <div className="thread-actions">
                    {selectedConversation.type === "direct" && (
                      <button
                        className="secondary"
                        onClick={() =>
                          setShowContactPrivacy((prev) => !prev)
                        }
                      >
                        Contact privacy
                      </button>
                    )}
                    {selectedConversation.type !== "direct" && (
                      <button
                        className="secondary"
                        onClick={() => setShowManagePanel((prev) => !prev)}
                      >
                        {showManagePanel ? "Close manage" : "Manage"}
                      </button>
                    )}
                    {selectedConversation.type === "direct" && (
                      <>
                        <button
                          className="secondary"
                          onClick={() => handleStartCall("audio")}
                          disabled={callState.status !== "idle"}
                        >
                          Audio call
                        </button>
                        <button
                          className="secondary"
                          onClick={() => handleStartCall("video")}
                          disabled={callState.status !== "idle"}
                        >
                          Video call
                        </button>
                      </>
                    )}
                    <button className="secondary">Search</button>
                    <button className="secondary">Info</button>
                    <span className="thread-type">
                      {selectedConversation.type}
                    </span>
                  </div>
                </div>

                {callState.status !== "idle" && (
                  <div className="call-panel card">
                    <div className="call-header">
                      <div>
                        <strong>
                          {callState.peerUsername
                            ? `Call with ${callState.peerUsername}`
                            : "Call"}
                        </strong>
                        <p className="muted">
                          {callState.media} • {callState.status}
                        </p>
                      </div>
                      <div className="row">
                        {callState.status === "incoming" && (
                          <>
                            <button onClick={handleAcceptCall}>Accept</button>
                            <button
                              className="secondary"
                              onClick={handleDeclineCall}
                            >
                              Decline
                            </button>
                          </>
                        )}
                        <button
                          className="secondary"
                          onClick={handleToggleMic}
                        >
                          {micMuted ? "Mic off" : "Mic on"}
                        </button>
                        <button className="danger" onClick={handleEndCall}>
                          End call
                        </button>
                      </div>
                    </div>
                    {callError && <p className="note">{callError}</p>}
                    <div
                      className={
                        callState.media === "video"
                          ? "call-videos"
                          : "call-audio"
                      }
                    >
                      <video ref={remoteVideoRef} autoPlay playsInline />
                      <video ref={localVideoRef} autoPlay playsInline muted />
                    </div>
                  </div>
                )}

                {showContactPrivacy && selectedConversation.type === "direct" && (
                  <div className="contact-privacy card">
                    <h4>Per-contact privacy</h4>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={contactPrivacy.hide_online}
                        onChange={(event) =>
                          setContactPrivacy((prev) => ({
                            ...prev,
                            hide_online: event.target.checked
                          }))
                        }
                      />
                      <span>Hide online status</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={contactPrivacy.hide_last_seen}
                        onChange={(event) =>
                          setContactPrivacy((prev) => ({
                            ...prev,
                            hide_last_seen: event.target.checked
                          }))
                        }
                      />
                      <span>Hide last seen</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={contactPrivacy.hide_profile_photo}
                        onChange={(event) =>
                          setContactPrivacy((prev) => ({
                            ...prev,
                            hide_profile_photo: event.target.checked
                          }))
                        }
                      />
                      <span>Hide profile photo</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={contactPrivacy.disable_read_receipts}
                        onChange={(event) =>
                          setContactPrivacy((prev) => ({
                            ...prev,
                            disable_read_receipts: event.target.checked
                          }))
                        }
                      />
                      <span>Disable read receipts</span>
                    </label>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={contactPrivacy.disable_typing_indicator}
                        onChange={(event) =>
                          setContactPrivacy((prev) => ({
                            ...prev,
                            disable_typing_indicator: event.target.checked
                          }))
                        }
                      />
                      <span>Disable typing indicator</span>
                    </label>
                    <div className="row">
                      <button onClick={handleContactPrivacySave}>Save</button>
                      <button
                        className="secondary"
                        onClick={() => setShowContactPrivacy(false)}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                {showManagePanel && selectedConversation.type !== "direct" && (
                  <div className="manage-panel card">
                    <div className="manage-header">
                      <div>
                        <h4>Manage {selectedConversation.type}</h4>
                        <p className="muted">
                          Visibility: {selectedConversation.visibility}
                        </p>
                      </div>
                      <button
                        className="secondary"
                        onClick={() =>
                          refreshRoster(selectedConversation.id).catch(() => undefined)
                        }
                      >
                        Refresh
                      </button>
                    </div>

                    <div className="manage-grid">
                      <div>
                        <h5>Members</h5>
                        {selectedConversation.visibility === "public" ? (
                          <div className="row">
                            <input
                              value={manageUsername}
                              onChange={(event) =>
                                setManageUsername(event.target.value)
                              }
                              placeholder="username"
                            />
                            <button onClick={handleAddMember}>Add</button>
                          </div>
                        ) : (
                          <p className="note">
                            Private chats accept members via invite links.
                          </p>
                        )}
                        <div className="manage-list">
                          {roster.map((member) => (
                            <div key={member.id} className="manage-item">
                              <div>
                                <strong>{member.username}</strong>
                                <span className="muted">
                                  {member.role}
                                </span>
                              </div>
                              <div className="manage-actions">
                                {member.role === "member" && (
                                  <button
                                    className="secondary"
                                    onClick={() =>
                                      handlePromoteMember(member.username)
                                    }
                                  >
                                    Make admin
                                  </button>
                                )}
                                {member.role === "admin" && (
                                  <>
                                    <button
                                      className="secondary"
                                      onClick={() =>
                                        handleDemoteMember(member.username)
                                      }
                                    >
                                      Remove admin
                                    </button>
                                    <label className="toggle inline">
                                      <input
                                        type="checkbox"
                                        checked={Boolean(
                                          member.permissions?.manage_members
                                        )}
                                        onChange={(event) =>
                                          handleUpdateAdminPerms(
                                            member.username,
                                            {
                                              manage_members: event.target.checked,
                                              manage_invites:
                                                member.permissions?.manage_invites
                                            }
                                          )
                                        }
                                      />
                                      <span>Manage members</span>
                                    </label>
                                    <label className="toggle inline">
                                      <input
                                        type="checkbox"
                                        checked={Boolean(
                                          member.permissions?.manage_invites
                                        )}
                                        onChange={(event) =>
                                          handleUpdateAdminPerms(
                                            member.username,
                                            {
                                              manage_members:
                                                member.permissions?.manage_members,
                                              manage_invites: event.target.checked
                                            }
                                          )
                                        }
                                      />
                                      <span>Manage invites</span>
                                    </label>
                                  </>
                                )}
                                {member.role !== "owner" && (
                                  <button
                                    className="danger"
                                    onClick={() =>
                                      handleRemoveMember(member.username)
                                    }
                                  >
                                    Remove
                                  </button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {selectedConversation.visibility === "private" && (
                        <div>
                          <h5>Invite links</h5>
                          <div className="row">
                            <input
                              type="number"
                              value={inviteMaxUses}
                              min={1}
                              onChange={(event) =>
                                setInviteMaxUses(Number(event.target.value))
                              }
                              placeholder="max uses"
                            />
                            <input
                              type="number"
                              value={inviteExpiresMinutes}
                              min={1}
                              onChange={(event) =>
                                setInviteExpiresMinutes(
                                  Number(event.target.value)
                                )
                              }
                              placeholder="expires (minutes)"
                            />
                            <button onClick={handleCreateInvite}>
                              Create link
                            </button>
                          </div>
                          <div className="manage-list">
                            {inviteLinks.map((invite) => (
                              <div key={invite.token} className="manage-item">
                                <div>
                                  <strong>
                                    {`${window.location.origin}/#invite=${invite.token}`}
                                  </strong>
                                  <span className="muted">
                                    Uses {invite.uses}/{invite.maxUses}
                                  </span>
                                  <span className="muted">
                                    Expires{" "}
                                    {invite.expiresAt
                                      ? new Date(invite.expiresAt).toLocaleString()
                                      : "never"}
                                  </span>
                                </div>
                                <div className="manage-actions">
                                  <button
                                    className="secondary"
                                    onClick={() =>
                                      navigator.clipboard
                                        .writeText(
                                          `${window.location.origin}/#invite=${invite.token}`
                                        )
                                        .catch(() => undefined)
                                    }
                                  >
                                    Copy
                                  </button>
                                  <button
                                    className="danger"
                                    onClick={() => handleRevokeInvite(invite.token)}
                                  >
                                    Revoke
                                  </button>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

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
                  {messageItems.length === 0 && (
                    <p className="muted">No messages yet.</p>
                  )}
                  {messageItems.map((item) =>
                    item.kind === "date" ? (
                      <div key={item.id} className="date-separator">
                        <span>{item.label}</span>
                      </div>
                    ) : (
                      <div
                        key={item.message.id}
                        className={
                          item.message.sender === sessionUsername
                            ? "message own"
                            : "message"
                        }
                      >
                        <div className="meta">
                          <span>{item.message.sender}</span>
                            <span className="meta-right">
                            <span title={new Date(item.message.createdAt).toLocaleString()}>
                              {formatTime(item.message.createdAt)} · {formatDateLabel(item.message.createdAt)}
                            </span>
                            {item.message.sender === sessionUsername && (
                              <span className="tick">
                                {getStatusMark(item.message.groupId)}
                              </span>
                            )}
                          </span>
                        </div>
                        {item.message.payload.text && (
                          <div className="text">{item.message.payload.text}</div>
                        )}
                        {item.message.payload.attachments.map((attachment, index) => (
                          <div
                            key={`${item.message.id}-${index}`}
                            className="attachment"
                          >
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
                                  const key = `${item.message.id}-${index}`;
                                  setAudioDurations((prev) => ({
                                    ...prev,
                                    [key]: event.currentTarget.duration
                                  }));
                                }}
                              />
                            )}
                            {attachment.kind === "audio" &&
                              audioDurations[`${item.message.id}-${index}`] && (
                                <div className="file-name">
                                  {attachment.name} - {audioDurations[
                                    `${item.message.id}-${index}`
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
                              pinnedIds.has(String(item.message.id))
                                ? "action active"
                                : "action"
                            }
                            onClick={() => handleTogglePinned(String(item.message.id))}
                          >
                            Pin
                          </button>
                          <button
                            className={
                              starredIds.has(String(item.message.id))
                                ? "action active"
                                : "action"
                            }
                            onClick={() =>
                              handleToggleStarred(String(item.message.id))
                            }
                          >
                            Star
                          </button>
                          <button
                            className="action danger"
                            onClick={() => handleDelete(item.message)}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    )
                  )}
                  <div ref={messageEndRef} />
                </div>

                <div className="composer">
                  <textarea
                    value={messageText}
                    onChange={(event) => {
                      setMessageText(event.target.value);
                      handleTyping();
                    }}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" && !event.shiftKey) {
                        event.preventDefault();
                        handleSend();
                      }
                    }}
                    placeholder="Type a message (emoji supported)"
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




