import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import crypto from "node:crypto";
import {
  clearUserTwoFactor,
  createAdminSession,
  createConversation,
  createMessage,
  createSession,
  createUser,
  deleteConversation,
  deleteMessageForAll,
  deleteMessageForSelf,
  deleteUserAndData,
  addMember,
  createInvite,
  findAdminSession,
  findSession,
  findUserById,
  findUserByPhone,
  findUserByUsername,
  findUserKeyBundleBySession,
  findInviteByToken,
  getMembership,
  getAdminCredentials,
  getConversationById,
  isMember,
  listMemberships,
  listInvites,
  listConversations,
  listConversationsForUser,
  listMembers,
  listSentStatuses,
  listSessionsForUser,
  listUserKeyBundles,
  listUsers,
  markDelivered,
  markRead,
  popOneTimePreKey,
  pollMessages,
  redeemInvite,
  removeSessionForDevice,
  removeSessionsForUser,
  removeMember,
  revokeInvite,
  setUserKeyBundle,
  updateMemberRole,
  updateAdminPassword,
  updatePrivacyOverride,
  updateSessionLastSeen,
  updateUserAccount,
  updateUserFlags,
  updateUserPassword,
  type ConversationType
} from "./db.js";
import { readUserProfile, updateUserProfile } from "./profiles.js";

const server = Fastify({ logger: true, bodyLimit: 20 * 1024 * 1024 });

if (!process.env.APP_MASTER_KEY) {
  throw new Error("APP_MASTER_KEY is required.");
}

await server.register(cors, {
  origin: true,
  methods: ["GET", "POST"]
});

await server.register(rateLimit, {
  global: true,
  max: 300,
  timeWindow: "1 minute"
});

server.addHook("onResponse", (request, reply, done) => {
  server.log.info(
    {
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      responseTime: reply.getResponseTime()
    },
    "request"
  );
  done();
});

server.addHook("preHandler", (request, reply, done) => {
  const authHeader = request.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    updateSessionLastSeen(token);
  }
  done();
});

const typingState = new Map<
  number,
  Map<number, { username: string; lastTypedAt: number }>
>();

const TYPING_TTL_MS = 6000;
const USERNAME_RE = /^[a-zA-Z0-9_]{5,32}$/;
const PHONE_RE = /^\+?\d{10,15}$/;
const MAX_MESSAGE_ID = 64;
const MAX_CIPHERTEXT = 16 * 1024 * 1024;
const MAX_NONCE = 512;
const MAX_GROUP_NAME = 40;
const MAX_BIO = 160;
const MAX_AVATAR = 3 * 1024 * 1024;
const MAX_KEY_FIELD = 5120;
const MAX_PREKEYS = 100;
const MAX_DEVICES = 3;
const ONLINE_WINDOW_MS = 60 * 1000;
const MAX_PAYLOADS = 200;
const CALL_EVENT_TTL_MS = 5 * 60 * 1000;
const MAX_CALL_EVENTS = 1000;

type CallEvent = {
  id: number;
  callId: string;
  targetUserId: number;
  targetDeviceId: string;
  type: "offer" | "answer" | "ice" | "end";
  payload: Record<string, unknown>;
  createdAt: number;
};

type CallSession = {
  callId: string;
  conversationId: number;
  fromUserId: number;
  fromUsername: string;
  fromDeviceId: string;
  toUserId: number;
  toUsername: string;
  toDeviceId: string;
  media: "audio" | "video";
  createdAt: number;
};

const callEvents: CallEvent[] = [];
const callSessions = new Map<string, CallSession>();

function pushCallEvent(event: CallEvent): void {
  callEvents.push(event);
  const cutoff = Date.now() - CALL_EVENT_TTL_MS;
  while (callEvents.length > MAX_CALL_EVENTS) {
    callEvents.shift();
  }
  while (callEvents.length && callEvents[0].createdAt < cutoff) {
    callEvents.shift();
  }
}

function generateToken(): string {
  return crypto.randomBytes(24).toString("hex");
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 32).toString("hex");
}

function getAuthSession(authHeader?: string): {
  userId: number;
  token: string;
  deviceId: string;
} | null {
  if (!authHeader) {
    return null;
  }
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return null;
  }
  const session = findSession(parts[1]);
  if (!session) {
    return null;
  }
  return {
    userId: session.user_id,
    token: session.token,
    deviceId: session.device_id || "legacy"
  };
}

function getAdminToken(authHeader?: string): string | null {
  if (!authHeader) {
    return null;
  }
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return null;
  }
  return parts[1];
}

server.get("/health", async () => ({ ok: true }));

server.post(
  "/api/auth/signup",
  { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const body = request.body as {
    username?: string;
    password?: string;
    phone?: string;
    firstName?: string;
    lastName?: string;
    publicKey?: string;
    deviceId?: string;
    deviceName?: string;
    deviceInfo?: {
      userAgent?: string;
      platform?: string;
      language?: string;
      deviceModel?: string;
    };
  };
  const username = body.username?.trim();
  const password = body.password?.trim();
  const phone = body.phone?.trim();
  const firstName = body.firstName?.trim();
  const lastName = body.lastName?.trim();
  const publicKey = body.publicKey?.trim();
  const deviceId = body.deviceId?.trim();
  const deviceName = body.deviceName?.trim() || "Unknown device";

  if (!phone || !firstName || !lastName || !username || !publicKey || !deviceId) {
    return reply
      .status(400)
      .send({ error: "phone, firstName, lastName, username, publicKey, deviceId required" });
  }

  if (!PHONE_RE.test(phone)) {
    return reply.status(400).send({ error: "invalid phone" });
  }

  if (!USERNAME_RE.test(username)) {
    return reply.status(400).send({ error: "invalid username" });
  }

  const existing = findUserByUsername(username);
  if (existing) {
    return reply.status(409).send({ error: "username already exists" });
  }
  const existingPhone = findUserByPhone(phone);
  if (existingPhone) {
    return reply.status(409).send({ error: "phone already exists" });
  }

  let salt = "";
  let passwordHash = "";
  const twoFactorEnabled = Boolean(password);
  if (password) {
    if (password.length < 6) {
      return reply.status(400).send({ error: "password too short" });
    }
    salt = crypto.randomBytes(16).toString("hex");
    passwordHash = hashPassword(password, salt);
  }

  const user = createUser(
    username,
    phone,
    firstName,
    lastName,
    passwordHash,
    salt,
    twoFactorEnabled,
    publicKey
  );
  const token = generateToken();
  const existingSessions = listSessionsForUser(user.id);
  const deviceCount = existingSessions.reduce(
    (count, session) =>
      session.device_id === deviceId ? count : count + 1,
    0
  );
  if (deviceCount >= MAX_DEVICES) {
    return reply.status(403).send({ error: "device limit reached" });
  }
  createSession(token, user.id, deviceId, deviceName, request.ip);

  updateUserProfile(user.username, request.ip, body.deviceInfo || {});

  return {
    userId: user.id,
    token,
    username: user.username,
    phone: user.phone,
    firstName: user.first_name,
    lastName: user.last_name,
    banned: user.banned,
    canSend: user.can_send,
    canCreate: user.can_create,
    avatar: user.avatar,
    bio: user.bio,
    profilePublic: user.profile_public,
    allowDirect: user.allow_direct,
    allowGroupInvite: user.allow_group_invite,
    privacy: user.privacy_defaults,
    twoFactorEnabled: user.two_factor_enabled,
    newDevice: true
  };
});

server.post(
  "/api/auth/login",
  { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const body = request.body as {
    phone?: string;
    password?: string;
    deviceId?: string;
    deviceName?: string;
    deviceInfo?: {
      userAgent?: string;
      platform?: string;
      language?: string;
      deviceModel?: string;
    };
  };
  const phone = body.phone?.trim();
  const password = body.password?.trim();
  const deviceId = body.deviceId?.trim();
  const deviceName = body.deviceName?.trim() || "Unknown device";

  if (!phone || !deviceId) {
    return reply.status(400).send({ error: "phone and deviceId required" });
  }

  const user = findUserByPhone(phone);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }

  if (user.two_factor_enabled) {
    if (!password) {
      return reply.status(401).send({ error: "2fa required" });
    }
    const passwordHash = hashPassword(password, user.password_salt);
    if (
      !crypto.timingSafeEqual(
        Buffer.from(passwordHash, "hex"),
        Buffer.from(user.password_hash, "hex")
      )
    ) {
      return reply.status(401).send({ error: "invalid credentials" });
    }
  }

  const token = generateToken();
  const sessions = listSessionsForUser(user.id);
  const hasDevice = sessions.some((session) => session.device_id === deviceId);
  const deviceCount = sessions.reduce(
    (count, session) =>
      session.device_id === deviceId ? count : count + 1,
    0
  );
  if (!hasDevice && deviceCount >= MAX_DEVICES) {
    return reply.status(403).send({ error: "device limit reached" });
  }
  createSession(token, user.id, deviceId, deviceName, request.ip);

  updateUserProfile(user.username, request.ip, body.deviceInfo || {});

  return {
    userId: user.id,
    token,
    username: user.username,
    phone: user.phone,
    firstName: user.first_name,
    lastName: user.last_name,
    banned: user.banned,
    canSend: user.can_send,
    canCreate: user.can_create,
    avatar: user.avatar,
    bio: user.bio,
    profilePublic: user.profile_public,
    allowDirect: user.allow_direct,
    allowGroupInvite: user.allow_group_invite,
    privacy: user.privacy_defaults,
    twoFactorEnabled: user.two_factor_enabled,
    newDevice: !hasDevice
  };
});

server.get("/api/users/:username/public-key", async (request, reply) => {
  const { username } = request.params as { username: string };
  const user = findUserByUsername(username);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }
  return { username: user.username, publicKey: user.public_key };
});

server.post("/api/auth/2fa/enable", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const body = request.body as { password?: string };
  const password = body.password?.trim();
  if (!password || password.length < 6) {
    return reply.status(400).send({ error: "password too short" });
  }
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt);
  const ok = updateUserPassword(session.userId, passwordHash, salt);
  if (!ok) {
    return reply.status(404).send({ error: "user not found" });
  }
  return { ok: true };
});

server.post("/api/auth/2fa/disable", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const body = request.body as { password?: string };
  const password = body.password?.trim();
  const user = findUserById(session.userId);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }
  if (user.two_factor_enabled) {
    if (!password) {
      return reply.status(400).send({ error: "password required" });
    }
    const passwordHash = hashPassword(password, user.password_salt);
    if (
      !crypto.timingSafeEqual(
        Buffer.from(passwordHash, "hex"),
        Buffer.from(user.password_hash, "hex")
      )
    ) {
      return reply.status(401).send({ error: "invalid credentials" });
    }
  }
  const ok = clearUserTwoFactor(session.userId);
  if (!ok) {
    return reply.status(404).send({ error: "user not found" });
  }
  return { ok: true };
});

server.get("/api/users/:username/profile", async (request, reply) => {
  const { username } = request.params as { username: string };
  const user = findUserByUsername(username);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }
  if (!user.profile_public) {
    return reply.status(403).send({ error: "profile not public" });
  }
  return {
    username: user.username,
    avatar: user.privacy_defaults.hide_profile_photo ? null : user.avatar,
    bio: user.bio
  };
});

server.get("/api/profile", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const user = findUserById(session.userId);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }
  return {
    username: user.username,
    phone: user.phone,
    firstName: user.first_name,
    lastName: user.last_name,
    avatar: user.avatar,
    bio: user.bio,
    profilePublic: user.profile_public,
    allowDirect: user.allow_direct,
    allowGroupInvite: user.allow_group_invite,
    privacy: user.privacy_defaults,
    twoFactorEnabled: user.two_factor_enabled
  };
});

server.post("/api/profile", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const body = request.body as {
    avatar?: string | null;
    bio?: string;
    profilePublic?: boolean;
    allowDirect?: boolean;
    allowGroupInvite?: boolean;
    privacy?: Partial<{
      hide_online: boolean;
      hide_last_seen: boolean;
      hide_profile_photo: boolean;
      disable_read_receipts: boolean;
      disable_typing_indicator: boolean;
    }>;
  };

  if (typeof body.bio === "string" && body.bio.length > MAX_BIO) {
    return reply.status(400).send({ error: "bio too long" });
  }

  if (typeof body.avatar === "string") {
    if (!body.avatar.startsWith("data:image/")) {
      return reply.status(400).send({ error: "invalid avatar format" });
    }
    if (body.avatar.length > MAX_AVATAR) {
      return reply.status(400).send({ error: "avatar too large" });
    }
  }

  const updated = updateUserAccount(session.userId, {
    avatar:
      typeof body.avatar === "string" || body.avatar === null
        ? body.avatar
        : undefined,
    bio: typeof body.bio === "string" ? body.bio : undefined,
    profile_public: typeof body.profilePublic === "boolean" ? body.profilePublic : undefined,
    allow_direct: typeof body.allowDirect === "boolean" ? body.allowDirect : undefined,
    allow_group_invite: typeof body.allowGroupInvite === "boolean" ? body.allowGroupInvite : undefined,
    privacy_defaults: body.privacy
  });

  if (!updated) {
    return reply.status(404).send({ error: "user not found" });
  }

  return { ok: true };
});

server.post("/api/privacy/contact", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const body = request.body as {
    username?: string;
    privacy?: Partial<{
      hide_online: boolean;
      hide_last_seen: boolean;
      hide_profile_photo: boolean;
      disable_read_receipts: boolean;
      disable_typing_indicator: boolean;
    }>;
  };
  const target = body.username?.trim();
  if (!target || !body.privacy) {
    return reply.status(400).send({ error: "username and privacy required" });
  }
  const updated = updatePrivacyOverride(session.userId, target, body.privacy);
  if (!updated) {
    return reply.status(404).send({ error: "user not found" });
  }
  return { ok: true };
});

server.get("/api/users/:username/profile-private", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const { username } = request.params as { username: string };
  const user = findUserByUsername(username);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }
  const viewer = findUserById(session.userId);
  const override = viewer
    ? user.privacy_overrides[viewer.username] || {}
    : {};
  const privacy = { ...user.privacy_defaults, ...override };
  return {
    username: user.username,
    avatar: privacy.hide_profile_photo ? null : user.avatar,
    bio: user.bio
  };
});

server.get("/api/users/:username/status", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const { username } = request.params as { username: string };
  const user = findUserByUsername(username);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }
  const viewer = findUserById(session.userId);
  const override = viewer
    ? user.privacy_overrides[viewer.username] || {}
    : {};
  const privacy = { ...user.privacy_defaults, ...override };
  if (privacy.hide_online && privacy.hide_last_seen) {
    return { online: false, lastSeen: null };
  }
  const sessions = listSessionsForUser(user.id);
  const latest = sessions
    .map((row) => row.last_seen_at)
    .sort((a, b) => b - a)[0];
  const online = latest ? Date.now() - latest < ONLINE_WINDOW_MS : false;
  return {
    online: privacy.hide_online ? false : online,
    lastSeen: privacy.hide_last_seen ? null : latest ?? null
  };
});

server.post("/api/keys/publish", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as {
    identityKey?: string;
    registrationId?: number;
    deviceId?: number;
    sessionDeviceId?: string;
    signedPreKeyId?: number;
    signedPreKey?: string;
    signedPreKeySig?: string;
    oneTimePreKeys?: Array<{ id: number; key: string }>;
  };

  if (
    !body.identityKey ||
    typeof body.registrationId !== "number" ||
    typeof body.deviceId !== "number" ||
    !body.sessionDeviceId ||
    !body.signedPreKey ||
    !body.signedPreKeySig ||
    typeof body.signedPreKeyId !== "number"
  ) {
    return reply.status(400).send({ error: "invalid key bundle" });
  }

  if (
    body.identityKey.length > MAX_KEY_FIELD ||
    body.signedPreKey.length > MAX_KEY_FIELD ||
    body.signedPreKeySig.length > MAX_KEY_FIELD
  ) {
    return reply.status(400).send({ error: "key bundle too large" });
  }

  const oneTimePreKeys = Array.isArray(body.oneTimePreKeys)
    ? body.oneTimePreKeys.slice(0, MAX_PREKEYS)
    : [];

  setUserKeyBundle(session.userId, {
    session_device_id: body.sessionDeviceId,
    registration_id: body.registrationId,
    device_id: body.deviceId,
    identity_key: body.identityKey,
    signed_prekey_id: body.signedPreKeyId,
    signed_prekey: body.signedPreKey,
    signed_prekey_sig: body.signedPreKeySig,
    one_time_prekeys: oneTimePreKeys.map((entry) => ({
      id: entry.id,
      key: entry.key
    }))
  });

  return { ok: true };
});

server.get("/api/keys/bundle/:username", async (request, reply) => {
  const { username } = request.params as { username: string };
  const user = findUserByUsername(username);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }

  const bundles = listUserKeyBundles(user.id);
  if (bundles.length === 0) {
    return reply.status(404).send({ error: "keys not available" });
  }

  const devices = bundles.map((bundle) => ({
    registrationId: bundle.registration_id ?? 1,
    deviceId: bundle.device_id ?? 1,
    sessionDeviceId: bundle.session_device_id,
    identityKey: bundle.identity_key,
    signedPreKeyId: bundle.signed_prekey_id,
    signedPreKey: bundle.signed_prekey,
    signedPreKeySig: bundle.signed_prekey_sig,
    oneTimePreKey: popOneTimePreKey(user.id, bundle.session_device_id)
  }));

  return { username: user.username, devices };
});

server.get("/api/conversations", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const conversations = listConversationsForUser(session.userId).map((conv) => {
    const members = listMembers(conv.id).map((member) => ({
      username: member.username,
      publicKey: member.public_key
    }));
    return {
      id: conv.id,
      type: conv.type,
      name: conv.name,
      ownerId: conv.owner_id,
      visibility: conv.visibility,
      members
    };
  });

  return { conversations };
});

server.post("/api/conversations", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const user = findUserById(session.userId);
  if (!user || user.banned) {
    return reply.status(403).send({ error: "user banned" });
  }
  if (!user.can_create) {
    return reply.status(403).send({ error: "user cannot create" });
  }

  const body = request.body as {
    type?: ConversationType;
    name?: string;
    members?: string[];
    visibility?: "public" | "private";
  };

  const type = body.type;
  const name = body.name?.trim() || null;
  const members = (body.members || []).map((member) => member.trim());
  const visibility = body.visibility === "private" ? "private" : "public";

  if (!type || !["direct", "group", "channel"].includes(type)) {
    return reply.status(400).send({ error: "invalid type" });
  }

  if (type !== "direct" && !name) {
    return reply.status(400).send({ error: "name required" });
  }

  if (name && name.length > MAX_GROUP_NAME) {
    return reply.status(400).send({ error: "name too long" });
  }

  if (type === "direct" && members.length !== 1) {
    return reply
      .status(400)
      .send({ error: "direct requires exactly one member" });
  }

  const uniqueMembers = Array.from(new Set(members)).filter(Boolean);
  const memberUsers = uniqueMembers
    .map((memberUsername) => findUserByUsername(memberUsername))
    .filter(Boolean) as Array<{ id: number; username: string; banned: boolean; allow_direct: boolean; allow_group_invite: boolean }>;

  if (memberUsers.length !== uniqueMembers.length) {
    return reply.status(404).send({ error: "one or more users not found" });
  }

  const blockedMember = memberUsers.find((member) => member.banned);
  if (blockedMember) {
    return reply.status(403).send({ error: "member banned" });
  }

  if (type === "direct" && memberUsers.some((member) => !member.allow_direct)) {
    return reply.status(403).send({ error: "member disabled direct chats" });
  }

  if (
    type !== "direct" &&
    memberUsers.some((member) => !member.allow_group_invite)
  ) {
    return reply.status(403).send({ error: "member disabled group invites" });
  }

  const conversation = createConversation(
    type,
    name,
    session.userId,
    memberUsers.map((member) => member.id),
    type === "direct" ? "private" : visibility
  );

  return { conversationId: conversation.id };
});

server.get("/api/conversations/:id/members", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }
  if (conversation.visibility === "private") {
    return reply.status(403).send({ error: "private chat requires invite link" });
  }

  if (!isMember(conversationId, session.userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  const members = listMembers(conversationId).map((member) => ({
    username: member.username,
    publicKey: member.public_key
  }));

  return { members };
});

server.get("/api/conversations/:id/roster", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }
  if (!isMember(conversationId, session.userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  const roster = listMemberships(conversationId).map((entry) => ({
    id: entry.user.id,
    username: entry.user.username,
    role: entry.role,
    permissions: entry.permissions || null
  }));

  return { members: roster, visibility: conversation.visibility };
});

server.post("/api/conversations/:id/members/add", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  const membership = getMembership(conversationId, session.userId);
  if (!membership) {
    return reply.status(403).send({ error: "forbidden" });
  }
  const canManage =
    membership.role === "owner" ||
    (membership.role === "admin" &&
      membership.permissions?.manage_members);
  if (!canManage) {
    return reply.status(403).send({ error: "insufficient permissions" });
  }

  const body = request.body as { username?: string };
  const targetUsername = body.username?.trim();
  if (!targetUsername) {
    return reply.status(400).send({ error: "username required" });
  }
  const target = findUserByUsername(targetUsername);
  if (!target) {
    return reply.status(404).send({ error: "user not found" });
  }
  if (target.banned) {
    return reply.status(403).send({ error: "user banned" });
  }

  if (conversation.type !== "direct" && !target.allow_group_invite) {
    return reply.status(403).send({ error: "user disabled group invites" });
  }

  addMember(conversationId, target.id, "member");
  return { ok: true };
});

server.post("/api/conversations/:id/members/remove", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  const membership = getMembership(conversationId, session.userId);
  if (!membership) {
    return reply.status(403).send({ error: "forbidden" });
  }
  const canManage =
    membership.role === "owner" ||
    (membership.role === "admin" &&
      membership.permissions?.manage_members);
  if (!canManage) {
    return reply.status(403).send({ error: "insufficient permissions" });
  }

  const body = request.body as { username?: string };
  const targetUsername = body.username?.trim();
  if (!targetUsername) {
    return reply.status(400).send({ error: "username required" });
  }
  const target = findUserByUsername(targetUsername);
  if (!target) {
    return reply.status(404).send({ error: "user not found" });
  }
  if (target.id === conversation.owner_id) {
    return reply.status(403).send({ error: "cannot remove owner" });
  }

  const ok = removeMember(conversationId, target.id);
  if (!ok) {
    return reply.status(404).send({ error: "member not found" });
  }
  return { ok: true };
});

server.post("/api/conversations/:id/role", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  if (conversation.owner_id !== session.userId) {
    return reply.status(403).send({ error: "owner only" });
  }

  const body = request.body as {
    username?: string;
    role?: "admin" | "member";
    permissions?: { manage_members?: boolean; manage_invites?: boolean };
  };
  const targetUsername = body.username?.trim();
  const role = body.role;
  if (!targetUsername || !role) {
    return reply.status(400).send({ error: "username and role required" });
  }
  const target = findUserByUsername(targetUsername);
  if (!target) {
    return reply.status(404).send({ error: "user not found" });
  }
  if (target.id === conversation.owner_id) {
    return reply.status(400).send({ error: "owner role cannot be changed" });
  }

  const updated = updateMemberRole(
    conversationId,
    target.id,
    role,
    body.permissions
  );
  if (!updated) {
    return reply.status(404).send({ error: "member not found" });
  }

  return { ok: true };
});

server.post("/api/conversations/:id/invites", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  const membership = getMembership(conversationId, session.userId);
  if (!membership) {
    return reply.status(403).send({ error: "forbidden" });
  }
  const canInvite =
    membership.role === "owner" ||
    (membership.role === "admin" &&
      membership.permissions?.manage_invites);
  if (!canInvite) {
    return reply.status(403).send({ error: "insufficient permissions" });
  }

  const body = request.body as {
    maxUses?: number;
    expiresInMinutes?: number;
  };
  const maxUses =
    typeof body.maxUses === "number" && body.maxUses > 0
      ? Math.min(body.maxUses, 1000)
      : 1;
  const expiresInMinutes =
    typeof body.expiresInMinutes === "number" && body.expiresInMinutes > 0
      ? Math.min(body.expiresInMinutes, 24 * 60)
      : 60;
  const expiresAt = Date.now() + expiresInMinutes * 60 * 1000;

  const invite = createInvite(
    conversationId,
    session.userId,
    maxUses,
    expiresAt
  );
  return { token: invite.token, expiresAt: invite.expires_at, maxUses };
});

server.get("/api/conversations/:id/invites", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  const membership = getMembership(conversationId, session.userId);
  if (!membership) {
    return reply.status(403).send({ error: "forbidden" });
  }
  const canInvite =
    membership.role === "owner" ||
    (membership.role === "admin" &&
      membership.permissions?.manage_invites);
  if (!canInvite) {
    return reply.status(403).send({ error: "insufficient permissions" });
  }

  const invites = listInvites(conversationId).map((invite) => ({
    token: invite.token,
    maxUses: invite.max_uses,
    uses: invite.uses,
    expiresAt: invite.expires_at,
    revoked: invite.revoked,
    createdAt: invite.created_at
  }));

  return { invites };
});

server.post("/api/conversations/invites/revoke", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as { token?: string };
  const token = body.token?.trim();
  if (!token) {
    return reply.status(400).send({ error: "token required" });
  }

  const invite = findInviteByToken(token);
  if (!invite) {
    return reply.status(404).send({ error: "invite not found" });
  }

  const membership = getMembership(invite.conversation_id, session.userId);
  if (!membership) {
    return reply.status(403).send({ error: "forbidden" });
  }
  const canInvite =
    membership.role === "owner" ||
    (membership.role === "admin" &&
      membership.permissions?.manage_invites);
  if (!canInvite) {
    return reply.status(403).send({ error: "insufficient permissions" });
  }

  const ok = revokeInvite(token);
  if (!ok) {
    return reply.status(404).send({ error: "invite not found" });
  }

  return { ok: true };
});

server.post("/api/invites/redeem", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as { token?: string };
  const token = body.token?.trim();
  if (!token) {
    return reply.status(400).send({ error: "token required" });
  }

  const invite = redeemInvite(token, session.userId);
  if (!invite) {
    return reply.status(400).send({ error: "invalid or expired invite" });
  }

  return { ok: true, conversationId: invite.conversation_id };
});

server.post(
  "/api/messages/send",
  { config: { rateLimit: { max: 300, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const user = findUserById(session.userId);
  if (!user || user.banned) {
    return reply.status(403).send({ error: "user banned" });
  }

  const body = request.body as {
    conversationId?: number;
    payloads?: Array<{
      messageId?: string;
      toUsername?: string;
      toDeviceId?: string;
      ciphertext?: string;
      nonce?: string;
    }>;
  };

  const conversationId = body.conversationId;
  const payloads = body.payloads || [];

  if (!conversationId || payloads.length === 0) {
    return reply
      .status(400)
      .send({ error: "conversationId and payloads required" });
  }

  if (payloads.length > MAX_PAYLOADS) {
    return reply.status(400).send({ error: "too many payloads" });
  }

  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  if (!isMember(conversationId, session.userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  if (conversation.type === "channel") {
    const membership = getMembership(conversationId, session.userId);
    if (!membership || (membership.role !== "owner" && membership.role !== "admin")) {
      return reply.status(403).send({ error: "channel is read-only" });
    }
  }

  const members = listMembers(conversationId);
  const memberUsernames = new Set(members.map((member) => member.username));
  const senderBundle = findUserKeyBundleBySession(
    session.userId,
    session.deviceId
  );
  const senderSignalDeviceId = String(senderBundle?.device_id ?? 1);

  for (const payload of payloads) {
    const messageId = payload.messageId?.trim();
    const toUsername = payload.toUsername?.trim();
    const toDeviceId = payload.toDeviceId?.trim();
    const ciphertext = payload.ciphertext?.trim();
    const nonce = payload.nonce?.trim();

    if (!messageId || !toUsername || !toDeviceId || !ciphertext || !nonce) {
      return reply
        .status(400)
        .send({ error: "messageId, toUsername, toDeviceId, ciphertext, nonce required" });
    }

    if (messageId.length > MAX_MESSAGE_ID) {
      return reply.status(400).send({ error: "messageId too long" });
    }

    if (ciphertext.length > MAX_CIPHERTEXT) {
      return reply.status(400).send({ error: "message too large" });
    }

    if (nonce.length > MAX_NONCE) {
      return reply.status(400).send({ error: "nonce too large" });
    }

    if (!memberUsernames.has(toUsername)) {
      return reply.status(400).send({ error: "recipient not in conversation" });
    }

    const recipient = findUserByUsername(toUsername);
    if (!recipient) {
      return reply.status(404).send({ error: "recipient not found" });
    }

    const isPlaintext = nonce.startsWith("plain:");
    if (isPlaintext && toDeviceId === "*") {
      const recipientSessions = listSessionsForUser(recipient.id);
      if (recipientSessions.length === 0) {
        return reply
          .status(400)
          .send({ error: "recipient has no active sessions" });
      }
      for (const sessionRow of recipientSessions) {
        createMessage(
          messageId,
          conversationId,
          session.userId,
          senderSignalDeviceId,
          recipient.id,
          sessionRow.device_id,
          ciphertext,
          nonce,
          ciphertext.length
        );
      }
      continue;
    }

    createMessage(
      messageId,
      conversationId,
      session.userId,
      senderSignalDeviceId,
      recipient.id,
      toDeviceId,
      ciphertext,
      nonce,
      ciphertext.length
    );
  }

  return { ok: true };
});

server.get(
  "/api/messages/poll",
  { config: { rateLimit: { max: 180, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const query = request.query as { since?: string; limit?: string };
  const sinceRaw = query.since;
  const since = sinceRaw ? Number(sinceRaw) : 0;
  const limitRaw = query.limit ? Number(query.limit) : 50;
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 100) : 50;

  const messages = pollMessages(
    session.userId,
    session.deviceId,
    Number.isFinite(since) ? since : 0,
    limit
  );
  markDelivered(messages.map((msg) => msg.id));

  return { messages };
});

server.get(
  "/api/messages/sent",
  { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const query = request.query as { since?: string; limit?: string };
  const sinceRaw = query.since;
  const since = sinceRaw ? Number(sinceRaw) : 0;
  const limitRaw = query.limit ? Number(query.limit) : 50;
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 100) : 50;

  const statuses = listSentStatuses(
    session.userId,
    Number.isFinite(since) ? since : 0,
    limit
  );
  return { statuses };
});

server.post("/api/messages/read", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as { conversationId?: number };
  if (!body.conversationId) {
    return reply.status(400).send({ error: "conversationId required" });
  }

  if (!isMember(body.conversationId, session.userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  const user = findUserById(session.userId);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }
  if (user.privacy_defaults.disable_read_receipts) {
    return { ok: true };
  }
  const conversation = getConversationById(body.conversationId);
  if (conversation?.type === "direct") {
    const members = listMembers(body.conversationId);
    const other = members.find((member) => member.id !== session.userId);
    if (other) {
      const override = user.privacy_overrides[other.username];
      if (override?.disable_read_receipts) {
        return { ok: true };
      }
    }
  }
  markRead(body.conversationId, session.userId);
  return { ok: true };
});

server.post("/api/messages/delete", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as {
    scope?: "self" | "all";
    groupId?: string;
    messageId?: number;
  };

  if (body.scope === "all") {
    if (!body.groupId) {
      return reply.status(400).send({ error: "groupId required" });
    }
    const updated = deleteMessageForAll(body.groupId, session.userId);
    if (!updated) {
      return reply.status(403).send({ error: "cannot delete this message" });
    }
    return { ok: true };
  }

  if (body.scope === "self") {
    if (!body.messageId) {
      return reply.status(400).send({ error: "messageId required" });
    }
    deleteMessageForSelf(body.messageId, session.userId);
    return { ok: true };
  }

  return reply.status(400).send({ error: "invalid scope" });
});

server.post(
  "/api/typing",
  { config: { rateLimit: { max: 180, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as { conversationId?: number; isTyping?: boolean };
  if (!body.conversationId) {
    return reply.status(400).send({ error: "conversationId required" });
  }

  if (!isMember(body.conversationId, session.userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  if (!typingState.has(body.conversationId)) {
    typingState.set(body.conversationId, new Map());
  }

  const conversationTyping = typingState.get(body.conversationId)!;
  if (!body.isTyping) {
    conversationTyping.delete(session.userId);
    return { ok: true };
  }

  const user = findUserById(session.userId);
  if (user?.privacy_defaults.disable_typing_indicator) {
    return { ok: true };
  }
  conversationTyping.set(session.userId, {
    username: user?.username ?? "unknown",
    lastTypedAt: Date.now()
  });

  return { ok: true };
});

server.get(
  "/api/typing",
  { config: { rateLimit: { max: 180, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const conversationId = Number(
    (request.query as { conversationId?: string }).conversationId
  );
  if (!conversationId) {
    return reply.status(400).send({ error: "conversationId required" });
  }

  if (!isMember(conversationId, session.userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  const now = Date.now();
  const conversationTyping = typingState.get(conversationId);
  if (!conversationTyping) {
    return { users: [] };
  }

  const viewer = findUserById(session.userId);
  const users = Array.from(conversationTyping.entries())
    .filter(([id, entry]) => id !== session.userId && now - entry.lastTypedAt < TYPING_TTL_MS)
    .filter(([id]) => {
      const typingUser = findUserById(id);
      if (!typingUser) {
        return false;
      }
      const override = viewer
        ? typingUser.privacy_overrides[viewer.username] || {}
        : {};
      const privacy = { ...typingUser.privacy_defaults, ...override };
      return !privacy.disable_typing_indicator;
    })
    .map(([, entry]) => entry.username);

  return { users };
});

server.post(
  "/api/calls/start",
  { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as {
    callId?: string;
    conversationId?: number;
    toUsername?: string;
    toDeviceId?: string;
    media?: "audio" | "video";
    offer?: string;
  };

  const callId = body.callId?.trim();
  const conversationId = body.conversationId;
  const toUsername = body.toUsername?.trim();
  const toDeviceId = body.toDeviceId?.trim();
  const media = body.media === "video" ? "video" : "audio";
  const offer = body.offer?.trim();

  if (!callId || !conversationId || !toUsername || !toDeviceId || !offer) {
    return reply.status(400).send({ error: "invalid call payload" });
  }

  const conversation = getConversationById(conversationId);
  if (!conversation || conversation.type !== "direct") {
    return reply.status(400).send({ error: "direct conversation required" });
  }

  if (!isMember(conversationId, session.userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  const recipient = findUserByUsername(toUsername);
  if (!recipient) {
    return reply.status(404).send({ error: "recipient not found" });
  }

  const caller = findUserById(session.userId);
  if (!caller) {
    return reply.status(404).send({ error: "user not found" });
  }

  const callSession: CallSession = {
    callId,
    conversationId,
    fromUserId: caller.id,
    fromUsername: caller.username,
    fromDeviceId: session.deviceId,
    toUserId: recipient.id,
    toUsername: recipient.username,
    toDeviceId,
    media,
    createdAt: Date.now()
  };
  callSessions.set(callId, callSession);

  pushCallEvent({
    id: Date.now(),
    callId,
    targetUserId: recipient.id,
    targetDeviceId: toDeviceId,
    type: "offer",
    payload: {
      fromUsername: caller.username,
      fromDeviceId: session.deviceId,
      media,
      offer,
      conversationId
    },
    createdAt: Date.now()
  });

  return { ok: true };
});

server.post(
  "/api/calls/answer",
  { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as { callId?: string; answer?: string };
  const callId = body.callId?.trim();
  const answer = body.answer?.trim();
  if (!callId || !answer) {
    return reply.status(400).send({ error: "invalid answer payload" });
  }

  const call = callSessions.get(callId);
  if (!call || call.toUserId !== session.userId) {
    return reply.status(404).send({ error: "call not found" });
  }

  pushCallEvent({
    id: Date.now(),
    callId,
    targetUserId: call.fromUserId,
    targetDeviceId: call.fromDeviceId,
    type: "answer",
    payload: {
      answer,
      fromUsername: call.toUsername,
      fromDeviceId: session.deviceId
    },
    createdAt: Date.now()
  });

  return { ok: true };
});

server.post(
  "/api/calls/ice",
  { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as {
    callId?: string;
    candidate?: string;
    target?: "caller" | "callee";
  };
  const callId = body.callId?.trim();
  const candidate = body.candidate?.trim();
  const target = body.target;

  if (!callId || !candidate || !target) {
    return reply.status(400).send({ error: "invalid ice payload" });
  }

  const call = callSessions.get(callId);
  if (!call) {
    return reply.status(404).send({ error: "call not found" });
  }

  const targetUserId =
    target === "caller" ? call.fromUserId : call.toUserId;
  const targetDeviceId =
    target === "caller" ? call.fromDeviceId : call.toDeviceId;

  pushCallEvent({
    id: Date.now(),
    callId,
    targetUserId,
    targetDeviceId,
    type: "ice",
    payload: {
      candidate,
      fromDeviceId: session.deviceId
    },
    createdAt: Date.now()
  });

  return { ok: true };
});

server.post(
  "/api/calls/end",
  { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as { callId?: string };
  const callId = body.callId?.trim();
  if (!callId) {
    return reply.status(400).send({ error: "callId required" });
  }

  const call = callSessions.get(callId);
  if (!call) {
    return reply.status(404).send({ error: "call not found" });
  }

  const targetUserId =
    call.fromUserId === session.userId ? call.toUserId : call.fromUserId;
  const targetDeviceId =
    call.fromUserId === session.userId ? call.toDeviceId : call.fromDeviceId;

  pushCallEvent({
    id: Date.now(),
    callId,
    targetUserId,
    targetDeviceId,
    type: "end",
    payload: {},
    createdAt: Date.now()
  });

  callSessions.delete(callId);

  return { ok: true };
});

server.get(
  "/api/calls/poll",
  { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const query = request.query as { since?: string };
  const since = query.since ? Number(query.since) : 0;
  const cutoff = Date.now() - CALL_EVENT_TTL_MS;

  const events = callEvents.filter((event) => {
    if (event.createdAt < cutoff) {
      return false;
    }
    if (event.createdAt <= (Number.isFinite(since) ? since : 0)) {
      return false;
    }
    return (
      event.targetUserId === session.userId &&
      event.targetDeviceId === session.deviceId
    );
  });

  return { events };
});

server.get("/api/devices", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const sessions = listSessionsForUser(session.userId);
  return {
    devices: sessions.map((row) => ({
      deviceId: row.device_id,
      deviceName: row.device_name,
      ip: row.ip,
      lastSeenAt: row.last_seen_at,
      createdAt: row.created_at,
      current: row.device_id === session.deviceId
    }))
  };
});

server.post("/api/devices/logout-all", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  removeSessionsForUser(session.userId);
  return { ok: true };
});

server.post("/api/devices/:deviceId/logout", async (request, reply) => {
  const session = getAuthSession(request.headers.authorization);
  if (!session) {
    return reply.status(401).send({ error: "unauthorized" });
  }
  const { deviceId } = request.params as { deviceId: string };
  removeSessionForDevice(session.userId, deviceId);
  return { ok: true };
});

server.post(
  "/api/admin/login",
  { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const body = request.body as { username?: string; password?: string };
  const username = body.username?.trim();
  const password = body.password?.trim();

  if (!username || !password) {
    return reply.status(400).send({ error: "username and password required" });
  }

  const credentials = getAdminCredentials();
  const passwordHash = hashPassword(password, credentials.password_salt);
  if (
    username !== credentials.username ||
    !crypto.timingSafeEqual(
      Buffer.from(passwordHash, "hex"),
      Buffer.from(credentials.password_hash, "hex")
    )
  ) {
    return reply.status(401).send({ error: "invalid credentials" });
  }

  const token = generateToken();
  createAdminSession(token);
  return { token, username: credentials.username };
});

server.post(
  "/api/admin/password",
  { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const token = getAdminToken(request.headers.authorization);
  if (!token || !findAdminSession(token)) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as { password?: string };
  const password = body.password?.trim();
  if (!password || password.length < 6) {
    return reply.status(400).send({ error: "password too short" });
  }

  updateAdminPassword(password);
  return { ok: true };
});

server.get(
  "/api/admin/users",
  { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const token = getAdminToken(request.headers.authorization);
  if (!token || !findAdminSession(token)) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const users = listUsers().map((user) => {
    const profile = readUserProfile(user.username);
    return {
      id: user.id,
      username: user.username,
      phone: user.phone,
      firstName: user.first_name,
      lastName: user.last_name,
      createdAt: user.created_at,
      banned: user.banned,
      canSend: user.can_send,
      canCreate: user.can_create,
      allowDirect: user.allow_direct,
      allowGroupInvite: user.allow_group_invite,
      avatar: user.avatar,
      bio: user.bio,
      profilePublic: user.profile_public,
      profile
    };
  });

  return { users };
});

server.get(
  "/api/admin/users/:id/profile-json",
  { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const token = getAdminToken(request.headers.authorization);
  if (!token || !findAdminSession(token)) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const userId = Number(id);
  const user = findUserById(userId);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }

  const profile = readUserProfile(user.username);
  const payload = {
    user: {
      id: user.id,
      username: user.username,
      phone: user.phone,
      firstName: user.first_name,
      lastName: user.last_name,
      createdAt: user.created_at
    },
    profile
  };

  reply.header("Content-Type", "application/json");
  reply.header(
    "Content-Disposition",
    `attachment; filename="${user.username}-metadata.json"`
  );
  return payload;
});

server.post(
  "/api/admin/users/:id/flags",
  { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const token = getAdminToken(request.headers.authorization);
  if (!token || !findAdminSession(token)) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const userId = Number(id);
  const body = request.body as {
    banned?: boolean;
    canSend?: boolean;
    canCreate?: boolean;
    allowDirect?: boolean;
    allowGroupInvite?: boolean;
  };

  const user = updateUserFlags(userId, {
    banned: body.banned,
    can_send: body.canSend,
    can_create: body.canCreate,
    allow_direct: body.allowDirect,
    allow_group_invite: body.allowGroupInvite
  });

  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }

  return { ok: true };
});

server.post(
  "/api/admin/users/:id/password",
  { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const token = getAdminToken(request.headers.authorization);
  if (!token || !findAdminSession(token)) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const userId = Number(id);
  const body = request.body as { password?: string };
  const password = body.password?.trim();
  if (!password || password.length < 6) {
    return reply.status(400).send({ error: "password too short" });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt);
  const ok = updateUserPassword(userId, passwordHash, salt);
  if (!ok) {
    return reply.status(404).send({ error: "user not found" });
  }

  return { ok: true };
});

server.post(
  "/api/admin/users/:id/delete",
  { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const token = getAdminToken(request.headers.authorization);
  if (!token || !findAdminSession(token)) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const userId = Number(id);
  const ok = deleteUserAndData(userId);
  if (!ok) {
    return reply.status(404).send({ error: "user not found" });
  }

  return { ok: true };
});

server.get(
  "/api/admin/conversations",
  { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const token = getAdminToken(request.headers.authorization);
  if (!token || !findAdminSession(token)) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const conversations = listConversations().map((conv) => {
    const members = listMembers(conv.id).map((member) => member.username);
    return {
      id: conv.id,
      type: conv.type,
      name: conv.name,
      ownerId: conv.owner_id,
      visibility: conv.visibility,
      createdAt: conv.created_at,
      members
    };
  });

  return { conversations };
});

server.post(
  "/api/admin/conversations/:id/delete",
  { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
  async (request, reply) => {
  const token = getAdminToken(request.headers.authorization);
  if (!token || !findAdminSession(token)) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const ok = deleteConversation(conversationId);
  if (!ok) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  return { ok: true };
});

const port = Number(process.env.PORT || 3001);
server
  .listen({ port, host: "0.0.0.0" })
  .catch((err) => {
    server.log.error(err);
    process.exit(1);
  });
