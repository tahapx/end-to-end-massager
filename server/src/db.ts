import path from "node:path";
import crypto from "node:crypto";
import { readEncryptedJson, writeEncryptedJson } from "./storage.js";

const DB_PATH = path.join(process.cwd(), "data.json");

export type UserRow = {
  id: number;
  username: string;
  phone: string;
  first_name: string;
  last_name: string;
  password_hash: string;
  password_salt: string;
  two_factor_enabled: boolean;
  public_key: string;
  created_at: number;
  banned: boolean;
  can_send: boolean;
  can_create: boolean;
  avatar: string | null;
  bio: string | null;
  profile_public: boolean;
  allow_direct: boolean;
  allow_group_invite: boolean;
  privacy_defaults: {
    hide_online: boolean;
    hide_last_seen: boolean;
    hide_profile_photo: boolean;
    disable_read_receipts: boolean;
    disable_typing_indicator: boolean;
  };
  privacy_overrides: Record<
    string,
    Partial<UserRow["privacy_defaults"]>
  >;
};

export type SessionRow = {
  token: string;
  user_id: number;
  device_id: string;
  device_name: string;
  ip: string;
  last_seen_at: number;
  created_at: number;
};

export type ConversationType = "direct" | "group" | "channel";

export type ConversationRow = {
  id: number;
  type: ConversationType;
  name: string | null;
  owner_id: number;
  visibility: "public" | "private";
  created_at: number;
};

export type MembershipRow = {
  conversation_id: number;
  user_id: number;
  role: "owner" | "admin" | "member";
  permissions?: {
    manage_members?: boolean;
    manage_invites?: boolean;
  };
};

export type MessageRow = {
  id: number;
  group_id: string;
  conversation_id: number;
  sender_id: number;
  sender_device_id: string;
  recipient_id: number;
  recipient_device_id: string;
  ciphertext: string;
  nonce: string;
  size_bytes: number;
  created_at: number;
  delivered_at: number | null;
  read_at: number | null;
  deleted_at: number | null;
  deleted_by: number | null;
};

export type OneTimePreKey = {
  id: number;
  key: string;
};

export type UserKeyBundle = {
  user_id: number;
  session_device_id: string;
  registration_id: number;
  device_id: number;
  identity_key: string;
  signed_prekey_id: number;
  signed_prekey: string;
  signed_prekey_sig: string;
  one_time_prekeys: OneTimePreKey[];
  updated_at: number;
};

export type InviteRow = {
  id: number;
  conversation_id: number;
  token: string;
  max_uses: number;
  uses: number;
  expires_at: number | null;
  created_by: number;
  created_at: number;
  revoked: boolean;
};

type AdminCredentials = {
  username: string;
  password_hash: string;
  password_salt: string;
  created_at: number;
  updated_at: number;
};

type AdminSession = {
  token: string;
  created_at: number;
};

type DbShape = {
  users: UserRow[];
  sessions: SessionRow[];
  conversations: ConversationRow[];
  memberships: MembershipRow[];
  messages: MessageRow[];
  key_bundles: UserKeyBundle[];
  invites: InviteRow[];
  admin_credentials: AdminCredentials | null;
  admin_sessions: AdminSession[];
  nextIds: {
    users: number;
    conversations: number;
    messages: number;
  };
};

const defaultDb: DbShape = {
  users: [],
  sessions: [],
  conversations: [],
  memberships: [],
  messages: [],
  key_bundles: [],
  invites: [],
  admin_credentials: null,
  admin_sessions: [],
  nextIds: { users: 1, conversations: 1, messages: 1 }
};

const DEFAULT_ADMIN_USERNAME = "taha";
const DEFAULT_ADMIN_PASSWORD = "12345678";

function loadDb(): DbShape {
  const parsed = readEncryptedJson<DbShape>(DB_PATH);
  if (!parsed) {
    return { ...defaultDb };
  }
  const db: DbShape = {
    ...defaultDb,
    ...parsed,
    nextIds: { ...defaultDb.nextIds, ...parsed.nextIds }
  };
  const ownerByConversation = new Map(
    db.conversations.map((conv) => [conv.id, conv.owner_id])
  );
  db.users = db.users.map((user) => ({
    ...user,
    phone: user.phone || "",
    first_name: user.first_name || "",
    last_name: user.last_name || "",
    two_factor_enabled: Boolean(user.two_factor_enabled),
    privacy_defaults: {
      hide_online: false,
      hide_last_seen: false,
      hide_profile_photo: false,
      disable_read_receipts: false,
      disable_typing_indicator: false,
      ...(user.privacy_defaults || {})
    },
    privacy_overrides: user.privacy_overrides || {}
  }));
  db.sessions = db.sessions.map((session) => ({
    ...session,
    device_id: session.device_id || "legacy",
    device_name: session.device_name || "Unknown device",
    ip: session.ip || "",
    last_seen_at: session.last_seen_at || session.created_at || Date.now()
  }));
  db.conversations = db.conversations.map((conversation) => ({
    ...conversation,
    visibility: conversation.visibility || "public"
  }));
  db.memberships = db.memberships.map((membership) => {
    const ownerId = ownerByConversation.get(membership.conversation_id);
    const role =
      membership.role ||
      (ownerId && membership.user_id === ownerId ? "owner" : "member");
    const permissions =
      role === "admin"
        ? {
            manage_members: membership.permissions?.manage_members ?? true,
            manage_invites: membership.permissions?.manage_invites ?? true
          }
        : undefined;
    return {
      ...membership,
      role,
      permissions
    };
  });
  for (const conversation of db.conversations) {
    const hasOwner = db.memberships.some(
      (member) =>
        member.conversation_id === conversation.id &&
        member.user_id === conversation.owner_id &&
        member.role === "owner"
    );
    if (!hasOwner) {
      db.memberships.push({
        conversation_id: conversation.id,
        user_id: conversation.owner_id,
        role: "owner"
      });
    }
  }
  db.key_bundles = db.key_bundles.map((bundle) => ({
    ...bundle,
    session_device_id: bundle.session_device_id || "legacy",
    registration_id: bundle.registration_id || 1,
    device_id: bundle.device_id || 1
  }));
  db.messages = db.messages.map((message) => ({
    ...message,
    sender_device_id: message.sender_device_id || "legacy",
    recipient_device_id: message.recipient_device_id || "legacy",
    size_bytes: message.size_bytes || message.ciphertext?.length || 0
  }));
  db.invites = (db.invites || []).map((invite) => ({
    ...invite,
    max_uses: invite.max_uses || 1,
    uses: invite.uses || 0,
    expires_at:
      invite.expires_at === undefined ? null : invite.expires_at,
    revoked: Boolean(invite.revoked)
  }));
  return db;
}

function saveDb(db: DbShape): void {
  writeEncryptedJson(DB_PATH, db);
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 32).toString("hex");
}

function ensureAdminCredentials(db: DbShape): void {
  if (db.admin_credentials) {
    return;
  }
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(DEFAULT_ADMIN_PASSWORD, salt);
  const now = Date.now();
  db.admin_credentials = {
    username: DEFAULT_ADMIN_USERNAME,
    password_hash: passwordHash,
    password_salt: salt,
    created_at: now,
    updated_at: now
  };
}

export function getAdminCredentials(): AdminCredentials {
  const db = loadDb();
  ensureAdminCredentials(db);
  saveDb(db);
  return db.admin_credentials!;
}

export function updateAdminPassword(newPassword: string): void {
  const db = loadDb();
  ensureAdminCredentials(db);
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(newPassword, salt);
  db.admin_credentials = {
    username: db.admin_credentials!.username,
    password_hash: passwordHash,
    password_salt: salt,
    created_at: db.admin_credentials!.created_at,
    updated_at: Date.now()
  };
  saveDb(db);
}

export function createAdminSession(token: string): void {
  const db = loadDb();
  db.admin_sessions.push({ token, created_at: Date.now() });
  saveDb(db);
}

export function findAdminSession(token: string): boolean {
  const db = loadDb();
  return db.admin_sessions.some((session) => session.token === token);
}

export function createUser(
  username: string,
  phone: string,
  firstName: string,
  lastName: string,
  passwordHash: string,
  passwordSalt: string,
  twoFactorEnabled: boolean,
  publicKey: string
): UserRow {
  const db = loadDb();
  const createdAt = Date.now();
  const user: UserRow = {
    id: db.nextIds.users,
    username,
    phone,
    first_name: firstName,
    last_name: lastName,
    password_hash: passwordHash,
    password_salt: passwordSalt,
    two_factor_enabled: twoFactorEnabled,
    public_key: publicKey,
    created_at: createdAt,
    banned: false,
    can_send: true,
    can_create: true,
    avatar: null,
    bio: null,
    profile_public: true,
    allow_direct: true,
    allow_group_invite: true,
    privacy_defaults: {
      hide_online: false,
      hide_last_seen: false,
      hide_profile_photo: false,
      disable_read_receipts: false,
      disable_typing_indicator: false
    },
    privacy_overrides: {}
  };
  db.nextIds.users += 1;
  db.users.push(user);
  saveDb(db);
  return user;
}

export function findUserByUsername(username: string): UserRow | null {
  const db = loadDb();
  return db.users.find((user) => user.username === username) ?? null;
}

export function findUserByPhone(phone: string): UserRow | null {
  const db = loadDb();
  return db.users.find((user) => user.phone === phone) ?? null;
}

export function findUserById(id: number): UserRow | null {
  const db = loadDb();
  return db.users.find((user) => user.id === id) ?? null;
}

export function listUsers(): UserRow[] {
  const db = loadDb();
  return db.users;
}

export function updateUserFlags(
  userId: number,
  updates: Partial<
    Pick<
      UserRow,
      "banned" | "can_send" | "can_create" | "allow_direct" | "allow_group_invite"
    >
  >
): UserRow | null {
  const db = loadDb();
  const user = db.users.find((item) => item.id === userId);
  if (!user) {
    return null;
  }
  if (typeof updates.banned === "boolean") {
    user.banned = updates.banned;
  }
  if (typeof updates.can_send === "boolean") {
    user.can_send = updates.can_send;
  }
  if (typeof updates.can_create === "boolean") {
    user.can_create = updates.can_create;
  }
  if (typeof updates.allow_direct === "boolean") {
    user.allow_direct = updates.allow_direct;
  }
  if (typeof updates.allow_group_invite === "boolean") {
    user.allow_group_invite = updates.allow_group_invite;
  }
  saveDb(db);
  return user;
}

export function updateUserPassword(
  userId: number,
  passwordHash: string,
  passwordSalt: string
): boolean {
  const db = loadDb();
  const user = db.users.find((item) => item.id === userId);
  if (!user) {
    return false;
  }
  user.password_hash = passwordHash;
  user.password_salt = passwordSalt;
  user.two_factor_enabled = true;
  saveDb(db);
  return true;
}

export function clearUserTwoFactor(userId: number): boolean {
  const db = loadDb();
  const user = db.users.find((item) => item.id === userId);
  if (!user) {
    return false;
  }
  user.password_hash = "";
  user.password_salt = "";
  user.two_factor_enabled = false;
  saveDb(db);
  return true;
}

export function updateUserAccount(
  userId: number,
  updates: Partial<
    Pick<
      UserRow,
      | "avatar"
      | "bio"
      | "profile_public"
      | "allow_direct"
      | "allow_group_invite"
      | "privacy_defaults"
    >
  >
): UserRow | null {
  const db = loadDb();
  const user = db.users.find((item) => item.id === userId);
  if (!user) {
    return null;
  }
  if (Object.prototype.hasOwnProperty.call(updates, "avatar")) {
    user.avatar = updates.avatar ?? null;
  }
  if (typeof updates.bio === "string") {
    user.bio = updates.bio;
  }
  if (typeof updates.profile_public === "boolean") {
    user.profile_public = updates.profile_public;
  }
  if (typeof updates.allow_direct === "boolean") {
    user.allow_direct = updates.allow_direct;
  }
  if (typeof updates.allow_group_invite === "boolean") {
    user.allow_group_invite = updates.allow_group_invite;
  }
  if (updates.privacy_defaults) {
    user.privacy_defaults = {
      ...user.privacy_defaults,
      ...updates.privacy_defaults
    };
  }
  saveDb(db);
  return user;
}

export function updatePrivacyOverride(
  userId: number,
  targetUsername: string,
  updates: Partial<UserRow["privacy_defaults"]>
): UserRow | null {
  const db = loadDb();
  const user = db.users.find((item) => item.id === userId);
  if (!user) {
    return null;
  }
  user.privacy_overrides[targetUsername] = {
    ...user.privacy_overrides[targetUsername],
    ...updates
  };
  saveDb(db);
  return user;
}

export function deleteUserAndData(userId: number): boolean {
  const db = loadDb();
  const user = db.users.find((item) => item.id === userId);
  if (!user) {
    return false;
  }
  db.users = db.users.filter((item) => item.id !== userId);
  db.sessions = db.sessions.filter((session) => session.user_id !== userId);
  db.memberships = db.memberships.filter(
    (member) => member.user_id !== userId
  );
  db.invites = db.invites.filter((invite) => invite.created_by !== userId);
  db.messages = db.messages.filter(
    (message) =>
      message.sender_id !== userId && message.recipient_id !== userId
  );

  const memberCounts = new Map<number, number>();
  for (const member of db.memberships) {
    memberCounts.set(
      member.conversation_id,
      (memberCounts.get(member.conversation_id) || 0) + 1
    );
  }
  const activeConversationIds = new Set<number>();
  for (const [conversationId, count] of memberCounts) {
    if (count > 0) {
      activeConversationIds.add(conversationId);
    }
  }
  db.conversations = db.conversations.filter((conv) => {
    if (!activeConversationIds.has(conv.id)) {
      return false;
    }
    return true;
  });
  db.invites = db.invites.filter((invite) =>
    activeConversationIds.has(invite.conversation_id)
  );
  db.messages = db.messages.filter((message) =>
    activeConversationIds.has(message.conversation_id)
  );

  saveDb(db);
  return true;
}

export function createSession(
  token: string,
  userId: number,
  deviceId: string,
  deviceName: string,
  ip: string
): void {
  const db = loadDb();
  const createdAt = Date.now();
  db.sessions = db.sessions.filter(
    (row) => !(row.user_id === userId && row.device_id === deviceId)
  );
  db.sessions.push({
    token,
    user_id: userId,
    device_id: deviceId,
    device_name: deviceName,
    ip,
    last_seen_at: createdAt,
    created_at: createdAt
  });
  saveDb(db);
}

export function findSession(token: string): SessionRow | null {
  const db = loadDb();
  const session = db.sessions.find((row) => row.token === token);
  return session ?? null;
}

export function listSessionsForUser(userId: number): SessionRow[] {
  const db = loadDb();
  return db.sessions.filter((row) => row.user_id === userId);
}

export function removeSessionsForUser(userId: number): void {
  const db = loadDb();
  db.sessions = db.sessions.filter((row) => row.user_id !== userId);
  saveDb(db);
}

export function removeSessionForDevice(
  userId: number,
  deviceId: string
): void {
  const db = loadDb();
  db.sessions = db.sessions.filter(
    (row) => !(row.user_id === userId && row.device_id === deviceId)
  );
  saveDb(db);
}

export function updateSessionLastSeen(token: string): void {
  const db = loadDb();
  const session = db.sessions.find((row) => row.token === token);
  if (!session) {
    return;
  }
  session.last_seen_at = Date.now();
  saveDb(db);
}

export function createConversation(
  type: ConversationType,
  name: string | null,
  ownerId: number,
  memberIds: number[],
  visibility: "public" | "private"
): ConversationRow {
  const db = loadDb();
  const createdAt = Date.now();
  const conversation: ConversationRow = {
    id: db.nextIds.conversations,
    type,
    name,
    owner_id: ownerId,
    visibility,
    created_at: createdAt
  };
  db.nextIds.conversations += 1;
  db.conversations.push(conversation);

  const uniqueMembers = Array.from(new Set([ownerId, ...memberIds]));
  for (const userId of uniqueMembers) {
    db.memberships.push({
      conversation_id: conversation.id,
      user_id: userId,
      role: userId === ownerId ? "owner" : "member"
    });
  }

  saveDb(db);
  return conversation;
}

export function listConversationsForUser(userId: number): ConversationRow[] {
  const db = loadDb();
  const conversationIds = new Set(
    db.memberships
      .filter((member) => member.user_id === userId)
      .map((member) => member.conversation_id)
  );

  return db.conversations.filter((conv) => conversationIds.has(conv.id));
}

export function listConversations(): ConversationRow[] {
  const db = loadDb();
  return db.conversations;
}

export function deleteConversation(conversationId: number): boolean {
  const db = loadDb();
  const exists = db.conversations.some((conv) => conv.id === conversationId);
  if (!exists) {
    return false;
  }
  db.conversations = db.conversations.filter((conv) => conv.id !== conversationId);
  db.memberships = db.memberships.filter(
    (member) => member.conversation_id !== conversationId
  );
  db.invites = db.invites.filter(
    (invite) => invite.conversation_id !== conversationId
  );
  db.messages = db.messages.filter(
    (message) => message.conversation_id !== conversationId
  );
  saveDb(db);
  return true;
}

export function getConversationById(id: number): ConversationRow | null {
  const db = loadDb();
  return db.conversations.find((conv) => conv.id === id) ?? null;
}

export function listMembers(conversationId: number): UserRow[] {
  const db = loadDb();
  const memberIds = db.memberships
    .filter((member) => member.conversation_id === conversationId)
    .map((member) => member.user_id);
  return db.users.filter((user) => memberIds.includes(user.id));
}

export function isMember(conversationId: number, userId: number): boolean {
  const db = loadDb();
  return db.memberships.some(
    (member) =>
      member.conversation_id === conversationId && member.user_id === userId
  );
}

export function getMembership(
  conversationId: number,
  userId: number
): MembershipRow | null {
  const db = loadDb();
  return (
    db.memberships.find(
      (member) =>
        member.conversation_id === conversationId && member.user_id === userId
    ) ?? null
  );
}

export function listMemberships(conversationId: number): Array<{
  user: UserRow;
  role: MembershipRow["role"];
  permissions?: MembershipRow["permissions"];
}> {
  const db = loadDb();
  const memberships = db.memberships.filter(
    (member) => member.conversation_id === conversationId
  );
  return memberships
    .map((member) => {
      const user = db.users.find((row) => row.id === member.user_id);
      if (!user) {
        return null;
      }
      return {
        user,
        role: member.role,
        permissions: member.permissions
      };
    })
    .filter(Boolean) as Array<{
    user: UserRow;
    role: MembershipRow["role"];
    permissions?: MembershipRow["permissions"];
  }>;
}

export function addMember(
  conversationId: number,
  userId: number,
  role: MembershipRow["role"] = "member"
): boolean {
  const db = loadDb();
  const exists = db.memberships.some(
    (member) =>
      member.conversation_id === conversationId && member.user_id === userId
  );
  if (exists) {
    return false;
  }
  db.memberships.push({
    conversation_id: conversationId,
    user_id: userId,
    role
  });
  saveDb(db);
  return true;
}

export function removeMember(
  conversationId: number,
  userId: number
): boolean {
  const db = loadDb();
  const before = db.memberships.length;
  db.memberships = db.memberships.filter(
    (member) =>
      !(
        member.conversation_id === conversationId &&
        member.user_id === userId
      )
  );
  if (db.memberships.length === before) {
    return false;
  }
  saveDb(db);
  return true;
}

export function updateMemberRole(
  conversationId: number,
  userId: number,
  role: MembershipRow["role"],
  permissions?: MembershipRow["permissions"]
): boolean {
  const db = loadDb();
  const member = db.memberships.find(
    (row) =>
      row.conversation_id === conversationId && row.user_id === userId
  );
  if (!member) {
    return false;
  }
  member.role = role;
  if (role === "admin") {
    member.permissions = {
      manage_members: permissions?.manage_members ?? member.permissions?.manage_members ?? true,
      manage_invites: permissions?.manage_invites ?? member.permissions?.manage_invites ?? true
    };
  } else {
    delete member.permissions;
  }
  saveDb(db);
  return true;
}

export function createInvite(
  conversationId: number,
  createdBy: number,
  maxUses: number,
  expiresAt: number | null
): InviteRow {
  const db = loadDb();
  let token = "";
  do {
    token = crypto.randomBytes(16).toString("hex");
  } while (db.invites.some((invite) => invite.token === token));
  const invite: InviteRow = {
    id: db.invites.length ? db.invites[db.invites.length - 1].id + 1 : 1,
    conversation_id: conversationId,
    token,
    max_uses: maxUses,
    uses: 0,
    expires_at: expiresAt,
    created_by: createdBy,
    created_at: Date.now(),
    revoked: false
  };
  db.invites.push(invite);
  saveDb(db);
  return invite;
}

export function listInvites(conversationId: number): InviteRow[] {
  const db = loadDb();
  return db.invites.filter((invite) => invite.conversation_id === conversationId);
}

export function findInviteByToken(token: string): InviteRow | null {
  const db = loadDb();
  return db.invites.find((invite) => invite.token === token) ?? null;
}

export function revokeInvite(token: string): boolean {
  const db = loadDb();
  const invite = db.invites.find((row) => row.token === token);
  if (!invite) {
    return false;
  }
  invite.revoked = true;
  saveDb(db);
  return true;
}

export function redeemInvite(
  token: string,
  userId: number
): InviteRow | null {
  const db = loadDb();
  const invite = db.invites.find((row) => row.token === token);
  if (!invite || invite.revoked) {
    return null;
  }
  if (invite.expires_at && Date.now() > invite.expires_at) {
    return null;
  }
  if (invite.uses >= invite.max_uses) {
    return null;
  }
  const already = db.memberships.some(
    (member) =>
      member.conversation_id === invite.conversation_id &&
      member.user_id === userId
  );
  if (!already) {
    db.memberships.push({
      conversation_id: invite.conversation_id,
      user_id: userId,
      role: "member"
    });
  }
  invite.uses += 1;
  saveDb(db);
  return invite;
}

export function createMessage(
  groupId: string,
  conversationId: number,
  senderId: number,
  senderDeviceId: string,
  recipientId: number,
  recipientDeviceId: string,
  ciphertext: string,
  nonce: string,
  sizeBytes: number
): void {
  const db = loadDb();
  const createdAt = Date.now();
  const message: MessageRow = {
    id: db.nextIds.messages,
    group_id: groupId,
    conversation_id: conversationId,
    sender_id: senderId,
    sender_device_id: senderDeviceId,
    recipient_id: recipientId,
    recipient_device_id: recipientDeviceId,
    ciphertext,
    nonce,
    size_bytes: sizeBytes,
    created_at: createdAt,
    delivered_at: null,
    read_at: null,
    deleted_at: null,
    deleted_by: null
  };
  db.nextIds.messages += 1;
  db.messages.push(message);
  saveDb(db);
}

export function setUserKeyBundle(
  userId: number,
  bundle: Omit<UserKeyBundle, "user_id" | "updated_at">
): void {
  const db = loadDb();
  const updatedAt = Date.now();
  const existing = db.key_bundles.find(
    (row) =>
      row.user_id === userId &&
      row.session_device_id === bundle.session_device_id
  );
  if (existing) {
    existing.session_device_id = bundle.session_device_id;
    existing.registration_id = bundle.registration_id;
    existing.device_id = bundle.device_id;
    existing.identity_key = bundle.identity_key;
    existing.signed_prekey_id = bundle.signed_prekey_id;
    existing.signed_prekey = bundle.signed_prekey;
    existing.signed_prekey_sig = bundle.signed_prekey_sig;
    existing.one_time_prekeys = bundle.one_time_prekeys;
    existing.updated_at = updatedAt;
  } else {
    db.key_bundles.push({
      user_id: userId,
      updated_at: updatedAt,
      ...bundle
    });
  }
  saveDb(db);
}

export function getUserKeyBundle(userId: number): UserKeyBundle | null {
  const db = loadDb();
  return db.key_bundles.find((row) => row.user_id === userId) ?? null;
}

export function listUserKeyBundles(userId: number): UserKeyBundle[] {
  const db = loadDb();
  return db.key_bundles.filter((row) => row.user_id === userId);
}

export function findUserKeyBundleBySession(
  userId: number,
  sessionDeviceId: string
): UserKeyBundle | null {
  const db = loadDb();
  return (
    db.key_bundles.find(
      (row) =>
        row.user_id === userId && row.session_device_id === sessionDeviceId
    ) ?? null
  );
}

export function popOneTimePreKey(
  userId: number,
  sessionDeviceId: string
): { id: number; key: string } | null {
  const db = loadDb();
  const bundle = db.key_bundles.find(
    (row) =>
      row.user_id === userId && row.session_device_id === sessionDeviceId
  );
  if (!bundle || bundle.one_time_prekeys.length === 0) {
    return null;
  }
  const prekey = bundle.one_time_prekeys.shift() ?? null;
  bundle.updated_at = Date.now();
  saveDb(db);
  return prekey;
}

export function pollMessages(
  recipientId: number,
  recipientDeviceId: string,
  since: number,
  limit = 50
): Array<{
  id: number;
  group_id: string;
  conversation_id: number;
  sender_username: string;
  sender_public_key: string;
  ciphertext: string;
  nonce: string;
  created_at: number;
  delivered_at: number | null;
  read_at: number | null;
  deleted_at: number | null;
  deleted_by: number | null;
}> {
  const db = loadDb();
  const usersById = new Map(db.users.map((user) => [user.id, user]));

  return db.messages
    .filter(
      (message) =>
        message.recipient_id === recipientId &&
        message.recipient_device_id === recipientDeviceId &&
        message.created_at > since
    )
    .sort((a, b) => a.created_at - b.created_at)
    .slice(0, Math.max(1, limit))
    .map((message) => {
      const sender = usersById.get(message.sender_id);
      return {
        id: message.id,
        group_id: message.group_id,
        conversation_id: message.conversation_id,
        sender_username: sender?.username ?? "unknown",
        sender_public_key: sender?.public_key ?? "",
        sender_device_id: message.sender_device_id,
        ciphertext: message.ciphertext,
        nonce: message.nonce,
        size_bytes: message.size_bytes,
        created_at: message.created_at,
        delivered_at: message.delivered_at,
        read_at: message.read_at,
        deleted_at: message.deleted_at,
        deleted_by: message.deleted_by
      };
    });
}

export function markDelivered(messageIds: number[]): void {
  if (messageIds.length === 0) {
    return;
  }
  const db = loadDb();
  const deliveredAt = Date.now();
  for (const message of db.messages) {
    if (messageIds.includes(message.id) && !message.delivered_at) {
      message.delivered_at = deliveredAt;
    }
  }
  saveDb(db);
}

export function markRead(conversationId: number, recipientId: number): void {
  const db = loadDb();
  const readAt = Date.now();
  let updated = false;
  for (const message of db.messages) {
    if (
      message.conversation_id === conversationId &&
      message.recipient_id === recipientId &&
      !message.read_at
    ) {
      message.read_at = readAt;
      updated = true;
    }
  }
  if (updated) {
    saveDb(db);
  }
}

export function listSentStatuses(
  senderId: number,
  since: number,
  limit = 50
): Array<{
  group_id: string;
  conversation_id: number;
  updated_at: number;
  delivered_at: number | null;
  read_at: number | null;
  deleted_at: number | null;
}> {
  const db = loadDb();
  const messages = db.messages.filter((message) => {
    if (message.sender_id !== senderId) {
      return false;
    }
    const updatedAt = Math.max(
      message.created_at,
      message.delivered_at ?? 0,
      message.read_at ?? 0,
      message.deleted_at ?? 0
    );
    return updatedAt > since;
  });
  const grouped = new Map<string, MessageRow[]>();

  for (const message of messages) {
    if (!grouped.has(message.group_id)) {
      grouped.set(message.group_id, []);
    }
    grouped.get(message.group_id)!.push(message);
  }

  const result: Array<{
    group_id: string;
    conversation_id: number;
    updated_at: number;
    delivered_at: number | null;
    read_at: number | null;
    deleted_at: number | null;
  }> = [];

  const groupedEntries = Array.from(grouped.entries()).slice(
    0,
    Math.max(1, limit)
  );

  for (const [groupId, items] of groupedEntries) {
    const deliveredAt = items
      .map((item) => item.delivered_at)
      .filter((value): value is number => value !== null)
      .sort((a, b) => b - a)[0] ?? null;
    const readAt = items
      .map((item) => item.read_at)
      .filter((value): value is number => value !== null)
      .sort((a, b) => b - a)[0] ?? null;
    const deletedAt = items
      .map((item) => item.deleted_at)
      .filter((value): value is number => value !== null)
      .sort((a, b) => b - a)[0] ?? null;

    const updatedAt = Math.max(
      items[0].created_at,
      deliveredAt ?? 0,
      readAt ?? 0,
      deletedAt ?? 0
    );

    result.push({
      group_id: groupId,
      conversation_id: items[0].conversation_id,
      updated_at: updatedAt,
      delivered_at: deliveredAt,
      read_at: readAt,
      deleted_at: deletedAt
    });
  }

  return result;
}

export function deleteMessageForAll(
  groupId: string,
  requesterId: number
): boolean {
  const db = loadDb();
  const deletedAt = Date.now();
  let updated = false;

  for (const message of db.messages) {
    if (message.group_id === groupId && message.sender_id === requesterId) {
      message.deleted_at = deletedAt;
      message.deleted_by = requesterId;
      updated = true;
    }
  }

  if (updated) {
    saveDb(db);
  }
  return updated;
}

export function deleteMessageForSelf(
  messageId: number,
  userId: number
): void {
  const db = loadDb();
  const deletedAt = Date.now();
  const message = db.messages.find((item) => item.id === messageId);
  if (!message) {
    return;
  }
  if (message.recipient_id !== userId) {
    return;
  }
  message.deleted_at = deletedAt;
  message.deleted_by = userId;
  saveDb(db);
}
