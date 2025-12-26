import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const DB_PATH = path.join(process.cwd(), "data.json");

export type UserRow = {
  id: number;
  username: string;
  password_hash: string;
  password_salt: string;
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
};

export type SessionRow = {
  token: string;
  user_id: number;
  created_at: number;
};

export type ConversationType = "direct" | "group" | "channel";

export type ConversationRow = {
  id: number;
  type: ConversationType;
  name: string | null;
  owner_id: number;
  created_at: number;
};

export type MembershipRow = {
  conversation_id: number;
  user_id: number;
};

export type MessageRow = {
  id: number;
  group_id: string;
  conversation_id: number;
  sender_id: number;
  recipient_id: number;
  ciphertext: string;
  nonce: string;
  created_at: number;
  delivered_at: number | null;
  read_at: number | null;
  deleted_at: number | null;
  deleted_by: number | null;
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
  admin_credentials: null,
  admin_sessions: [],
  nextIds: { users: 1, conversations: 1, messages: 1 }
};

const DEFAULT_ADMIN_USERNAME = "myadmin";
const DEFAULT_ADMIN_PASSWORD = "000123";

function loadDb(): DbShape {
  if (!fs.existsSync(DB_PATH)) {
    return { ...defaultDb };
  }
  const raw = fs.readFileSync(DB_PATH, "utf-8");
  try {
    const parsed = JSON.parse(raw) as DbShape;
    return {
      ...defaultDb,
      ...parsed,
      nextIds: { ...defaultDb.nextIds, ...parsed.nextIds }
    };
  } catch {
    return { ...defaultDb };
  }
}

function saveDb(db: DbShape): void {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
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
  passwordHash: string,
  passwordSalt: string,
  publicKey: string
): UserRow {
  const db = loadDb();
  const createdAt = Date.now();
  const user: UserRow = {
    id: db.nextIds.users,
    username,
    password_hash: passwordHash,
    password_salt: passwordSalt,
    public_key: publicKey,
    created_at: createdAt,
    banned: false,
    can_send: true,
    can_create: true,
    avatar: null,
    bio: null,
    profile_public: true,
    allow_direct: true,
    allow_group_invite: true
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
  saveDb(db);
  return true;
}

export function updateUserAccount(
  userId: number,
  updates: Partial<
    Pick<
      UserRow,
      "avatar" | "bio" | "profile_public" | "allow_direct" | "allow_group_invite"
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
  db.messages = db.messages.filter((message) =>
    activeConversationIds.has(message.conversation_id)
  );

  saveDb(db);
  return true;
}

export function createSession(token: string, userId: number): void {
  const db = loadDb();
  const createdAt = Date.now();
  db.sessions.push({ token, user_id: userId, created_at: createdAt });
  saveDb(db);
}

export function findSession(token: string): { user_id: number } | null {
  const db = loadDb();
  const session = db.sessions.find((row) => row.token === token);
  return session ? { user_id: session.user_id } : null;
}

export function createConversation(
  type: ConversationType,
  name: string | null,
  ownerId: number,
  memberIds: number[]
): ConversationRow {
  const db = loadDb();
  const createdAt = Date.now();
  const conversation: ConversationRow = {
    id: db.nextIds.conversations,
    type,
    name,
    owner_id: ownerId,
    created_at: createdAt
  };
  db.nextIds.conversations += 1;
  db.conversations.push(conversation);

  const uniqueMembers = Array.from(new Set([ownerId, ...memberIds]));
  for (const userId of uniqueMembers) {
    db.memberships.push({ conversation_id: conversation.id, user_id: userId });
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

export function createMessage(
  groupId: string,
  conversationId: number,
  senderId: number,
  recipientId: number,
  ciphertext: string,
  nonce: string
): void {
  const db = loadDb();
  const createdAt = Date.now();
  const message: MessageRow = {
    id: db.nextIds.messages,
    group_id: groupId,
    conversation_id: conversationId,
    sender_id: senderId,
    recipient_id: recipientId,
    ciphertext,
    nonce,
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

export function pollMessages(
  recipientId: number,
  since: number
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
        message.recipient_id === recipientId && message.created_at > since
    )
    .sort((a, b) => a.created_at - b.created_at)
    .map((message) => {
      const sender = usersById.get(message.sender_id);
      return {
        id: message.id,
        group_id: message.group_id,
        conversation_id: message.conversation_id,
        sender_username: sender?.username ?? "unknown",
        sender_public_key: sender?.public_key ?? "",
        ciphertext: message.ciphertext,
        nonce: message.nonce,
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
  since: number
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

  for (const [groupId, items] of grouped) {
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
