import fs from "node:fs";
import path from "node:path";

const DB_PATH = path.join(process.cwd(), "data.json");

export type UserRow = {
  id: number;
  username: string;
  password_hash: string;
  password_salt: string;
  public_key: string;
  created_at: number;
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
  conversation_id: number;
  sender_id: number;
  recipient_id: number;
  ciphertext: string;
  nonce: string;
  created_at: number;
  delivered_at: number | null;
};

type DbShape = {
  users: UserRow[];
  sessions: SessionRow[];
  conversations: ConversationRow[];
  memberships: MembershipRow[];
  messages: MessageRow[];
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
  nextIds: { users: 1, conversations: 1, messages: 1 }
};

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
    created_at: createdAt
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
    conversation_id: conversationId,
    sender_id: senderId,
    recipient_id: recipientId,
    ciphertext,
    nonce,
    created_at: createdAt,
    delivered_at: null
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
  conversation_id: number;
  sender_username: string;
  sender_public_key: string;
  ciphertext: string;
  nonce: string;
  created_at: number;
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
        conversation_id: message.conversation_id,
        sender_username: sender?.username ?? "unknown",
        sender_public_key: sender?.public_key ?? "",
        ciphertext: message.ciphertext,
        nonce: message.nonce,
        created_at: message.created_at
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
    if (messageIds.includes(message.id)) {
      message.delivered_at = deliveredAt;
    }
  }
  saveDb(db);
}
