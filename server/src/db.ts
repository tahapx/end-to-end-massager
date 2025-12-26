import fs from "node:fs";
import path from "node:path";

const DB_PATH = path.join(process.cwd(), "data.json");

type UserRow = {
  id: number;
  username: string;
  public_key: string;
  created_at: number;
};

type SessionRow = {
  token: string;
  user_id: number;
  created_at: number;
};

type MessageRow = {
  id: number;
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
  messages: MessageRow[];
  nextIds: {
    users: number;
    messages: number;
  };
};

const defaultDb: DbShape = {
  users: [],
  sessions: [],
  messages: [],
  nextIds: { users: 1, messages: 1 }
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

export function createUser(username: string, publicKey: string): UserRow {
  const db = loadDb();
  const createdAt = Date.now();
  const user: UserRow = {
    id: db.nextIds.users,
    username,
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

export function createMessage(
  senderId: number,
  recipientId: number,
  ciphertext: string,
  nonce: string
): void {
  const db = loadDb();
  const createdAt = Date.now();
  const message: MessageRow = {
    id: db.nextIds.messages,
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
