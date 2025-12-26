import Fastify from "fastify";
import cors from "@fastify/cors";
import crypto from "node:crypto";
import {
  createConversation,
  createMessage,
  createSession,
  createUser,
  getConversationById,
  isMember,
  listConversationsForUser,
  listMembers,
  findSession,
  findUserById,
  findUserByUsername,
  pollMessages,
  markDelivered,
  type ConversationType
} from "./db.js";

const server = Fastify({ logger: true });

await server.register(cors, {
  origin: true,
  methods: ["GET", "POST"]
});

function generateToken(): string {
  return crypto.randomBytes(24).toString("hex");
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 32).toString("hex");
}

function getAuthUserId(authHeader?: string): number | null {
  if (!authHeader) {
    return null;
  }
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return null;
  }
  const session = findSession(parts[1]);
  return session ? session.user_id : null;
}

server.get("/health", async () => ({ ok: true }));

server.post("/api/auth/signup", async (request, reply) => {
  const body = request.body as {
    username?: string;
    password?: string;
    publicKey?: string;
  };
  const username = body.username?.trim();
  const password = body.password?.trim();
  const publicKey = body.publicKey?.trim();

  if (!username || !password || !publicKey) {
    return reply
      .status(400)
      .send({ error: "username, password, publicKey required" });
  }

  if (password.length < 6) {
    return reply.status(400).send({ error: "password too short" });
  }

  const existing = findUserByUsername(username);
  if (existing) {
    return reply.status(409).send({ error: "username already exists" });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt);
  const user = createUser(username, passwordHash, salt, publicKey);
  const token = generateToken();
  createSession(token, user.id);

  return { userId: user.id, token, username: user.username };
});

server.post("/api/auth/login", async (request, reply) => {
  const body = request.body as { username?: string; password?: string };
  const username = body.username?.trim();
  const password = body.password?.trim();

  if (!username || !password) {
    return reply.status(400).send({ error: "username and password required" });
  }

  const user = findUserByUsername(username);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
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

  const token = generateToken();
  createSession(token, user.id);

  return { userId: user.id, token, username: user.username };
});

server.get("/api/users/:username/public-key", async (request, reply) => {
  const { username } = request.params as { username: string };
  const user = findUserByUsername(username);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
  }
  return { username: user.username, publicKey: user.public_key };
});

server.get("/api/conversations", async (request, reply) => {
  const userId = getAuthUserId(request.headers.authorization);
  if (!userId) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const conversations = listConversationsForUser(userId).map((conv) => {
    const members = listMembers(conv.id).map((member) => ({
      username: member.username,
      publicKey: member.public_key
    }));
    return {
      id: conv.id,
      type: conv.type,
      name: conv.name,
      ownerId: conv.owner_id,
      members
    };
  });

  return { conversations };
});

server.post("/api/conversations", async (request, reply) => {
  const userId = getAuthUserId(request.headers.authorization);
  if (!userId) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as {
    type?: ConversationType;
    name?: string;
    members?: string[];
  };

  const type = body.type;
  const name = body.name?.trim() || null;
  const members = (body.members || []).map((member) => member.trim());

  if (!type || !["direct", "group", "channel"].includes(type)) {
    return reply.status(400).send({ error: "invalid type" });
  }

  if (type !== "direct" && !name) {
    return reply.status(400).send({ error: "name required" });
  }

  if (type === "direct" && members.length !== 1) {
    return reply
      .status(400)
      .send({ error: "direct requires exactly one member" });
  }

  const uniqueMembers = Array.from(new Set(members)).filter(Boolean);
  const memberUsers = uniqueMembers
    .map((memberUsername) => findUserByUsername(memberUsername))
    .filter(Boolean) as Array<{ id: number; username: string }>;

  if (memberUsers.length !== uniqueMembers.length) {
    return reply.status(404).send({ error: "one or more users not found" });
  }

  const totalMembers = memberUsers.length + 1;
  if (totalMembers > 5) {
    return reply.status(400).send({ error: "max 5 members allowed" });
  }

  const conversation = createConversation(
    type,
    name,
    userId,
    memberUsers.map((member) => member.id)
  );

  return { conversationId: conversation.id };
});

server.get("/api/conversations/:id/members", async (request, reply) => {
  const userId = getAuthUserId(request.headers.authorization);
  if (!userId) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const { id } = request.params as { id: string };
  const conversationId = Number(id);
  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  if (!isMember(conversationId, userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  const members = listMembers(conversationId).map((member) => ({
    username: member.username,
    publicKey: member.public_key
  }));

  return { members };
});

server.post("/api/messages/send", async (request, reply) => {
  const userId = getAuthUserId(request.headers.authorization);
  if (!userId) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as {
    conversationId?: number;
    payloads?: Array<{ toUsername?: string; ciphertext?: string; nonce?: string }>;
  };

  const conversationId = body.conversationId;
  const payloads = body.payloads || [];

  if (!conversationId || payloads.length === 0) {
    return reply
      .status(400)
      .send({ error: "conversationId and payloads required" });
  }

  const conversation = getConversationById(conversationId);
  if (!conversation) {
    return reply.status(404).send({ error: "conversation not found" });
  }

  if (!isMember(conversationId, userId)) {
    return reply.status(403).send({ error: "forbidden" });
  }

  if (conversation.type === "channel" && conversation.owner_id !== userId) {
    return reply.status(403).send({ error: "channel is read-only" });
  }

  const members = listMembers(conversationId);
  const memberUsernames = new Set(members.map((member) => member.username));

  for (const payload of payloads) {
    const toUsername = payload.toUsername?.trim();
    const ciphertext = payload.ciphertext?.trim();
    const nonce = payload.nonce?.trim();

    if (!toUsername || !ciphertext || !nonce) {
      return reply
        .status(400)
        .send({ error: "toUsername, ciphertext, nonce required" });
    }

    if (!memberUsernames.has(toUsername)) {
      return reply.status(400).send({ error: "recipient not in conversation" });
    }

    const recipient = findUserByUsername(toUsername);
    if (!recipient) {
      return reply.status(404).send({ error: "recipient not found" });
    }

    createMessage(conversationId, userId, recipient.id, ciphertext, nonce);
  }

  return { ok: true };
});

server.get("/api/messages/poll", async (request, reply) => {
  const userId = getAuthUserId(request.headers.authorization);
  if (!userId) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const sinceRaw = (request.query as { since?: string }).since;
  const since = sinceRaw ? Number(sinceRaw) : 0;

  const messages = pollMessages(userId, Number.isFinite(since) ? since : 0);
  markDelivered(messages.map((msg) => msg.id));

  return { messages };
});

const port = Number(process.env.PORT || 3001);
server
  .listen({ port, host: "0.0.0.0" })
  .catch((err) => {
    server.log.error(err);
    process.exit(1);
  });
