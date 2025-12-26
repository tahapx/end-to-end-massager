import Fastify from "fastify";
import cors from "@fastify/cors";
import crypto from "node:crypto";
import {
  createMessage,
  createSession,
  createUser,
  findSession,
  findUserById,
  findUserByUsername,
  pollMessages,
  markDelivered
} from "./db.js";

const server = Fastify({ logger: true });

await server.register(cors, {
  origin: true,
  methods: ["GET", "POST"]
});

function generateToken(): string {
  return crypto.randomBytes(24).toString("hex");
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
  const body = request.body as { username?: string; publicKey?: string };
  const username = body.username?.trim();
  const publicKey = body.publicKey?.trim();

  if (!username || !publicKey) {
    return reply.status(400).send({ error: "username and publicKey required" });
  }

  const existing = findUserByUsername(username);
  if (existing) {
    return reply.status(409).send({ error: "username already exists" });
  }

  const user = createUser(username, publicKey);
  const token = generateToken();
  createSession(token, user.id);

  return { userId: user.id, token, username: user.username };
});

server.post("/api/auth/login", async (request, reply) => {
  const body = request.body as { username?: string };
  const username = body.username?.trim();

  if (!username) {
    return reply.status(400).send({ error: "username required" });
  }

  const user = findUserByUsername(username);
  if (!user) {
    return reply.status(404).send({ error: "user not found" });
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

server.post("/api/messages/send", async (request, reply) => {
  const userId = getAuthUserId(request.headers.authorization);
  if (!userId) {
    return reply.status(401).send({ error: "unauthorized" });
  }

  const body = request.body as {
    toUsername?: string;
    ciphertext?: string;
    nonce?: string;
  };

  const toUsername = body.toUsername?.trim();
  const ciphertext = body.ciphertext?.trim();
  const nonce = body.nonce?.trim();

  if (!toUsername || !ciphertext || !nonce) {
    return reply
      .status(400)
      .send({ error: "toUsername, ciphertext, nonce required" });
  }

  const recipient = findUserByUsername(toUsername);
  if (!recipient) {
    return reply.status(404).send({ error: "recipient not found" });
  }

  createMessage(userId, recipient.id, ciphertext, nonce);
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
