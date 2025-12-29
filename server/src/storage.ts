import crypto from "node:crypto";
import fs from "node:fs";

type EncryptedPayload = {
  v: number;
  iv: string;
  tag: string;
  data: string;
};

function getMasterKey(): Buffer {
  const raw = process.env.APP_MASTER_KEY;
  if (!raw || raw.length < 16) {
    throw new Error("APP_MASTER_KEY is required (min 16 chars).");
  }
  return crypto.createHash("sha256").update(raw).digest();
}

export function writeEncryptedJson(path: string, value: unknown): void {
  const key = getMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(value));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const payload: EncryptedPayload = {
    v: 1,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64")
  };

  fs.writeFileSync(path, JSON.stringify(payload));
}

export function readEncryptedJson<T>(path: string): T | null {
  if (!fs.existsSync(path)) {
    return null;
  }
  const raw = fs.readFileSync(path, "utf-8");
  const payload = JSON.parse(raw) as EncryptedPayload;
  if (!payload || payload.v !== 1) {
    throw new Error("Invalid encrypted payload.");
  }

  const key = getMasterKey();
  const iv = Buffer.from(payload.iv, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  const data = Buffer.from(payload.data, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(plaintext.toString("utf-8")) as T;
}
