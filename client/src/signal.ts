import { Buffer } from "buffer";
import {
  Direction,
  KeyHelper,
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
  type KeyPairType,
  type SignedPreKeyPairType,
  type StorageType
} from "@privacyresearch/libsignal-protocol-typescript";
import {
  SignalStore,
  resetSignalDb,
  exportSignalStore,
  importSignalStore
} from "./signalStore";

const DEVICE_ID = 1;
const PREKEY_BATCH = 30;

const contextCache = new Map<string, SignalContext>();

type SignalContext = {
  username: string;
  store: SignalStore;
  storage: StorageType;
};

type LocalKeyBundle = {
  identityKey: string;
  registrationId: number;
  deviceId: number;
  signedPreKeyId: number;
  signedPreKey: string;
  signedPreKeySig: string;
  oneTimePreKeys: Array<{ id: number; key: string }>;
};

type DeviceBundle = {
  registrationId: number;
  deviceId: number;
  sessionDeviceId?: string;
  identityKey: string;
  signedPreKeyId: number;
  signedPreKey: string;
  signedPreKeySig: string;
  oneTimePreKey?: { id: number; key: string } | null;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function ensureBufferGlobal() {
  const globalAny = globalThis as typeof globalThis & { Buffer?: typeof Buffer };
  if (!globalAny.Buffer) {
    globalAny.Buffer = Buffer;
  }
}

ensureBufferGlobal();

function toBase64(buffer: ArrayBuffer): string {
  return Buffer.from(new Uint8Array(buffer)).toString("base64");
}

function fromBase64(value: string): ArrayBuffer {
  const buffer = Buffer.from(value, "base64");
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

function binaryToBase64(value: string): string {
  return Buffer.from(value, "binary").toString("base64");
}

function base64ToBinary(value: string): string {
  return Buffer.from(value, "base64").toString("binary");
}

function serializeKeyPair(keyPair: KeyPairType): string {
  return JSON.stringify({
    pub: toBase64(keyPair.pubKey),
    priv: toBase64(keyPair.privKey)
  });
}

function parseKeyPair(raw: string): KeyPairType {
  const parsed = JSON.parse(raw) as { pub: string; priv: string };
  return {
    pubKey: fromBase64(parsed.pub),
    privKey: fromBase64(parsed.priv)
  };
}

function randomId(): number {
  return Math.floor(Math.random() * (2 ** 31 - 1));
}

function createStorage(store: SignalStore): StorageType {
  return {
    async getIdentityKeyPair() {
      const raw = await store.getMeta("identityKeyPair");
      return raw ? parseKeyPair(raw) : undefined;
    },
    async getLocalRegistrationId() {
      const raw = await store.getMeta("registrationId");
      return raw ? Number(raw) : undefined;
    },
    async isTrustedIdentity(
      identifier: string,
      identityKey: ArrayBuffer,
      _direction: Direction
    ) {
      const existing = await store.getIdentity(identifier);
      if (!existing) {
        return true;
      }
      return existing === toBase64(identityKey);
    },
    async saveIdentity(
      encodedAddress: string,
      publicKey: ArrayBuffer,
      _nonblockingApproval?: boolean
    ) {
      const serialized = toBase64(publicKey);
      const existing = await store.getIdentity(encodedAddress);
      await store.setIdentity(encodedAddress, serialized);
      return existing ? existing !== serialized : true;
    },
    async loadPreKey(keyId: number | string) {
      const raw = await store.getPreKey(Number(keyId));
      return raw ? parseKeyPair(raw) : undefined;
    },
    async storePreKey(keyId: number | string, keyPair: KeyPairType) {
      await store.setPreKey(Number(keyId), serializeKeyPair(keyPair));
    },
    async removePreKey(keyId: number | string) {
      await store.deletePreKey(Number(keyId));
    },
    async storeSession(encodedAddress: string, record: string) {
      await store.setSession(encodedAddress, record);
    },
    async loadSession(encodedAddress: string) {
      const raw = await store.getSession(encodedAddress);
      return raw ?? undefined;
    },
    async loadSignedPreKey(keyId: number | string) {
      const raw = await store.getSignedPreKey(Number(keyId));
      return raw ? parseKeyPair(raw) : undefined;
    },
    async storeSignedPreKey(keyId: number | string, keyPair: KeyPairType) {
      await store.setSignedPreKey(Number(keyId), serializeKeyPair(keyPair));
    },
    async removeSignedPreKey(keyId: number | string) {
      await store.setSignedPreKey(Number(keyId), "");
    }
  };
}

async function getContext(username: string): Promise<SignalContext> {
  const cached = contextCache.get(username);
  if (cached) {
    return cached;
  }
  const store = new SignalStore(`${username}:web-v1`);
  const storage = createStorage(store);
  const context: SignalContext = { username, store, storage };
  contextCache.set(username, context);
  return context;
}

async function resetPreKeys(store: SignalStore) {
  const raw = await store.getMeta("preKeyIds");
  const ids = raw ? (JSON.parse(raw) as number[]) : [];
  for (const id of ids) {
    await store.deletePreKey(id);
  }
  await store.setMeta("preKeyIds", JSON.stringify([]));
}

async function ensureIdentityKeys(
  context: SignalContext,
  force: boolean
): Promise<{ identityKeyPair: KeyPairType; registrationId: number }> {
  let identityKeyPair = await context.store.getMeta("identityKeyPair");
  let registrationId = await context.store.getMeta("registrationId");

  if (!identityKeyPair || !registrationId || force) {
    const newIdentity = await KeyHelper.generateIdentityKeyPair();
    const newRegistration = KeyHelper.generateRegistrationId();
    await context.store.setMeta("identityKeyPair", serializeKeyPair(newIdentity));
    await context.store.setMeta("registrationId", String(newRegistration));
    identityKeyPair = serializeKeyPair(newIdentity);
    registrationId = String(newRegistration);
  }

  return {
    identityKeyPair: parseKeyPair(identityKeyPair),
    registrationId: Number(registrationId)
  };
}

async function ensureSignedPreKey(
  context: SignalContext,
  identityKeyPair: KeyPairType,
  force: boolean
): Promise<{ signedPreKeyId: number; signedPreKey: SignedPreKeyPairType }> {
  let signedPreKeyId = await context.store.getMeta("signedPreKeyId");
  let signedPreKeyRaw = await context.store.getMeta("signedPreKey");

  if (!signedPreKeyId || !signedPreKeyRaw || force) {
    const nextId = randomId();
    const signedPreKey = await KeyHelper.generateSignedPreKey(
      identityKeyPair,
      nextId
    );
    await context.store.setMeta("signedPreKeyId", String(nextId));
    await context.store.setMeta(
      "signedPreKey",
      JSON.stringify({
        keyPair: serializeKeyPair(signedPreKey.keyPair),
        signature: toBase64(signedPreKey.signature)
      })
    );
    signedPreKeyId = String(nextId);
    signedPreKeyRaw = await context.store.getMeta("signedPreKey");
  }

  const parsed = JSON.parse(signedPreKeyRaw!) as {
    keyPair: string;
    signature: string;
  };

  return {
    signedPreKeyId: Number(signedPreKeyId),
    signedPreKey: {
      keyId: Number(signedPreKeyId),
      keyPair: parseKeyPair(parsed.keyPair),
      signature: fromBase64(parsed.signature)
    }
  };
}

export async function ensureLocalKeys(
  username: string,
  force: boolean
): Promise<LocalKeyBundle | null> {
  const context = await getContext(username);
  const { identityKeyPair, registrationId } = await ensureIdentityKeys(
    context,
    force
  );
  const { signedPreKeyId, signedPreKey } = await ensureSignedPreKey(
    context,
    identityKeyPair,
    force
  );

  if (force) {
    await resetPreKeys(context.store);
  }

  const preKeys = [];
  for (let i = 0; i < PREKEY_BATCH; i += 1) {
    const keyId = randomId();
    const preKey = await KeyHelper.generatePreKey(keyId);
    await context.storage.storePreKey(keyId, preKey.keyPair);
    preKeys.push({ id: keyId, key: toBase64(preKey.keyPair.pubKey) });
  }
  await context.store.setMeta(
    "preKeyIds",
    JSON.stringify(preKeys.map((entry) => entry.id))
  );

  await context.storage.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);

  return {
    identityKey: toBase64(identityKeyPair.pubKey),
    registrationId,
    deviceId: DEVICE_ID,
    signedPreKeyId,
    signedPreKey: toBase64(signedPreKey.keyPair.pubKey),
    signedPreKeySig: toBase64(signedPreKey.signature),
    oneTimePreKeys: preKeys
  };
}

export async function ensureSession(
  localUsername: string,
  remoteUsername: string,
  bundle: DeviceBundle
): Promise<void> {
  const context = await getContext(localUsername);
  const address = new SignalProtocolAddress(
    remoteUsername,
    bundle.deviceId || 1
  );

  const existing = await context.storage.loadSession(address.toString());
  if (existing) {
    return;
  }

  const builder = new SessionBuilder(context.storage, address);
  await builder.processPreKey({
    registrationId: bundle.registrationId,
    identityKey: fromBase64(bundle.identityKey),
    signedPreKey: {
      keyId: bundle.signedPreKeyId,
      publicKey: fromBase64(bundle.signedPreKey),
      signature: fromBase64(bundle.signedPreKeySig)
    },
    preKey: bundle.oneTimePreKey
      ? {
          keyId: bundle.oneTimePreKey.id,
          publicKey: fromBase64(bundle.oneTimePreKey.key)
        }
      : undefined
  });
}

export async function encryptSignalMessage(
  localUsername: string,
  remoteUsername: string,
  deviceId: number,
  plaintext: string
): Promise<{ ciphertext: string; nonce: string }> {
  const context = await getContext(localUsername);
  const address = new SignalProtocolAddress(remoteUsername, deviceId || 1);
  const cipher = new SessionCipher(context.storage, address);
  const message = await cipher.encrypt(encoder.encode(plaintext).buffer);
  const body = message.body || "";
  return {
    ciphertext: binaryToBase64(body),
    nonce: `signal:v1:${message.type}`
  };
}

export async function resetSignalState(): Promise<void> {
  contextCache.clear();
  await resetSignalDb();
}

export async function exportSignalState(): Promise<Record<string, string>> {
  return exportSignalStore();
}

export async function importSignalState(
  data: Record<string, string>
): Promise<void> {
  contextCache.clear();
  await importSignalStore(data);
}

export async function decryptSignalMessage(
  localUsername: string,
  remoteUsername: string,
  deviceId: number,
  ciphertext: string,
  nonce: string
): Promise<string> {
  const context = await getContext(localUsername);
  const address = new SignalProtocolAddress(remoteUsername, deviceId || 1);
  const cipher = new SessionCipher(context.storage, address);
  const typeRaw = nonce.split(":")[2] || "1";
  const parsedType = Number(typeRaw);
  const type = parsedType === 3 ? 3 : 1;
  const binary = base64ToBinary(ciphertext);
  try {
    const plaintext =
      type === 3
        ? await cipher.decryptPreKeyWhisperMessage(binary, "binary")
        : await cipher.decryptWhisperMessage(binary, "binary");
    return decoder.decode(new Uint8Array(plaintext));
  } catch (error) {
    // Fallback to the other decrypt mode for mixed/legacy traffic.
    const fallback =
      type === 3
        ? await cipher.decryptWhisperMessage(binary, "binary")
        : await cipher.decryptPreKeyWhisperMessage(binary, "binary");
    return decoder.decode(new Uint8Array(fallback));
  }
}

export async function createSenderKeyDistribution(): Promise<{
  message: string;
}> {
  throw new Error("Sender keys are not supported in the browser build.");
}

export async function processSenderKeyDistribution(): Promise<void> {
  throw new Error("Sender keys are not supported in the browser build.");
}

export async function encryptGroupMessage(): Promise<{
  ciphertext: string;
  nonce: string;
}> {
  throw new Error("Group sender keys are not supported in the browser build.");
}

export async function decryptGroupMessage(): Promise<string> {
  throw new Error("Group sender keys are not supported in the browser build.");
}

export function hasSenderKeySent(): boolean {
  return false;
}

export function markSenderKeySent(): void {
  // no-op
}
