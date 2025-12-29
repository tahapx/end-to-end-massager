const DB_NAME = "messager-signal";
const DB_VERSION = 1;
const STORE_NAME = "signal";

let dbPromise: Promise<IDBDatabase> | null = null;
let dbInstance: IDBDatabase | null = null;

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) {
    return dbPromise;
  }
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => {
      dbInstance = request.result;
      resolve(request.result);
    };
    request.onerror = () => reject(request.error);
  });
  return dbPromise;
}

async function getItem(key: string): Promise<string | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(key);
    request.onsuccess = () => {
      resolve(typeof request.result === "string" ? request.result : null);
    };
    request.onerror = () => reject(request.error);
  });
}

async function setItem(key: string, value: string): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.put(value, key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function deleteItem(key: string): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.delete(key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function exportSignalStore(): Promise<Record<string, string>> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const data: Record<string, string> = {};
    const request = store.openCursor();
    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor) {
        if (typeof cursor.value === "string") {
          data[String(cursor.key)] = cursor.value;
        }
        cursor.continue();
      } else {
        resolve(data);
      }
    };
    request.onerror = () => reject(request.error);
  });
}

export async function importSignalStore(
  data: Record<string, string>
): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    for (const [key, value] of Object.entries(data)) {
      store.put(value, key);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function resetSignalDb(): Promise<void> {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
  dbPromise = null;
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
}

export class SignalStore {
  private namespace: string;

  constructor(namespace: string) {
    this.namespace = namespace;
  }

  private key(prefix: string, id: string | number) {
    return `${this.namespace}:${prefix}:${id}`;
  }

  async getMeta(id: string): Promise<string | null> {
    return getItem(this.key("meta", id));
  }

  async setMeta(id: string, value: string): Promise<void> {
    await setItem(this.key("meta", id), value);
  }

  async deleteMeta(id: string): Promise<void> {
    await deleteItem(this.key("meta", id));
  }

  async getIdentity(keyId: string): Promise<string | null> {
    return getItem(this.key("identity", keyId));
  }

  async setIdentity(keyId: string, value: string): Promise<void> {
    await setItem(this.key("identity", keyId), value);
  }

  async getSession(keyId: string): Promise<string | null> {
    return getItem(this.key("session", keyId));
  }

  async setSession(keyId: string, value: string): Promise<void> {
    await setItem(this.key("session", keyId), value);
  }

  async getPreKey(preKeyId: number): Promise<string | null> {
    return getItem(this.key("prekey", preKeyId));
  }

  async setPreKey(preKeyId: number, value: string): Promise<void> {
    await setItem(this.key("prekey", preKeyId), value);
  }

  async deletePreKey(preKeyId: number): Promise<void> {
    await deleteItem(this.key("prekey", preKeyId));
  }

  async getSignedPreKey(signedPreKeyId: number): Promise<string | null> {
    return getItem(this.key("signed-prekey", signedPreKeyId));
  }

  async setSignedPreKey(signedPreKeyId: number, value: string): Promise<void> {
    await setItem(this.key("signed-prekey", signedPreKeyId), value);
  }

  async getSenderKey(keyId: string): Promise<string | null> {
    return getItem(this.key("sender-key", keyId));
  }

  async setSenderKey(keyId: string, value: string): Promise<void> {
    await setItem(this.key("sender-key", keyId), value);
  }
}
