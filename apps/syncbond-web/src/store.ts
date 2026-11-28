// The demo's own metadata store. Deliberately separate from the device
// driver's IndexedDB database: this holds only the small pieces the page
// needs before (and across) pairing — the identity secret, the standalone
// replicator's snapshot, and the group facts captured at pairing time.
// Everything lives under one database name, `syncbond-web-demo`, so the
// demo's state can never collide with the bindings' own database or a
// future production frontend (dispatch SYNCBOND-WEB-001 isolation rule).

const DB_NAME = "syncbond-web-demo";
const STORE = "meta";

export interface PairedFacts {
  /** The SPAKE2 role this end played (the greeting decided it). */
  role: "initiator" | "responder";
  groupId: string;
  keyEpoch: number;
  /** The session's group key, base64. Private material. */
  groupKeyB64: string;
  peerDeviceId: string;
  channelId: string;
  token: string;
  serverId: string;
}

interface MetaRecord {
  identity?: number[];
  replicator?: number[];
  paired?: PairedFacts;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function loadAll(): Promise<MetaRecord> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const request = tx.objectStore(STORE).get("state");
    request.onsuccess = () => resolve((request.result as MetaRecord | undefined) ?? {});
    request.onerror = () => reject(request.error);
  });
}

async function save(patch: MetaRecord): Promise<void> {
  const db = await openDb();
  const current = await loadAll();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put({ ...current, ...patch }, "state");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ------------------------------------------------------------- base64

export function bytesToB64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

export function b64ToBytes(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ------------------------------------------------------------- public API

export interface DemoMeta {
  identityBytes: Uint8Array | null;
  replicatorBytes: Uint8Array | null;
  paired: PairedFacts | null;
}

export async function loadMeta(): Promise<DemoMeta> {
  const record = await loadAll();
  return {
    identityBytes: record.identity ? new Uint8Array(record.identity) : null,
    replicatorBytes: record.replicator ? new Uint8Array(record.replicator) : null,
    paired: record.paired ?? null,
  };
}

export async function saveIdentity(identityBytes: Uint8Array): Promise<void> {
  await save({ identity: Array.from(identityBytes) });
}

export async function saveReplicator(replicatorBytes: Uint8Array): Promise<void> {
  await save({ replicator: Array.from(replicatorBytes) });
}

export async function savePaired(facts: PairedFacts): Promise<void> {
  await save({ paired: facts });
}

/** Wipe every trace of the demo: identity, replicator, and pairing. */
export async function resetDemo(): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
