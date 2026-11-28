// Browser relay device driver (todo.md DSR-44): one device's encrypted
// sync against one relay channel, living in the application's JavaScript
// context (the "browser" of the acceptance). The WASM binding provides the
// state primitives — replicator CRUD, the envelope keyring, the receive
// position — while this module owns the wire (fetch append/pull), the
// un-acked outbox, and the durable snapshot.
//
// Persistence model: one IndexedDB record per device holding the versioned
// snapshot (replicator state + receive position + identity) and the sealed
// outbox, written atomically as one `put`. The snapshot IS the commit point
// for the pull cursor: the receive position (and so the next pull's `after`)
// only moves inside the snapshot, so a failed write leaves the durable
// cursor unchanged and a refresh re-pulls from it (idempotently). When
// IndexedDB is absent the driver degrades to an in-memory store and reports
// `mode: "memory"` with a `persistenceWarning` naming the cause.
//
// The WebSocket transport (pairing) is intentionally injected: a browser
// `WebSocket` cannot set an `Authorization` header, so authentication is the
// host's concern (cookie, subprotocol, or a header-capable client in tests).
// The sync wire here is plain `fetch` — no socket — so only pairing needs
// the injection.

import init, * as wasm from "../wasm-gen/syncbond_wasm.js";
import { loadSyncbondWasm } from "./wrapper.js";

const DB_NAME = "syncbond-relay-devices";
const STORE = "devices";
const PROTOCOL_VERSION = 1;
const PULL_LIMIT = 64;

// ------------------------------------------------------------ persistence

function hasIndexedDB() {
  return typeof indexedDB !== "undefined" && indexedDB !== null;
}

function openDb(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbLoad(db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const request = tx.objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}

function idbPut(db, key, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ----------------------------------------------------------------- driver

/**
 * Create one device. `config` is:
 *   { nodeId, relayUrl, channelId, token, serverId, cursorChannel, groupId,
 *     keyEpoch, groupKey32, identity?, dbName?, snapshotBytes? }
 * `groupKey32` is the 32-byte session key (Uint8Array). `identity` is an
 * optional `WasmIdentity`; a fresh one is generated when omitted (the
 * pairing flow hands the same identity to `WasmPairingEnd`). `dbName`
 * renames the IndexedDB database (default `syncbond-relay-devices`) so a
 * host application can keep its devices isolated from other users of this
 * module; `snapshotBytes` (a `WasmReplicator.save()` output) seeds the
 * replicator when no durable record exists yet, so writes made before the
 * device had group facts are carried into the paired device.
 */
export async function createRelayDevice(config) {
  await loadSyncbondWasm();

  const identity = config.identity ?? new wasm.WasmIdentity();
  const keyring = wasm.WasmKeyring.import(config.groupId, config.keyEpoch, config.groupKey32);
  const nodeId = config.nodeId ?? identity.device_id;

  let db = null;
  let mode = "memory";
  let persistenceWarning = null;

  const device = {
    identity,
    keyring,
    nodeId,
    relayUrl: config.relayUrl.replace(/\/$/, ""),
    channelId: config.channelId,
    token: config.token,
    serverId: config.serverId,
    cursorChannel: config.cursorChannel,
    groupId: config.groupId,
    keyEpoch: config.keyEpoch,
    outbox: [],
    replicator: null,
    receive: null,
    db: null,
    failCommit: false,
    mode: "memory",
    persistenceWarning: null,
  };

  const restore = (snapshotBytes, outbox) => {
    const [replicator, receive] = wasm.WasmReplicator.load_snapshot(
      snapshotBytes,
      wasm.strategy_lww_hlc(),
    );
    device.replicator = replicator;
    device.receive = receive;
    device.outbox = outbox ?? [];
  };

  if (hasIndexedDB()) {
    try {
      db = await openDb(config.dbName ?? DB_NAME);
      device.db = db;
      mode = "indexeddb";
      const saved = await idbLoad(db, nodeId);
      if (saved) {
        restore(new Uint8Array(saved.snapshot), saved.outbox);
      } else if (config.snapshotBytes) {
        // A host that staged writes before the device had group facts hands
        // them over here; a durable record, when one exists, always wins.
        device.replicator = wasm.WasmReplicator.load(config.snapshotBytes);
        device.receive = new wasm.WasmReceiveState();
      } else {
        device.replicator = new wasm.WasmReplicator(nodeId);
        device.receive = new wasm.WasmReceiveState();
      }
    } catch (error) {
      // A blocked/failed IndexedDB must not take the app down; degrade to
      // memory with an explicit reason.
      device.db = null;
      mode = "memory";
      persistenceWarning = `IndexedDB unavailable (${error?.message ?? error}); state is memory-only and will be lost on reload`;
    }
  } else {
    persistenceWarning =
      "IndexedDB is not available in this environment; state is memory-only and will be lost on reload";
  }

  if (!device.replicator) {
    device.replicator = config.snapshotBytes
      ? wasm.WasmReplicator.load(config.snapshotBytes)
      : new wasm.WasmReplicator(nodeId);
    device.receive = new wasm.WasmReceiveState();
  }
  device.mode = mode;
  device.persistenceWarning = persistenceWarning;
  return device;
}

// -------------------------------------------------------------- persistence

/** The durable record for this device, or `null` in memory mode.
 *
 * `commit` marks the cursor-advance write — the one the acceptance pins:
 * when `device.failCommit` is set, a commit write throws and the durable
 * snapshot (and so the durable cursor) stays where it was. Staging writes
 * (`write`/`remove`, the append-ack write) do not check the flag, so the
 * hook fails exactly the operation that would have moved the cursor.
 */
export async function persistDevice(device, commit) {
  if (!device.db) return;
  const snapshot = device.replicator.export_snapshot(
    device.identity,
    device.groupId,
    device.keyEpoch,
    device.receive,
  );
  const record = { snapshot: Array.from(snapshot), outbox: device.outbox.slice() };
  if (commit && device.failCommit) {
    device.failCommit = false;
    throw new Error("injected IndexedDB write failure");
  }
  await idbPut(device.db, device.nodeId, record);
}

// ------------------------------------------------------------------- wire

function requestId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `js-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
}

async function appendEnvelopes(device, envelopeObjects) {
  const response = await fetch(
    `${device.relayUrl}/v1/channels/${device.channelId}/append`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${device.token}`,
      },
      body: JSON.stringify({
        protocolVersion: PROTOCOL_VERSION,
        requestId: requestId(),
        envelopes: envelopeObjects,
      }),
    },
  );
  if (!response.ok) {
    throw new Error(`append failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

async function pullAfter(device, after) {
  const response = await fetch(
    `${device.relayUrl}/v1/channels/${device.channelId}/pull`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${device.token}`,
      },
      body: JSON.stringify({
        protocolVersion: PROTOCOL_VERSION,
        requestId: requestId(),
        after,
        limit: PULL_LIMIT,
      }),
    },
  );
  if (!response.ok) {
    throw new Error(`pull failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

// ----------------------------------------------------------------- public

/** Write one record locally and stage it for the next sync. */
export async function write(device, key, payload) {
  const opJson = device.replicator.put(key, payload);
  const envelopeJson = device.keyring.seal(device.identity.device_id, new TextEncoder().encode(opJson));
  device.outbox.push(envelopeJson);
  await persistDevice(device);
  return opJson;
}

/** Tombstone one record locally and stage it for the next sync. */
export async function remove(device, key) {
  const opJson = device.replicator.delete(key);
  const envelopeJson = device.keyring.seal(device.identity.device_id, new TextEncoder().encode(opJson));
  device.outbox.push(envelopeJson);
  await persistDevice(device);
  return opJson;
}

/**
 * One sync cycle: push the staged outbox, pull what is new, apply it, and
 * commit the receive position. Returns `{ appended, pulled, applied }`.
 * A failed append stops before any pull; a failed persist leaves the
 * durable cursor where it was (the snapshot is the commit point).
 */
export async function syncOnce(device) {
  const report = { appended: 0, pulled: 0, applied: 0 };
  if (device.outbox.length > 0) {
    const ack = await appendEnvelopes(device, device.outbox.map((json) => JSON.parse(json)));
    const acked = new Set(ack.acks.map((entry) => entry.messageId));
    device.outbox = device.outbox.filter(
      (json) => !acked.has(JSON.parse(json).messageId),
    );
    report.appended = ack.acks.length;
    await persistDevice(device);
  }
  const after = device.receive.server_seq(device.serverId, device.cursorChannel) ?? 0;
  const page = await pullAfter(device, after);
  if (page.entries.length > 0) {
    const opJsons = device.keyring.open_batch(
      page.entries.map((entry) => JSON.stringify(entry.envelope)),
      device.receive,
    );
    for (const opJson of opJsons) {
      if (device.replicator.apply_remote_op(opJson)) {
        report.applied += 1;
      }
    }
    device.receive.set_server_cursor(device.serverId, device.cursorChannel, page.nextCursor);
    report.pulled = page.entries.length;
    await persistDevice(device, true);
  }
  return report;
}

/** Rebuild this device from its durable record (crash-restart path). */
export async function refresh(device) {
  if (!device.db) return device;
  const saved = await idbLoad(device.db, device.nodeId);
  if (!saved) return device;
  const [replicator, receive] = wasm.WasmReplicator.load_snapshot(
    new Uint8Array(saved.snapshot),
    wasm.strategy_lww_hlc(),
  );
  device.replicator = replicator;
  device.receive = receive;
  device.outbox = saved.outbox ?? [];
  return device;
}

/**
 * The pull cursor as it is *durable* right now: the one a refresh would
 * resume from. Contrast with `receiveCursor`, which is in-memory — the two
 * differ exactly when a persist failed, and `refresh` reverts the memory to
 * this value.
 */
export async function durableCursor(device) {
  if (!device.db) return null;
  const saved = await idbLoad(device.db, device.nodeId);
  if (!saved) return 0;
  const [, receive] = wasm.WasmReplicator.load_snapshot(
    new Uint8Array(saved.snapshot),
    wasm.strategy_lww_hlc(),
  );
  return receive.server_seq(device.serverId, device.cursorChannel) ?? 0;
}

export function get(device, key) {
  const bytes = device.replicator.get(key);
  return bytes == null ? null : new TextDecoder().decode(bytes);
}

export function keys(device) {
  return device.replicator.keys;
}

export function recordCount(device) {
  return device.replicator.record_count;
}

/** The current receive cursor for this (server, channel), or 0. */
export function receiveCursor(device) {
  return device.receive.server_seq(device.serverId, device.cursorChannel) ?? 0;
}
