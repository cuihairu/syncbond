// Browser WASM wrapper: loads the wasm-bindgen module (web target), detects
// IndexedDB availability, and exposes replicator operations. When IndexedDB
// is absent the wrapper degrades to an in-memory store and reports the
// limitation through `mode`/`persistenceWarning` so callers can surface it
// instead of silently losing state on reload.
//
// Node (no `indexedDB` global) exercises the degradation path in tests; a
// browser has a real IndexedDB and gets `mode: "indexeddb"`.

import init, * as wasm from "../wasm-gen/syncbond_wasm.js";

let wasmReady = null;

/** Load the wasm module once. In Node the .wasm is read from disk (fetch of
 *  a file:// URL is unsupported); in a browser the glue fetches it relative
 *  to the module URL. */
export function loadSyncbondWasm() {
  if (!wasmReady) {
    wasmReady = (async () => {
      if (typeof process !== "undefined" && process.versions?.node) {
        const { readFileSync } = await import("node:fs");
        const wasmPath = new URL("../wasm-gen/syncbond_wasm_bg.wasm", import.meta.url);
        await init({ module_or_path: readFileSync(wasmPath) });
      } else {
        await init();
      }
    })();
  }
  return wasmReady;
}

function hasIndexedDB() {
  return typeof indexedDB !== "undefined" && indexedDB !== null;
}

// ------------------------------------------------------------- persistence

function openDb(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains("state")) {
        request.result.createObjectStore("state");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbLoad(db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("state", "readonly");
    const request = tx.objectStore("state").get(key);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}

async function idbSave(db, key, bytes) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("state", "readwrite");
    tx.objectStore("state").put(bytes, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ------------------------------------------------------------------ public

const DB_NAME = "syncbond-state";

/**
 * Create a browser replicator with IndexedDB persistence when available.
 *
 * Returns `{ replicator, mode, persistenceWarning, put, delete, get, keys,
 * recordCount, save, load, gcTombstones }`. `mode` is `"indexeddb"` when
 * state survives reloads, otherwise `"memory"` and `persistenceWarning`
 * carries the degradation message.
 */
export async function createBrowserReplicator(nodeId) {
  await loadSyncbondWasm();

  const node = new wasm.WasmReplicator(nodeId);
  let mode = "memory";
  let persistenceWarning = null;
  let db = null;

  if (hasIndexedDB()) {
    try {
      db = await openDb(DB_NAME);
      const saved = await idbLoad(db, nodeId);
      if (saved) {
        const restored = wasm.WasmReplicator.load(new Uint8Array(saved));
        return wrap(restored, nodeId, db, "indexeddb", null);
      }
      mode = "indexeddb";
    } catch (error) {
      // A blocked/failed IndexedDB must not take the app down; degrade to
      // memory with an explicit reason.
      db = null;
      persistenceWarning = `IndexedDB unavailable (${error?.message ?? error}); state is memory-only and will be lost on reload`;
    }
  } else {
    persistenceWarning =
      "IndexedDB is not available in this environment; state is memory-only and will be lost on reload";
  }

  return wrap(node, nodeId, db, mode, persistenceWarning);
}

function wrap(node, nodeId, db, mode, persistenceWarning) {
  const persist = async () => {
    if (db) await idbSave(db, nodeId, node.save());
  };
  return {
    replicator: node,
    mode,
    persistenceWarning,
    async put(key, payload) {
      node.put(key, payload);
      await persist();
    },
    async delete(key) {
      node.delete(key);
      await persist();
    },
    get(key) {
      return node.get(key);
    },
    keys() {
      return node.keys;
    },
    get recordCount() {
      return node.record_count;
    },
    gcTombstones(nowMs, olderThanMs) {
      return node.gcTombstones(nowMs, olderThanMs);
    },
    save() {
      return node.save();
    },
    load(bytes) {
      return wasm.WasmReplicator.load(bytes);
    },
  };
}

export function protocolVersion() {
  return wasm.protocol_version();
}

export function abiVersion() {
  return wasm.abi_version();
}

/** Run a cross-language conformance fixture; returns the report object. */
export function runConformance(fixtureJson) {
  return JSON.parse(wasm.conformance_run(fixtureJson));
}
