// A hand-rolled IndexedDB stand-in for the DSR-44 acceptance, so the browser
// persistence path is exercised without a browser and without an npm
// dependency. It implements only what the driver uses: `open`, an upgrade
// that creates one store, and a single-key store of whole records with
// transaction `oncomplete`.
//
// Two independent "browser contexts" are two independent factories: each has
// its own databases and keys, which is exactly the IndexedDB partitioning a
// real browser gives per origin — the driver must therefore sync its state
// with its peers through the relay, never by reaching into the other
// context's store.

const ASYNC = (fn) => {
  queueMicrotask(fn);
};

class FakeRequest {
  constructor() {
    this.result = undefined;
    this.error = null;
    this.onsuccess = null;
    this.onerror = null;
  }
}

class FakeObjectStore {
  constructor(store, transaction) {
    this._store = store;
    this._tx = transaction;
  }

  get(key) {
    const request = new FakeRequest();
    ASYNC(() => {
      const stored = this._store.data.get(key);
      request.result = stored === undefined ? null : stored;
      request.onsuccess?.();
    });
    return request;
  }

  put(value, key) {
    const request = new FakeRequest();
    ASYNC(() => {
      this._store.data.set(key, value);
      request.result = key;
      request.onsuccess?.();
      // A single-key store with one put per transaction: completion follows
      // the write in its own microtask, as IndexedDB does.
      ASYNC(() => this._tx.oncomplete?.());
    });
    return request;
  }
}

class FakeTransaction {
  constructor(db) {
    this.db = db;
    this.error = null;
    this.oncomplete = null;
    this.onerror = null;
  }

  objectStore(name) {
    const store = this.db.stores.get(name);
    if (!store) throw new Error(`unknown object store: ${name}`);
    return new FakeObjectStore(store, this);
  }
}

class FakeDatabase {
  constructor(name) {
    this.name = name;
    this.stores = new Map();
    this._names = new Set();
  }

  get objectStoreNames() {
    return this;
  }

  contains(name) {
    return this._names.has(name);
  }

  createObjectStore(name) {
    this._names.add(name);
    this.stores.set(name, { name, data: new Map() });
  }

  objectStore(name) {
    const store = this.stores.get(name);
    if (!store) throw new Error(`unknown object store: ${name}`);
    return new FakeObjectStore(store);
  }

  transaction(name) {
    return new FakeTransaction(this);
  }
}

class FakeIDBFactory {
  constructor() {
    this._databases = new Map();
  }

  open(name, version) {
    const request = new FakeRequest();
    ASYNC(() => {
      let db = this._databases.get(name);
      if (!db) {
        db = new FakeDatabase(name);
        this._databases.set(name, db);
        request.result = db;
        request.onupgradeneeded?.();
      } else {
        request.result = db;
      }
      request.onsuccess?.();
    });
    return request;
  }
}

/**
 * Install a fresh IndexedDB-like factory as `globalThis.indexedDB` (one
 * "browser context") and return it. `globalThis.indexedDB = null` removes
 * IndexedDB again, which is the driver's degradation branch.
 */
export function installFakeIndexedDB() {
  const factory = new FakeIDBFactory();
  globalThis.indexedDB = factory;
  return factory;
}

export function removeIndexedDB() {
  globalThis.indexedDB = undefined;
}
