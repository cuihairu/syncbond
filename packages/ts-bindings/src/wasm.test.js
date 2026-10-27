import assert from "node:assert/strict";
import test from "node:test";
import {
  abiVersion,
  createBrowserReplicator,
  loadSyncbondWasm,
  protocolVersion,
  runConformance,
} from "./wasm/wrapper.js";

// The cross-language conformance fixture: two LWW nodes converge on a key
// (the newer write wins on both sides) and a key-epoch rotation rejects the
// removed device's attempt to open the envelope sealed after rotation.
const FIXTURE = {
  version: 1,
  scenarios: [
    {
      type: "replication",
      name: "lww",
      strategy: "lww",
      nodes: { left: 1000, right: 2000 },
      steps: [
        { put: { node: "left", key: "k", payload: "bGVmdA" } },
        {
          put: { node: "right", key: "k", payload: "cmlnaHQ", name: "right_writes_newer" },
        },
        { sync: ["left", "right"] },
        {
          check: {
            node: "left",
            key: "k",
            state: "live",
            payload: "cmlnaHQ",
            name: "left_sees_newer_write",
          },
        },
        {
          check: {
            node: "right",
            key: "k",
            state: "live",
            payload: "cmlnaHQ",
            name: "right_keeps_newer_write",
          },
        },
      ],
    },
    {
      type: "key_epoch",
      name: "rotation",
      group: "g",
      epoch: 1,
      next_epoch: 2,
      key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      next_key: "__________________________________________8",
      survivors: ["s1"],
      removed: ["gone"],
      plaintext: "cGF5bG9hZA",
    },
  ],
};

test("wasm loads and reports versions", async () => {
  await loadSyncbondWasm();
  assert.ok(protocolVersion() > 0);
  assert.equal(abiVersion(), 1);
});

test("wasm replicator CRUD and save/load round-trip", async () => {
  await loadSyncbondWasm();
  const node = new (await import("./wasm-gen/syncbond_wasm.js")).WasmReplicator("wasm-a");
  node.put("greeting", new TextEncoder().encode("hello"));
  node.put("doc", new TextEncoder().encode("doc v1"));
  assert.deepEqual(node.keys, ["doc", "greeting"]);
  assert.equal(node.record_count, 2);
  assert.equal(new TextDecoder().decode(node.get("greeting")), "hello");

  // Persistence round-trip: bytes out of save() rebuild an identical store.
  const bytes = node.save();
  const restored = (await import("./wasm-gen/syncbond_wasm.js")).WasmReplicator.load(bytes);
  assert.deepEqual(restored.keys, ["doc", "greeting"]);
  assert.equal(new TextDecoder().decode(restored.get("doc")), "doc v1");

  node.delete("doc");
  assert.deepEqual(node.keys, ["greeting"]);
  // wasm-bindgen maps `Option::None` to `undefined` (the napi path returns
  // null); both are falsy, so consumers checking absence work either way.
  assert.equal(node.get("doc"), undefined);
});

test("no IndexedDB degrades to memory with an explicit warning", async () => {
  // Node has no `indexedDB` global; the wrapper must degrade clearly rather
  // than fail silently or pretend state is durable.
  const store = await createBrowserReplicator("wasm-degrade");
  assert.equal(store.mode, "memory");
  assert.ok(
    store.persistenceWarning && store.persistenceWarning.includes("IndexedDB"),
    `degradation message must name the cause, got: ${store.persistenceWarning}`,
  );
  await store.put("k", new TextEncoder().encode("v"));
  assert.equal(new TextDecoder().decode(store.get("k")), "v");
  assert.equal(store.recordCount, 1);
});

test("wasm runs the cross-language conformance fixture", async () => {
  await loadSyncbondWasm();
  const report = runConformance(JSON.stringify(FIXTURE));
  assert.equal(report.version, 1);
  assert.equal(report.ok, true, JSON.stringify(report));
  const replication = report.scenarios.find((scenario) => scenario.type === "replication");
  assert.ok(replication, "replication scenario present");
  assert.ok(replication.checks.every((check) => check.ok));
});
