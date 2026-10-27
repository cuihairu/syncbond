import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  abiVersion,
  createBrowserReplicator,
  loadSyncbondWasm,
  protocolVersion,
  runConformance,
} from "./wasm/wrapper.js";

// The canonical cross-language fixture, shared by every binding
// (crates/syncbond-ffi/fixtures/conformance.json). The same on-disk file
// drives the merge / tombstone-GC / key-epoch scenarios byte-identically
// across languages.
const fixture = readFileSync(
  fileURLToPath(
    new URL("../../../crates/syncbond-ffi/fixtures/conformance.json", import.meta.url),
  ),
  "utf8",
);
const canonicalReport = readFileSync(
  fileURLToPath(
    new URL("../../../crates/syncbond-ffi/fixtures/conformance.expected.json", import.meta.url),
  ),
  "utf8",
);

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
  const report = runConformance(fixture);
  assert.equal(report.version, 1);
  assert.equal(report.ok, true, JSON.stringify(report));
  assert.deepEqual(
    report.scenarios.map((scenario) => scenario.name).sort(),
    [
      "malformed_pn_counter_payload_is_rejected",
      "malformed_strategy_payload_is_rejected",
      "merge_lww",
      "rotation",
      "tombstone_gc_blocks_resurrection",
    ],
  );
  for (const scenario of report.scenarios) {
    assert.equal(scenario.ok, true, `scenario ${scenario.name}`);
    assert.ok(scenario.checks.every((check) => check.ok));
  }
  const rotation = report.scenarios.find((scenario) => scenario.name === "rotation");
  const gone = rotation.rotations.find((row) => row.device === "gone");
  assert.equal(gone.opened_rotated, false);
  assert.equal(gone.rotated_error, -5);
  // The runner output is deterministic: byte-for-byte equality against the
  // canonical report pins any language drift (mangled fixture or report).
  // (serde_json emits keys in sorted order, which JSON.parse/stringify
  // preserves, so the re-serialized object matches the canonical bytes.)
  assert.equal(JSON.stringify(runConformance(fixture)), canonicalReport);
});
