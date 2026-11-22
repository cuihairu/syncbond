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

// ------------------------------------- DSR-43: single-thread network core

test("wasm identity export/import round-trip", async () => {
  await loadSyncbondWasm();
  const wasm = await import("./wasm-gen/syncbond_wasm.js");

  const identity = new wasm.WasmIdentity();
  const exported = identity.export();
  assert.equal(exported.length, 64, "the secret key is 64 bytes");

  const restored = wasm.WasmIdentity.import(exported);
  assert.equal(restored.device_id, identity.device_id);
  assert.deepEqual(Array.from(restored.public_key), Array.from(identity.public_key));

  // A wrong-length key is rejected, not silently accepted as another identity.
  assert.throws(() => wasm.WasmIdentity.import(new Uint8Array(63)));
});

test("wasm drives a pairing frame exchange to completion", async () => {
  await loadSyncbondWasm();
  const wasm = await import("./wasm-gen/syncbond_wasm.js");
  const code = "K7Q2M4";
  const identityA = new wasm.WasmIdentity();
  const identityB = new wasm.WasmIdentity();
  const a = new wasm.WasmPairingEnd(identityA, wasm.pairing_role_initiator(), code);
  const b = new wasm.WasmPairingEnd(identityB, wasm.pairing_role_responder(), code);

  // One wire round: drain both outboxes and hand every frame to the other
  // end unless it already finished. The host owns the wire — this loop is
  // the whole of the exchange's transport.
  const drain = (end) => {
    const frames = [];
    let frame = end.pop_outgoing();
    while (frame) {
      frames.push(frame);
      frame = end.pop_outgoing();
    }
    return frames;
  };
  const wireRound = () => {
    for (const frame of drain(a)) if (!b.is_finished) b.push(frame);
    for (const frame of drain(b)) if (!a.is_finished) a.push(frame);
    return a.is_finished && b.is_finished;
  };

  let rounds = 0;
  while (!wireRound()) {
    rounds += 1;
    assert.ok(rounds <= 6, `the exchange wedged after ${rounds} rounds`);
  }

  const eventA = a.poll();
  const eventB = b.poll();
  assert.equal(eventA, wasm.pairing_event_completed());
  assert.equal(eventB, wasm.pairing_event_completed());

  const sessionA = a.take_session();
  const sessionB = b.take_session();
  assert.equal(sessionA.group_id, sessionB.group_id);
  assert.equal(sessionA.peer_device_id, identityB.device_id);
  assert.equal(sessionB.peer_device_id, identityA.device_id);
  assert.equal(sessionA.invalidated, false);
});

test("wasm applies a remote op and advances its receive position", async () => {
  await loadSyncbondWasm();
  const wasm = await import("./wasm-gen/syncbond_wasm.js");

  const sender = new wasm.WasmReplicator("wasm-remote-a");
  const receiver = new wasm.WasmReplicator("wasm-remote-b");
  sender.put("shared", new TextEncoder().encode("remote value"));
  const opJson = sender.op_json(0);

  assert.equal(receiver.apply_remote_op(opJson), true, "a first application applies");
  assert.equal(new TextDecoder().decode(receiver.get("shared")), "remote value");
  assert.equal(receiver.apply_remote_op(opJson), false, "a redelivery is a no-op");

  // The receive position carries the pull cursor and the dedup knowledge; it
  // is what a restart needs to avoid re-pulling what it already applied.
  const receive = new wasm.WasmReceiveState();
  receive.set_server_cursor("relay-1", "ch", 41);
  receive.set_source_cursor("wasm-remote-a", 1);
  receive.mark_seen("message-1");
  assert.equal(receive.server_seq("relay-1", "ch"), 41);
  assert.equal(receive.server_seq("relay-1", "missing"), undefined);
  assert.equal(receive.seen("message-1"), true);
  assert.equal(receive.seen("other"), false);
});

test("wasm recovers full state from an exported snapshot", async () => {
  await loadSyncbondWasm();
  const wasm = await import("./wasm-gen/syncbond_wasm.js");

  const identity = new wasm.WasmIdentity();
  const node = new wasm.WasmReplicator(identity.device_id);
  node.put("a", new TextEncoder().encode("a1"));
  node.put("b", new TextEncoder().encode("b1"));
  node.delete("b");

  const receive = new wasm.WasmReceiveState();
  receive.set_server_cursor("relay-1", "ch", 7);
  receive.mark_seen("message-42");

  const snapshot = node.export_snapshot(identity, "group-1", 2, receive);
  assert.ok(snapshot.length > 0);

  const [restored, restoredReceive] = wasm.WasmReplicator.load_snapshot(
    snapshot,
    wasm.strategy_lww_hlc(),
  );
  assert.equal(restored.node_id, identity.device_id);
  assert.deepEqual(restored.keys, ["a"], "the live key survives, the tombstone does not");
  assert.equal(new TextDecoder().decode(restored.get("a")), "a1");
  assert.equal(restored.get("b"), undefined);
  assert.equal(restoredReceive.server_seq("relay-1", "ch"), 7);
  assert.equal(restoredReceive.seen("message-42"), true);

  // The restored device keeps syncing: a second round trip is byte-stable.
  const again = restored.export_snapshot(identity, "group-1", 2, restoredReceive);
  const [third, thirdReceive] = wasm.WasmReplicator.load_snapshot(
    again,
    wasm.strategy_lww_hlc(),
  );
  assert.deepEqual(third.keys, ["a"]);
  assert.equal(new TextDecoder().decode(third.get("a")), "a1");
  assert.equal(thirdReceive.server_seq("relay-1", "ch"), 7);
});
