import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  NativeIdentity,
  NativeReplicator,
  conformanceRun,
  pairMemory,
  protocolVersion,
} from "./native/binding.js";

// The canonical cross-language fixture, shared by every binding
// (crates/syncbond-ffi/fixtures/conformance.json). The same on-disk file
// drives the merge / tombstone-GC / key-epoch scenarios byte-identically
// across languages.
const canonicalFixture = readFileSync(
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

test("protocol version is exposed", () => {
  assert.equal(typeof protocolVersion(), "number");
  assert.ok(protocolVersion() > 0);
});

test("identity generates distinct device ids and keys", () => {
  const a = NativeIdentity.generate();
  const b = NativeIdentity.generate();
  assert.notEqual(a.deviceId, b.deviceId);
  assert.equal(a.publicKey.length, 32);
});

test("pair/sync e2e: two devices converge bidirectionally", async () => {
  const pairing = pairMemory("SYNC77");
  const initiator = pairing.initiatorSession();
  const responder = pairing.responderSession();
  assert.equal(initiator.invalidated, false);
  assert.equal(initiator.groupId, responder.groupId);
  assert.ok(initiator.peerDeviceId.length > 0);
  assert.notEqual(initiator.peerDeviceId, responder.peerDeviceId);

  const deviceA = new NativeReplicator("ts-device-a");
  const deviceB = new NativeReplicator("ts-device-b");

  deviceA.put("greeting", Buffer.from("hello from A"));
  deviceA.put("doc:1", Buffer.from("A writes first"));
  deviceB.put("reply", Buffer.from("hi from B"));

  // Both halves of the exchange run concurrently: A sends then receives,
  // B receives then sends.
  const [statsA, statsB] = await Promise.all([
    deviceA.sync(initiator, true),
    deviceB.sync(responder, false),
  ]);

  assert.equal(statsA.sentOps, 2);
  assert.equal(statsB.sentOps, 1);

  // Both directions carried data across the encrypted channel.
  assert.equal(Buffer.from(deviceB.get("greeting")).toString(), "hello from A");
  assert.equal(Buffer.from(deviceA.get("reply")).toString(), "hi from B");
  assert.equal(deviceA.recordCount, 3);
  assert.equal(deviceB.recordCount, 3);

  // Second round: more writes and a delete propagate incrementally, with
  // the full-oplog resend deduplicated by op id.
  deviceB.put("reply", Buffer.from("edited by B"));
  deviceB.delete("doc:1");
  deviceA.put("doc:2", Buffer.from("second doc"));

  await Promise.all([
    deviceA.sync(initiator, true),
    deviceB.sync(responder, false),
  ]);

  assert.deepEqual(deviceA.keys(), ["doc:2", "greeting", "reply"]);
  assert.deepEqual(deviceB.keys(), ["doc:2", "greeting", "reply"]);
  assert.equal(Buffer.from(deviceA.get("reply")).toString(), "edited by B");
  assert.equal(Buffer.from(deviceB.get("doc:2")).toString(), "second doc");
  assert.equal(deviceA.get("doc:1"), null);
  assert.equal(deviceB.get("doc:1"), null);
  assert.equal(deviceA.recordCount, 4);
  assert.equal(deviceB.recordCount, 4);
});

test("invalidated session refuses to sync", async () => {
  const pairing = pairMemory("SYNC99");
  const initiator = pairing.initiatorSession();
  initiator.invalidate();
  assert.equal(initiator.invalidated, true);
  const device = new NativeReplicator("ts-late");
  device.put("k", Buffer.from("v"));
  await assert.rejects(() => device.sync(initiator, true));
});

test("conformance: canonical fixture passes all named checks", () => {
  const report = JSON.parse(conformanceRun(canonicalFixture));
  assert.equal(report.ok, true);
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
    for (const check of scenario.checks) {
      assert.equal(check.ok, true, `${scenario.name}:${check.name}`);
    }
  }
  const rotation = report.scenarios.find((scenario) => scenario.name === "rotation");
  const gone = rotation.rotations.find((row) => row.device === "gone");
  assert.equal(gone.opened_rotated, false);
  assert.equal(gone.rotated_error, -5);
  // The runner output is deterministic: byte-for-byte equality against the
  // canonical report pins any language drift (mangled fixture or report).
  assert.equal(conformanceRun(canonicalFixture), canonicalReport);
});
