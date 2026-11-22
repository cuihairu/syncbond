// Browser-context relay acceptance (todo.md DSR-44): two independent browser
// contexts pair over the relay's WebSocket room (the header-capable injected
// transport, since a browser `WebSocket` cannot set `Authorization`), sync
// encrypted operations through a real relay channel, recover after a refresh
// from IndexedDB, and degrade explicitly when IndexedDB is absent.
//
// "Two independent browser contexts" are two `createRelayDevice` instances
// with separate fake-IndexedDB factories — the partitioning a real browser
// gives per origin — sharing one real relay. The Rust harness boots the
// relay in-process and exports SYNCBOND_TEST_RELAY / SYNCBOND_TEST_ADMIN;
// without those the suite skips.

import assert from "node:assert/strict";
import test from "node:test";
import { loadSyncbondWasm } from "./wasm/wrapper.js";
import {
  createRelayDevice,
  durableCursor,
  get,
  keys,
  receiveCursor,
  refresh,
  remove,
  syncOnce,
  write,
} from "./wasm/browser-driver.js";
import { installFakeIndexedDB, removeIndexedDB } from "./wasm/fake-indexeddb.js";
import { openRawWebSocket } from "./wasm/raw-ws.js";

const relayUrl = process.env.SYNCBOND_TEST_RELAY;
const admin = process.env.SYNCBOND_TEST_ADMIN;
const GROUP_KEY_32 = new Uint8Array(32).fill(7);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function provision() {
  const channelRes = await fetch(`${relayUrl}/v1/channels`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${admin}` },
    body: JSON.stringify({ protocolVersion: 1, requestId: "wasm-channel-1" }),
  });
  assert.equal(channelRes.status, 201, `create channel: ${channelRes.status}`);
  const { channelId } = await channelRes.json();
  const issue = async (label) => {
    const res = await fetch(`${relayUrl}/v1/channels/${channelId}/credentials`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${admin}` },
      body: JSON.stringify({
        protocolVersion: 1,
        requestId: `wasm-cred-${label}`,
        scopes: ["append", "pull"],
        label,
      }),
    });
    assert.equal(res.status, 201, `issue ${label}: ${res.status}`);
    const { token } = await res.json();
    assert.ok(token);
    return token;
  };
  return { channelId, tokenA: await issue("a"), tokenB: await issue("b") };
}

/**
 * Pair two `WasmPairingEnd`s over one relay room using header-capable raw
 * sockets. The relay forwards pairing frames verbatim; the transport shuttles
 * base64url frames until both ends reach the completed transition.
 */
async function pairOverRelay(identityA, identityB, endA, endB) {
  const roomRes = await fetch(`${relayUrl}/v1/pairing/rooms`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocolVersion: 1, requestId: "wasm-room-1" }),
  });
  assert.equal(roomRes.status, 201, `create pairing room: ${roomRes.status}`);
  const { roomId, capability } = await roomRes.json();
  assert.ok(roomId && capability);

  const wsA = openRawWebSocket(relayUrl, `/v1/pairing/${roomId}`, {
    authorization: `Bearer ${capability}`,
  });
  const wsB = openRawWebSocket(relayUrl, `/v1/pairing/${roomId}`, {
    authorization: `Bearer ${capability}`,
  });

  const wire = (socket, end) => {
    const pending = [];
    const pump = () => {
      while (!end.is_finished) {
        const frame = end.pop_outgoing();
        if (!frame) break;
        const text = JSON.stringify({
          type: "pairing.frame",
          protocolVersion: 1,
          data: Buffer.from(frame).toString("base64url"),
        });
        if (socket.readyState === 1) socket.send(text);
        else pending.push(text);
      }
    };
    socket.onopen = () => {
      while (pending.length > 0 && socket.readyState === 1) {
        socket.send(pending.shift());
      }
      pump();
    };
    socket.onmessage = (raw) => {
      const message = JSON.parse(raw);
      if (message.type !== "pairing.frame") return;
      if (!end.is_finished) end.push(Buffer.from(message.data, "base64url"));
      pump();
    };
    socket.onerror = (error) => {
      throw new Error(`pairing socket error: ${error}`);
    };
    return { pump, close: () => socket.close() };
  };

  const wireA = wire(wsA, endA);
  const wireB = wire(wsB, endB);
  const deadline = Date.now() + 5000;
  while (!(endA.is_finished && endB.is_finished)) {
    if (Date.now() > deadline) {
      throw new Error("pairing frame exchange wedged over the relay room");
    }
    await sleep(5);
  }
  wireA.close();
  wireB.close();
  return { roomId };
}

test("two browser contexts pair over ws, sync, and refresh-recover", { skip: !relayUrl || !admin }, async () => {
  await loadSyncbondWasm();
  const wasm = await import("./wasm-gen/syncbond_wasm.js");
  const { channelId, tokenA, tokenB } = await provision();

  // Two independent browser contexts: separate IndexedDB factories, separate
  // identities, separate pairing ends.
  installFakeIndexedDB(); // context A
  const identityA = new wasm.WasmIdentity();
  const identityB = new wasm.WasmIdentity();
  const code = wasm.generate_pairing_code();
  const endA = new wasm.WasmPairingEnd(identityA, wasm.pairing_role_initiator(), code);
  const endB = new wasm.WasmPairingEnd(identityB, wasm.pairing_role_responder(), code);

  // Pair over the relay room through the header-capable transport.
  await pairOverRelay(identityA, identityB, endA, endB);
  assert.equal(endA.poll(), wasm.pairing_event_completed());
  assert.equal(endB.poll(), wasm.pairing_event_completed());
  const sessionA = endA.take_session();
  const sessionB = endB.take_session();
  assert.equal(sessionA.group_id, sessionB.group_id, "both ends derive the same group");
  assert.equal(sessionA.peer_device_id, identityB.device_id);
  assert.equal(sessionB.peer_device_id, identityA.device_id);

  installFakeIndexedDB(); // context B
  const deviceA = await createRelayDevice({
    nodeId: "ctx-a",
    relayUrl,
    channelId,
    token: tokenA,
    serverId: "relay-1",
    cursorChannel: "ch",
    groupId: "group-1",
    keyEpoch: 1,
    groupKey32: GROUP_KEY_32,
    identity: identityA,
  });
  const deviceB = await createRelayDevice({
    nodeId: "ctx-b",
    relayUrl,
    channelId,
    token: tokenB,
    serverId: "relay-1",
    cursorChannel: "ch",
    groupId: "group-1",
    keyEpoch: 1,
    groupKey32: GROUP_KEY_32,
    identity: identityB,
  });
  assert.equal(deviceA.mode, "indexeddb");
  assert.equal(deviceB.mode, "indexeddb");

  // Sync: each context writes a key the other reads.
  await write(deviceA, "a", new TextEncoder().encode("a0"));
  await write(deviceB, "b", new TextEncoder().encode("b0"));

  const converge = async () => {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      await Promise.all([syncOnce(deviceA), syncOnce(deviceB)]);
      if (["a", "b"].every((key) => get(deviceA, key) !== null && get(deviceB, key) !== null)) {
        return true;
      }
      await sleep(10);
    }
    return false;
  };
  assert.ok(await converge(), "both contexts converged on a and b");
  assert.equal(get(deviceA, "a"), "a0");
  assert.equal(get(deviceA, "b"), "b0");
  assert.equal(get(deviceB, "a"), "a0");
  assert.equal(get(deviceB, "b"), "b0");

  // Refresh from IndexedDB: each context rebuilds from its durable snapshot.
  await refresh(deviceA);
  await refresh(deviceB);
  assert.equal(get(deviceA, "a"), "a0", "A refreshed with a");
  assert.equal(get(deviceA, "b"), "b0", "A refreshed with the peer's b");
  assert.equal(get(deviceB, "a"), "a0", "B refreshed with the peer's a");
  assert.equal(get(deviceB, "b"), "b0", "B refreshed with b");

  // Persistence failure must not advance the durable cursor.
  await write(deviceA, "c", new TextEncoder().encode("c0"));
  await write(deviceB, "d", new TextEncoder().encode("d0"));
  await syncOnce(deviceA); // A pushes c and pulls d, committing its cursor.
  const beforeCommit = await durableCursor(deviceB);
  deviceB.failCommit = true;
  await assert.rejects(() => syncOnce(deviceB), /injected IndexedDB write failure/);
  assert.equal(
    await durableCursor(deviceB),
    beforeCommit,
    "a failed commit must leave the durable cursor where it was",
  );
  assert.ok(
    receiveCursor(deviceB) > beforeCommit,
    "the in-memory cursor may advance ahead of the durable one",
  );
  // Refresh reverts to the durable cursor; the next sync re-pulls idempotently.
  await refresh(deviceB);
  assert.equal(receiveCursor(deviceB), beforeCommit);
  await syncOnce(deviceB);
  assert.equal(get(deviceB, "c"), "c0", "B re-pulled the peer write after refresh");
  assert.equal(get(deviceB, "d"), "d0", "B kept its own staged write");

  // A tombstone propagates too.
  await remove(deviceA, "a");
  await syncOnce(deviceA);
  const sawTombstone = await (async () => {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      await syncOnce(deviceB);
      if (get(deviceB, "a") === null) return true;
      await sleep(10);
    }
    return false;
  })();
  assert.ok(sawTombstone, "B observed A's delete");
});

test("no IndexedDB degrades explicitly and still works in-session", { skip: !relayUrl || !admin }, async () => {
  await loadSyncbondWasm();
  const { channelId, tokenA } = await provision();
  removeIndexedDB();
  const device = await createRelayDevice({
    nodeId: "ctx-memory",
    relayUrl,
    channelId,
    token: tokenA,
    serverId: "relay-1",
    cursorChannel: "ch",
    groupId: "group-1",
    keyEpoch: 1,
    groupKey32: GROUP_KEY_32,
  });
  assert.equal(device.mode, "memory");
  assert.ok(
    device.persistenceWarning && device.persistenceWarning.includes("IndexedDB"),
    `degradation must name the cause, got: ${device.persistenceWarning}`,
  );
  await write(device, "z", new TextEncoder().encode("z0"));
  const report = await syncOnce(device); // no IndexedDB, but the wire works
  assert.equal(report.appended, 1);
  assert.equal(get(device, "z"), "z0");
  assert.deepEqual(keys(device), ["z"]);
});
