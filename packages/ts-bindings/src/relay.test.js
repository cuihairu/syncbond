// Relay driver e2e (todo.md DSR-37): two Node processes sync through a real
// relay channel and recover after a restart. The Rust harness boots the relay
// in-process and exports SYNCBOND_TEST_RELAY (http URL) and SYNCBOND_TEST_ADMIN
// (bearer token); without those the suite skips so a plain `npm test` stays
// green. Each device runs in its own child process (the acceptance's "two Node
// processes") and asserts main-thread responsiveness and a clean stop itself.

import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const relayUrl = process.env.SYNCBOND_TEST_RELAY;
const admin = process.env.SYNCBOND_TEST_ADMIN;
const childPath = join(dirname(fileURLToPath(import.meta.url)), "relay-child.js");
// The same 32 bytes of 0x07 the Rust driver test uses: two devices in one
// group import the identical group key material.
const groupKeyB64 = Buffer.alloc(32, 7).toString("base64");

function runChild(phase, config, tmp) {
  const configPath = join(tmp, `${phase}-${config.node}-config.json`);
  const outPath = join(tmp, `${phase}-${config.node}-out.json`);
  writeFileSync(configPath, JSON.stringify(config));
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [childPath, phase, configPath, outPath], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`child ${phase} ${config.node} exited ${code}: ${stderr}`));
        return;
      }
      resolve(JSON.parse(readFileSync(outPath, "utf8")));
    });
  });
}

test("two node processes sync through a relay and recover", { skip: !relayUrl || !admin }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "syncbond-relay-"));
  try {
    // Provision one channel and two append/pull credentials through the same
    // admin endpoints the Rust client drives, so the wire shape is pinned by
    // one test only if it changes here first.
    const channelRes = await fetch(`${relayUrl}/v1/channels`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${admin}`,
      },
      body: JSON.stringify({ protocolVersion: 1, requestId: "js-channel-1" }),
    });
    assert.equal(channelRes.status, 201, `create channel: ${channelRes.status}`);
    const { channelId } = await channelRes.json();
    assert.ok(channelId);

    const issue = async (label) => {
      const res = await fetch(`${relayUrl}/v1/channels/${channelId}/credentials`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${admin}`,
        },
        body: JSON.stringify({
          protocolVersion: 1,
          requestId: `js-cred-${label}`,
          scopes: ["append", "pull"],
          label,
        }),
      });
      assert.equal(res.status, 201, `issue ${label}: ${res.status}`);
      const body = await res.json();
      assert.ok(body.token, `credential ${label} must carry a token`);
      return body.token;
    };
    const tokenA = await issue("js-a");
    const tokenB = await issue("js-b");

    // Phase 1: two fresh devices write concurrently and converge both ways.
    // They must run at the same time: each waits on a key only the other
    // writes.
    const [liveA, liveB] = await Promise.all([
      runChild(
        "live",
        {
          relayUrl,
          channelId,
          token: tokenA,
          groupKeyB64,
          node: "js-a",
          writes: [["a/0", "a0"]],
          expect: [["a/0", "a0"], ["b/1", "b1"]],
          waitMs: 15000,
        },
        tmp,
      ),
      runChild(
        "live",
        {
          relayUrl,
          channelId,
          token: tokenB,
          groupKeyB64,
          node: "js-b",
          writes: [["b/0", "b0"], ["b/1", "b1"]],
          expect: [["a/0", "a0"], ["b/1", "b1"]],
          waitMs: 15000,
        },
        tmp,
      ),
    ]);

    // Phase 2, sequential restarts: B resumes from its snapshot and writes
    // b/2 while A is already down (A's phase-1 child exited), then A resumes
    // and must pull what it missed while down. The restored state of each
    // device is verified by the child before it starts the worker.
    const restartedB = await runChild(
      "restart",
      {
        relayUrl,
        channelId,
        token: tokenB,
        groupKeyB64,
        node: "js-b",
        stateB64: liveB.stateB64,
        expectBeforeStart: [["b/0", "b0"], ["b/1", "b1"]],
        writes: [["b/2", "b2"]],
        expect: [["b/0", "b0"], ["b/1", "b1"], ["b/2", "b2"]],
        waitMs: 15000,
      },
      tmp,
    );
    const restartedA = await runChild(
      "restart",
      {
        relayUrl,
        channelId,
        token: tokenA,
        groupKeyB64,
        node: "js-a",
        stateB64: liveA.stateB64,
        expectBeforeStart: [["a/0", "a0"]],
        writes: [["a/1", "a1"]],
        expect: [["a/0", "a0"], ["a/1", "a1"], ["b/1", "b1"], ["b/2", "b2"]],
        waitMs: 15000,
      },
      tmp,
    );

    // `pulled` marks the devices that must have applied an op pulled from
    // the relay: a restarted device that only writes its own key has
    // nothing to pull and legitimately reports zero.
    for (const [phase, run, pulled] of [
      ["live-a", liveA, true],
      ["live-b", liveB, true],
      ["restart-b", restartedB, false],
      ["restart-a", restartedA, true],
    ]) {
      assert.equal(run.stopReason, 1, `${phase} must stop cancelled`);
      assert.equal(run.error, null, `${phase} must stop with no error`);
      assert.ok(
        run.maxStallMs < 250,
        `${phase} starved the main thread: ${run.maxStallMs}ms longest stall`,
      );
      if (pulled) {
        assert.ok(run.progress.applied > 0, `${phase} must have applied pulled ops`);
      }
      assert.ok(run.converged, `${phase} reported convergence`);
    }
    assert.equal(restartedA.got["b/2"], "b2", "A must catch what B wrote while A was down");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
