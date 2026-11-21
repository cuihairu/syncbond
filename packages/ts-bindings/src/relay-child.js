// Relay driver child process (todo.md DSR-37): one Node process runs one
// device against a relay channel and reports how the run went. The parent
// test spawns two of these (the "two Node processes" of the acceptance) and
// a second pair after a restart, so recovery from exported state is exercised
// through real child processes, not one process juggling two devices.
//
// Usage: node relay-child.js <phase> <config.json> <out.json>
//   phase  "live"    - a fresh device that writes and syncs.
//          "restart" - a device restored from an exported state snapshot.
//   config { relayUrl, channelId, token, groupKeyB64, nodeId, stateB64?,
//            writes: [[key, value], ...], expect: [[key, value], ...],
//            expectBeforeStart?: [[key, value], ...], waitMs }
//
// The child asserts its own invariants and exits non-zero on failure; the
// parent checks the exit code and the reported output. A 1ms ticker runs on
// the JS main thread for the whole sync wait: the native driver does its
// blocking work on the libuv thread pool, so the ticker must never stall for
// long (the acceptance "blocking work does not occupy the JS main thread").

import { writeFileSync } from "node:fs";
import { readFileSync } from "node:fs";
import { NativeRelayDriver } from "./native/binding.js";

function fail(message) {
  console.error(`relay-child ${process.argv[2]}: ${message}`);
  process.exit(1);
}

const [, , phase, configPath, outPath] = process.argv;
const config = JSON.parse(readFileSync(configPath, "utf8"));
const groupKey = Buffer.from(config.groupKeyB64, "base64");

const driver = new NativeRelayDriver(
  config.relayUrl,
  config.channelId,
  config.token,
  "relay-1",
  "ch",
  "group-1",
  1,
  groupKey,
  config.node,
  5000,
  0,
  undefined,
  config.stateB64 ? Buffer.from(config.stateB64, "base64") : undefined,
);

async function value(key) {
  const bytes = await driver.get(key);
  return bytes == null ? null : Buffer.from(bytes).toString("utf8");
}

// A restored device must already hold what it committed before the restart.
for (const [key, expected] of config.expectBeforeStart ?? []) {
  const got = await value(key);
  if (got !== expected) {
    fail(`restored state lost ${key}: got ${JSON.stringify(got)}, want ${expected}`);
  }
}

driver.config(2, 8, 1, 2, 1000, 1);

// The responsiveness probe: if the native driver's blocking calls ran on the
// JS main thread, this ticker would stall while they run. What matters is
// the longest gap between fires, not how many fired — Node coalesces 1ms
// timers to one fire per event-loop turn.
let lastTick = Date.now();
let maxStallMs = 0;
const ticker = setInterval(() => {
  const now = Date.now();
  maxStallMs = Math.max(maxStallMs, now - lastTick);
  lastTick = now;
}, 1);

await driver.start();
for (const [key, value] of config.writes) {
  await driver.write(key, Buffer.from(value, "utf8"));
}

const deadline = Date.now() + (config.waitMs ?? 15000);
let converged = false;
while (Date.now() < deadline) {
  let all = true;
  for (const [key] of config.expect) {
    if ((await value(key)) == null) {
      all = false;
      break;
    }
  }
  if (all) {
    converged = true;
    break;
  }
  await new Promise((resolve) => setTimeout(resolve, 5));
}
clearInterval(ticker);

const got = {};
for (const [key] of config.expect) {
  got[key] = await value(key);
}
for (const [key, expected] of config.expect) {
  if (got[key] !== expected) {
    fail(`expected ${key}=${expected}, got ${JSON.stringify(got[key])}`);
  }
}
if (!converged) {
  fail(`did not converge on ${config.expect.map(([key]) => key).join(", ")}`);
}
if (maxStallMs >= 250) {
  fail(`the JS main thread stalled ${maxStallMs}ms during the sync`);
}

// Cancel the loop and join the worker before reading the outcome, so the
// stop reason is the deterministic "cancelled" (1) a clean host stop yields.
await driver.stop();
if (driver.running) {
  fail("driver still running after a clean stop");
}
if (driver.stopReason !== 1) {
  fail(`stop reason is ${driver.stopReason}, want 1 (cancelled)`);
}
if (driver.error !== null) {
  fail(`clean stop must have no error, got ${JSON.stringify(driver.error)}`);
}
const progress = driver.progress();
const state = await driver.exportState();
writeFileSync(
  outPath,
  JSON.stringify({
    phase,
    node: config.node,
    maxStallMs,
    converged,
    progress: {
      running: progress.running,
      cycles: progress.cycles,
      sentBatches: progress.sentBatches,
      sentEnvelopes: progress.sentEnvelopes,
      pagesPulled: progress.pagesPulled,
      applied: progress.applied,
    },
    stopReason: driver.stopReason,
    error: driver.error,
    got,
    stateB64: Buffer.from(state).toString("base64"),
  }),
);
