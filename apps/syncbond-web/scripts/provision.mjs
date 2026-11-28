// One-shot provisioning for the demo (run: `pnpm provision` here, with the
// relay already running per the README). Reads the relay's bootstrap admin
// credential, creates one channel, and issues two append+pull credentials
// — one per demo browser. The result lands in public/provision.json, which
// the page fetches; the file is gitignored because it carries bearer
// tokens (demo-grade, loopback-only). Every invocation creates a NEW
// channel: run it again whenever you start a fresh pairing session.
//
// Env knobs (all optional):
//   SYNCBOND_RELAY_URL          default http://127.0.0.1:8080
//   SYNCBOND_ADMIN_CREDENTIAL   default <app>/relay-data/admin-credential
//                               (matches relay.example.json's dataDir when
//                               the server runs from the repo root)

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const relayUrl = (process.env.SYNCBOND_RELAY_URL ?? "http://127.0.0.1:8080").replace(/\/$/, "");
const adminFile =
  process.env.SYNCBOND_ADMIN_CREDENTIAL ?? join(appDir, "relay-data", "admin-credential");
const outFile = join(appDir, "public", "provision.json");

const PROTOCOL_VERSION = 1;

function requestId(name) {
  return `demo-provision-${name}-${Date.now()}`;
}

async function adminPost(path, body) {
  const admin = readFileSync(adminFile, "utf8").trim();
  const response = await fetch(`${relayUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${admin}` },
    body: JSON.stringify(body),
  });
  if (response.status !== 201) {
    throw new Error(`${path} failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

async function main() {
  // A fresh channel every run: a channel is one group's append log, and
  // each new pairing derives a new group id — reusing a channel across
  // sessions would poison the pull with the previous group's envelopes.
  const channel = await adminPost("/v1/channels", {
    protocolVersion: PROTOCOL_VERSION,
    requestId: requestId("channel"),
  });
  const issue = async (label) =>
    adminPost(`/v1/channels/${channel.channelId}/credentials`, {
      protocolVersion: PROTOCOL_VERSION,
      requestId: requestId(label),
      scopes: ["append", "pull"],
      label: `demo-${label}`,
    });
  const tokenA = await issue("a");
  const tokenB = await issue("b");

  const provision = {
    channelId: channel.channelId,
    tokenA: tokenA.token,
    tokenB: tokenB.token,
  };
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, `${JSON.stringify(provision, null, 2)}\n`);
  console.log(`provisioned channel ${provision.channelId} -> ${outFile}`);
}

main().catch((error) => {
  console.error(`provision failed: ${error.message}`);
  console.error("(is the relay running? see apps/syncbond-web/README.md step 2)");
  process.exit(1);
});
