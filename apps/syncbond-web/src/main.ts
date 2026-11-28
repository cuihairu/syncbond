// The demo page's controller: identity, entries, pairing. Three sections,
// no framework, one file. Reads provision.json (written once by
// `scripts/provision.mjs`) for the relay channel and the two tokens; the
// creator takes token A and the joiner token B — deterministic because a
// joiner is exactly a page opened with invite query parameters.

import * as wasm from "@syncbond/bindings-ts/src/wasm-gen/syncbond_wasm.js";
import { loadSyncbondWasm } from "@syncbond/bindings-ts/src/wasm/wrapper.js";
import {
  createRelayDevice,
  get as deviceGet,
  keys as deviceKeys,
  persistDevice,
  recordCount,
  remove as deviceRemove,
  syncOnce,
  write as deviceWrite,
  type RelayDevice,
} from "@syncbond/bindings-ts/src/wasm/browser-driver.js";
import {
  b64ToBytes,
  bytesToB64,
  loadMeta,
  resetDemo,
  saveIdentity,
  savePaired,
  saveReplicator,
  type PairedFacts,
} from "./store";
import {
  createInvite,
  inviteFromLocation,
  inviteUrl,
  pairOverRoom,
  RELAY_API,
  type Invite,
} from "./pairing";

/** The device driver's own database, demo-prefixed (see store.ts). */
const DEVICE_DB_NAME = "syncbond-web-demo-devices";
const SERVER_ID = "relay-1";
const SYNC_INTERVAL_MS = 1500;

interface Provision {
  channelId: string;
  tokenA: string;
  tokenB: string;
}

const $ = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`missing #${id}`);
  return element as T;
};

const log = (line: string): void => {
  const entry = document.createElement("div");
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${line}`;
  $("log").prepend(entry);
};

// ------------------------------------------------------------------ state

let identity: wasm.WasmIdentity;
/** Standalone replicator: owns writes until pairing succeeds. */
let standalone: wasm.WasmReplicator;
let device: RelayDevice | null = null;
let paired: PairedFacts | null = null;
let provision: Provision | null = null;
let online = true;

// -------------------------------------------------------------- rendering

function setStatus(text: string): void {
  $("status").textContent = text;
}

function renderIdentity(): void {
  $("device-id").textContent = identity.device_id;
}

function renderEntries(): void {
  const list = $("entries");
  list.textContent = "";
  const entries = document.createDocumentFragment();
  if (device) {
    for (const key of deviceKeys(device)) {
      entries.appendChild(entryRow(key, deviceGet(device, key) ?? ""));
    }
    $("record-count").textContent = String(recordCount(device));
  } else {
    for (const key of standalone.keys) {
      const value = standalone.get(key);
      entries.appendChild(
        entryRow(key, value ? new TextDecoder().decode(value) : ""),
      );
    }
    $("record-count").textContent = String(standalone.record_count);
  }
  list.appendChild(entries);
}

function entryRow(key: string, value: string): HTMLLIElement {
  const row = document.createElement("li");
  const label = document.createElement("code");
  label.textContent = `${key} = ${value}`;
  row.appendChild(label);
  const removeButton = document.createElement("button");
  removeButton.textContent = "delete";
  removeButton.onclick = () => void removeEntry(key);
  row.appendChild(removeButton);
  return row;
}

function renderPairing(): void {
  const section = $("pairing-status");
  section.textContent = "";
  if (paired && device) {
    const line = document.createElement("p");
    line.textContent =
      `paired with ${paired.peerDeviceId} (role ${paired.role}); ` +
      `group ${paired.groupId} epoch ${paired.keyEpoch}; ` +
      `persistence ${device.mode}`;
    section.appendChild(line);
    $("invite-box").hidden = true;
    $("pair-actions").hidden = true;
    $("sync-controls").hidden = false;
  } else {
    $("invite-box").hidden = true;
    $("pair-actions").hidden = false;
    $("sync-controls").hidden = true;
  }
  if (device?.persistenceWarning) {
    const warning = document.createElement("p");
    warning.textContent = `warning: ${device.persistenceWarning}`;
    section.appendChild(warning);
  }
}

// ---------------------------------------------------------------- actions

async function addEntry(): Promise<void> {
  const keyInput = $("entry-key") as HTMLInputElement;
  const valueInput = $("entry-value") as HTMLInputElement;
  const key = keyInput.value.trim();
  const value = valueInput.value;
  if (!key) return;
  if (device) {
    await deviceWrite(device, key, new TextEncoder().encode(value));
  } else {
    standalone.put(key, new TextEncoder().encode(value));
    await saveReplicator(standalone.save());
  }
  keyInput.value = "";
  valueInput.value = "";
  renderEntries();
  log(`wrote "${key}"${device ? "" : " (standalone; syncs after pairing)"}`);
}

async function removeEntry(key: string): Promise<void> {
  if (device) {
    await deviceRemove(device, key);
  } else {
    standalone.delete(key);
    await saveReplicator(standalone.save());
  }
  renderEntries();
  log(`deleted "${key}"`);
}

async function newIdentity(): Promise<void> {
  if (paired) {
    log("refusing new identity while paired; wipe the demo first");
    return;
  }
  identity = new wasm.WasmIdentity();
  standalone = new wasm.WasmReplicator(identity.device_id);
  await saveIdentity(identity.export());
  await saveReplicator(standalone.save());
  renderIdentity();
  renderEntries();
  log(`new identity ${identity.device_id}`);
}

function exportIdentity(): void {
  const blob = new Blob(
    [JSON.stringify({ deviceId: identity.device_id, secretKeyB64: bytesToB64(identity.export()) })],
    { type: "application/json" },
  );
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `syncbond-identity-${identity.device_id}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
  log("identity exported (keep the file private; it is the secret key)");
}

async function importIdentity(file: File): Promise<void> {
  if (paired) {
    log("refusing import while paired; wipe the demo first");
    return;
  }
  const parsed = JSON.parse(await file.text()) as { secretKeyB64?: string };
  if (!parsed.secretKeyB64) throw new Error("file has no secretKeyB64");
  identity = wasm.WasmIdentity.import(b64ToBytes(parsed.secretKeyB64));
  standalone = new wasm.WasmReplicator(identity.device_id);
  await saveIdentity(identity.export());
  await saveReplicator(standalone.save());
  renderIdentity();
  renderEntries();
  log(`identity imported: ${identity.device_id}`);
}

async function beginCreateInvite(): Promise<void> {
  if (!provision) {
    log("no provision.json — run `pnpm provision` in apps/syncbond-web first");
    return;
  }
  try {
    const invite = await createInvite();
    $("invite-code").textContent = invite.code;
    $("invite-link").textContent = inviteUrl(invite);
    $("invite-box").hidden = false;
    log(`invite created: code ${invite.code}; open the link in the second browser`);
    // The creator joins its own room at once: first arrival = responder,
    // so the joiner's handshake has a counterparty waiting.
    await runPairing(invite);
  } catch (error) {
    log(`invite failed: ${error}`);
  }
}

async function runPairing(invite: Invite): Promise<void> {
  if (!provision) {
    setStatus("pairing needs provision.json (run `pnpm provision`)");
    return;
  }
  setStatus("pairing…");
  try {
    const outcome = await pairOverRoom(invite, identity, log);
    // Convention: the joiner (the page opened through the invite link,
    // normally the second arrival = initiator) takes token B.
    paired = {
      role: outcome.role,
      groupId: outcome.facts.groupId,
      keyEpoch: outcome.facts.keyEpoch,
      groupKeyB64: outcome.facts.groupKeyB64,
      peerDeviceId: outcome.peerDeviceId,
      channelId: provision.channelId,
      token: outcome.role === "initiator" ? provision.tokenB : provision.tokenA,
      serverId: SERVER_ID,
    };
    await savePaired(paired);
    await enterPairedMode();
    setStatus("paired");
  } catch (error) {
    setStatus("pairing failed");
    log(`pairing failed: ${error}`);
  } finally {
    // Clean the URL so a reload does not re-enter the joiner flow.
    if (paired) history.replaceState(null, "", window.location.pathname);
  }
}

/** Build the relay device from the stored facts and carry pre-pairing writes. */
async function enterPairedMode(): Promise<void> {
  if (!paired) return;
  device = await createRelayDevice({
    nodeId: identity.device_id,
    relayUrl: RELAY_API,
    channelId: paired.channelId,
    token: paired.token,
    serverId: paired.serverId,
    cursorChannel: paired.channelId,
    groupId: paired.groupId,
    keyEpoch: paired.keyEpoch,
    groupKey32: b64ToBytes(paired.groupKeyB64),
    identity,
    dbName: DEVICE_DB_NAME,
    // The standalone replicator's snapshot carries any writes made before
    // pairing into the paired device; a durable record, when one exists,
    // always wins over it (driver rule).
    snapshotBytes: standalone.save(),
  });
  // Snapshot seeding restores the ops but does not stage them for the
  // wire; seal the pre-pairing oplog so the peer receives those writes.
  for (let index = 0; index < device.replicator.oplog_len; index += 1) {
    const opJson = device.replicator.op_json(index);
    device.outbox.push(device.keyring.seal(identity.device_id, new TextEncoder().encode(opJson)));
  }
  if (device.outbox.length > 0) {
    await persistDevice(device);
    log(`staged ${device.outbox.length} pre-pairing write(s) for sync`);
  }
  renderPairing();
  renderEntries();
  await tick();
}

// ------------------------------------------------------------------- sync

async function tick(): Promise<void> {
  if (!device || !online) return;
  try {
    const report = await syncOnce(device);
    if (report.appended || report.pulled || report.applied) {
      renderEntries();
      log(`sync: pushed ${report.appended}, pulled ${report.pulled}, applied ${report.applied}`);
    }
  } catch (error) {
    log(`sync failed: ${error}`);
  }
}

// ------------------------------------------------------------------- boot

async function boot(): Promise<void> {
  await loadSyncbondWasm();

  const meta = await loadMeta();
  identity = meta.identityBytes ? wasm.WasmIdentity.import(meta.identityBytes) : new wasm.WasmIdentity();
  if (!meta.identityBytes) await saveIdentity(identity.export());
  standalone = meta.replicatorBytes
    ? wasm.WasmReplicator.load(meta.replicatorBytes)
    : new wasm.WasmReplicator(identity.device_id);
  if (!meta.replicatorBytes) await saveReplicator(standalone.save());

  try {
    const response = await fetch("provision.json");
    if (response.ok) provision = await response.json();
  } catch {
    provision = null;
  }
  if (!provision) {
    log("provision.json not found — pairing needs `pnpm provision` once (README step 2)");
  }

  // Wire static handlers.
  $("add-entry").onclick = () => void addEntry();
  $("new-identity").onclick = () => void newIdentity();
  $("export-identity").onclick = exportIdentity;
  $("import-identity").onchange = (event) => {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (file) void importIdentity(file).catch((error) => log(`import failed: ${error}`));
  };
  $("create-invite").onclick = () => void beginCreateInvite();
  $("wipe").onclick = () => {
    void resetDemo().then(() => window.location.assign(window.location.pathname));
  };
  $("offline-toggle").onchange = (event) => {
    online = !(event.target as HTMLInputElement).checked;
    log(online ? "back online; draining staged writes" : "offline: writes stage locally, sync paused");
  };
  $("sync-now").onclick = () => void tick();
  setInterval(() => void tick(), SYNC_INTERVAL_MS);

  renderIdentity();
  renderEntries();

  if (meta.paired) {
    paired = meta.paired;
    await enterPairedMode();
    setStatus("paired (restored)");
  } else {
    renderPairing();
    setStatus("standalone");
    const invite = inviteFromLocation();
    if (invite) {
      log("invite link detected; joining as the second browser");
      // Show the code this end expects, so both screens can be compared.
      $("invite-code").textContent = invite.code;
      $("invite-box").hidden = false;
      await runPairing(invite);
    }
  }
}

void boot().catch((error) => {
  setStatus("boot failed");
  log(`boot failed: ${error}`);
});
