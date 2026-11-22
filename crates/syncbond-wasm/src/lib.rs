//! Browser WASM bindings for syncbond (todo.md DSR-43).
//!
//! The library runs an in-memory pairing/sync handshake on worker threads,
//! which `wasm32-unknown-unknown` (built without the `atomics` feature)
//! cannot provide. This crate therefore exposes the single-thread-safe
//! surface and nothing more: identity generation **and import/export**,
//! replicator CRUD with a byte-level save/load (so a host can persist state
//! in IndexedDB), the **externally driven pairing frame exchange** (the host
//! owns the wire and the event loop), **remote operation handling** (apply a
//! wire op and advance the receive position), **full state recovery** (the
//! versioned snapshot with the receive position, importable with the host
//! clock), the **envelope keyring** (seal a wire op into a relay envelope and
//! open a pulled page back, advancing the receive position with it — the
//! encryption half of the relay sync, DSR-44), the **pairing code generator**,
//! the tombstone GC entry point, and the cross-language conformance
//! runner (thread-free). The in-memory `PairResult` and the relay driver
//! are threaded and are intentionally not exposed; the application wires its
//! own transport (WebRTC/WebSocket, DSR-44) and feeds frames in and out.
//!
//! When the host has no IndexedDB the wrapper degrades to an in-memory
//! store and reports the limitation explicitly (see `packages/ts-bindings`
//! `src/wasm/wrapper.js`).

use std::collections::HashSet;
use std::sync::Arc;

use syncbond_core::batch::open_operations;
use syncbond_core::conflict::LwwHlc;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::replication::{decode_state, encode_state, Operation, Replicator};
use syncbond_ffi::error::{
    SB_PAIR_EVENT_COMPLETED, SB_PAIR_EVENT_FAILED, SB_PAIR_ROLE_INITIATOR, SB_PAIR_ROLE_RESPONDER,
};
use syncbond_ffi::handles::{self, PairEnd};
use syncbond_relay_protocol::dto::Envelope;
use wasm_bindgen::prelude::*;

// ----------------------------------------------------------- identity

/// A device identity (Ed25519 keypair + device id). `generate` makes a fresh
/// one; `import`/`export` round-trip the 64-byte secret key so a host can
/// persist a device identity and resume its sessions after a reload.
#[wasm_bindgen]
pub struct WasmIdentity {
    inner: DeviceIdentity,
}

#[wasm_bindgen]
impl WasmIdentity {
    #[wasm_bindgen(constructor)]
    pub fn generate() -> WasmIdentity {
        WasmIdentity {
            inner: DeviceIdentity::generate(),
        }
    }

    /// Rebuild an identity from the 64-byte secret key (`export`'s output).
    #[wasm_bindgen]
    pub fn import(secret_key: Vec<u8>) -> Result<WasmIdentity, JsValue> {
        DeviceIdentity::from_secret_key_bytes(&secret_key)
            .map(|inner| WasmIdentity { inner })
            .map_err(js_error)
    }

    /// The 64-byte Ed25519 secret key. **Private material**: store it behind
    /// the application's protected storage; a leak forges this device.
    #[wasm_bindgen]
    pub fn export(&self) -> Vec<u8> {
        self.inner.secret_key.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn device_id(&self) -> String {
        self.inner.device_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key.to_vec()
    }
}

// ------------------------------------------------------------- pairing

/// One end of an externally driven pairing exchange (todo.md DSR-34).
///
/// The host owns the wire and the event loop: it drains the outbound
/// protocol frames with `popOutgoing`, feeds the inbound ones with `push`,
/// and advances the machine with `poll` until it reports the completed event
/// (then `takeSession`) or the failed event (then `failure`). Two ends driven
/// this way complete the same handshake the in-memory pairing does — the
/// difference is only who moves the frames. The completed session's
/// application channel is the host's to wire (its own frames, or the relay
/// driver) and must never silently look connected, so `WasmSession` does not
/// expose `send`/`recv` here.
#[wasm_bindgen]
pub struct WasmPairingEnd {
    inner: PairEnd,
}

#[wasm_bindgen]
impl WasmPairingEnd {
    /// Start one end of the exchange from the caller's identity. `role` is
    /// `pairing_role_initiator()` or `pairing_role_responder()`; both ends
    /// must be handed the same issued `code`.
    #[wasm_bindgen(constructor)]
    pub fn new(identity: &WasmIdentity, role: i32, code: &str) -> Result<WasmPairingEnd, JsValue> {
        if role != SB_PAIR_ROLE_INITIATOR && role != SB_PAIR_ROLE_RESPONDER {
            return Err(js_error(format!("unknown pairing role {role}")));
        }
        let identity = handles::Identity(identity.inner.clone());
        PairEnd::new(&identity, role, code)
            .map(|inner| WasmPairingEnd { inner })
            .map_err(ffi_error)
    }

    /// The next frame the machine wants on the wire, if any.
    #[wasm_bindgen]
    pub fn pop_outgoing(&mut self) -> Option<Vec<u8>> {
        self.inner.pop_outgoing()
    }

    /// Feed one frame received from the wire. A protocol violation is not an
    /// error here: it becomes a failed `poll` plus one queued abort frame.
    #[wasm_bindgen]
    pub fn push(&mut self, frame: Vec<u8>) -> Result<(), JsValue> {
        self.inner.push(&frame).map_err(ffi_error)
    }

    /// Advance the machine and report what it found, exactly once. The event
    /// constants are `pairing_event_none/completed/failed`.
    #[wasm_bindgen]
    pub fn poll(&mut self) -> i32 {
        self.inner.poll()
    }

    /// Queue the goodbye frame (best effort, once), for a host that gives up.
    #[wasm_bindgen]
    pub fn abort(&mut self) {
        self.inner.abort();
    }

    /// Whether the exchange reached its terminal transition.
    #[wasm_bindgen(getter)]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    /// The failure a `poll` reported, if any.
    #[wasm_bindgen]
    pub fn failure(&self) -> Option<String> {
        self.inner.failure()
    }

    /// Take the completed session; available once a completed `poll` handed it
    /// over.
    #[wasm_bindgen]
    pub fn take_session(&mut self) -> Result<WasmSession, JsValue> {
        self.inner
            .take_session()
            .map(|inner| WasmSession { inner })
            .map_err(ffi_error)
    }
}

/// One authenticated, encrypted session end. The group facts and invalidation
/// surface; the application channel is the host's to wire (see
/// [`WasmPairingEnd`]).
#[wasm_bindgen]
pub struct WasmSession {
    inner: handles::Session,
}

#[wasm_bindgen]
impl WasmSession {
    #[wasm_bindgen(getter)]
    pub fn group_id(&self) -> String {
        self.inner.group_id()
    }

    #[wasm_bindgen(getter)]
    pub fn peer_device_id(&self) -> String {
        self.inner.peer_device_id()
    }

    #[wasm_bindgen(getter)]
    pub fn invalidated(&self) -> bool {
        self.inner.invalidated()
    }

    #[wasm_bindgen]
    pub fn invalidate(&self) {
        self.inner.invalidate();
    }
}

// --------------------------------------------------------- replicator

/// An LWW/HLC replicator. Writes go to the local oplog; `applyRemoteOp`
/// applies one wire op from a peer, and `sync` (over a transport the
/// application owns) propagates them. `save`/`load` round-trip the local
/// replication state; `exportSnapshot`/`loadSnapshot` round-trip the full
/// versioned snapshot with the receive position (todo.md DSR-35).
#[wasm_bindgen]
pub struct WasmReplicator {
    inner: Replicator,
}

#[wasm_bindgen]
impl WasmReplicator {
    #[wasm_bindgen(constructor)]
    pub fn new(node_id: String) -> WasmReplicator {
        WasmReplicator {
            inner: Replicator::with_wall_clock(node_id, Arc::new(LwwHlc), wall_clock()),
        }
    }

    /// Write one record; returns the operation as wire JSON so the host can
    /// seal it into an envelope (todo.md DSR-44). The op has already been
    /// applied locally.
    #[wasm_bindgen]
    pub fn put(&mut self, key: String, payload: Vec<u8>) -> Result<String, JsValue> {
        let op = self.inner.put(key, payload).map_err(js_error)?;
        serde_json::to_string(&op).map_err(js_error)
    }

    /// Tombstone one record; returns the operation as wire JSON (see `put`).
    #[wasm_bindgen]
    pub fn delete(&mut self, key: String) -> Result<String, JsValue> {
        let op = self.inner.delete(key).map_err(js_error)?;
        serde_json::to_string(&op).map_err(js_error)
    }

    /// Payload of a live record; tombstoned (deleted) or absent keys read as
    /// `undefined` (wasm-bindgen's `Option::None` mapping; the napi path
    /// returns `null` — both are falsy).
    #[wasm_bindgen]
    pub fn get(&self, key: String) -> Option<Vec<u8>> {
        self.inner
            .get(&key)
            .filter(|record| !record.deleted)
            .map(|record| record.payload.clone())
    }

    /// Keys with a live (non-tombstoned) value, sorted.
    #[wasm_bindgen(getter)]
    pub fn keys(&self) -> Vec<String> {
        self.inner.live_keys()
    }

    #[wasm_bindgen(getter)]
    pub fn record_count(&self) -> u32 {
        self.inner.record_count() as u32
    }

    #[wasm_bindgen(getter)]
    pub fn node_id(&self) -> String {
        self.inner.node_id.clone()
    }

    /// One oplog op as wire JSON (index into the local log). Feed a peer's
    /// output into `applyRemoteOp` on the other side.
    #[wasm_bindgen]
    pub fn op_json(&self, index: u32) -> Result<String, JsValue> {
        let op = self
            .inner
            .oplog()
            .get(index as usize)
            .ok_or_else(|| js_error(format!("oplog index {index} out of range")))?;
        serde_json::to_string(op).map_err(js_error)
    }

    /// Apply one wire op; `false` when it was a duplicate or was rejected
    /// because it would resurrect a garbage-collected delete. The caller
    /// advances its receive position with the same op's message id.
    #[wasm_bindgen]
    pub fn apply_remote_op(&mut self, op_json: String) -> Result<bool, JsValue> {
        let op: Operation = serde_json::from_str(&op_json)
            .map_err(|error| js_error(format!("invalid op json: {error}")))?;
        self.inner.apply_remote(&op).map_err(js_error)
    }

    /// Serialize the full local replication state. The identity/group/epoch
    /// fields of the snapshot are placeholders; only oplog, cursor and GC
    /// barriers round-trip (which is what replication needs to resume).
    #[wasm_bindgen]
    pub fn save(&self) -> Result<Vec<u8>, JsValue> {
        let placeholder = DeviceIdentity {
            device_id: self.inner.node_id.clone(),
            public_key: [0u8; 32],
            secret_key: [0u8; 64],
        };
        let state = self.inner.snapshot_state(&placeholder, "", 0);
        encode_state(&state).map_err(js_error)
    }

    /// Rebuild a replicator from `save()` output (crash-restart path).
    #[wasm_bindgen]
    pub fn load(bytes: Vec<u8>) -> Result<WasmReplicator, JsValue> {
        let state = decode_state(&bytes).map_err(js_error)?;
        let inner = Replicator::from_state_with_clock(&state, Arc::new(LwwHlc), wall_clock())
            .map_err(js_error)?;
        Ok(WasmReplicator { inner })
    }

    /// Assemble the versioned snapshot (todo.md DSR-35): the committed
    /// state, the receive position that explains it, and the group facts the
    /// restored device needs. **The blob is private material** — it carries
    /// the identity's Ed25519 secret key, so store it behind protected
    /// storage.
    #[wasm_bindgen]
    pub fn export_snapshot(
        &self,
        identity: &WasmIdentity,
        group_id: String,
        key_epoch: f64,
        receive: &WasmReceiveState,
    ) -> Result<Vec<u8>, JsValue> {
        handles::build_snapshot(
            &self.inner,
            &identity.inner,
            &group_id,
            key_epoch as u64,
            &receive.inner.0,
        )
        .map_err(ffi_error)
    }

    /// Rebuild a replicator and its receive position from `exportSnapshot`
    /// output (crash-restart path with the full receive knowledge). Returns
    /// `[replicator, receive]`; `strategy` is the merge strategy the snapshot
    /// was built under (`strategy_lww_hlc()` etc.).
    #[wasm_bindgen]
    pub fn load_snapshot(bytes: Vec<u8>, strategy: u32) -> Result<Vec<JsValue>, JsValue> {
        let (replicator, receive) =
            handles::import_snapshot_with_clock(&bytes, strategy, wall_clock())
                .map_err(ffi_error)?;
        let replicator: JsValue = WasmReplicator {
            inner: replicator.0,
        }
        .into();
        let receive: JsValue = WasmReceiveState { inner: receive }.into();
        Ok(vec![replicator, receive])
    }

    /// Drop tombstones older than `older_than_ms` relative to `now_ms`.
    /// Returns the number of oplog entries removed by collapsing collected
    /// histories down to their single tombstone op.
    #[wasm_bindgen]
    pub fn gc_tombstones(&mut self, now_ms: f64, older_than_ms: f64) -> u32 {
        let report = self
            .inner
            .gc_tombstones(now_ms as u64, older_than_ms as u64);
        report.oplog_entries_removed as u32
    }
}

// ----------------------------------------------------- receive position

/// The receive-side pull position and dedup knowledge (todo.md DSR-35).
/// Carried in the snapshot alongside the replicator state, so a restart does
/// not re-pull (and re-apply) every remote operation already seen.
#[wasm_bindgen]
pub struct WasmReceiveState {
    inner: handles::ReceiveState,
}

impl Default for WasmReceiveState {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmReceiveState {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmReceiveState {
        WasmReceiveState {
            inner: handles::ReceiveState::new(),
        }
    }

    /// The server-assigned sequence the next pull must start after, for one
    /// (server, channel). Upserts.
    #[wasm_bindgen]
    pub fn set_server_cursor(
        &mut self,
        server_id: String,
        channel_id: String,
        server_seq: f64,
    ) -> Result<(), JsValue> {
        self.inner
            .set_server_cursor(&server_id, &channel_id, server_seq as u64)
            .map_err(ffi_error)
    }

    /// The highest local cursor seen for one replica's `"<node>:<n>"` op ids.
    #[wasm_bindgen]
    pub fn set_source_cursor(&mut self, node_id: String, seq: f64) -> Result<(), JsValue> {
        self.inner
            .set_source_cursor(&node_id, seq as u64)
            .map_err(ffi_error)
    }

    /// Record one already-opened envelope so a redelivery is a no-op.
    #[wasm_bindgen]
    pub fn mark_seen(&mut self, message_id: String) -> Result<(), JsValue> {
        self.inner.mark_seen(&message_id).map_err(ffi_error)
    }

    /// `undefined` when this (server, channel) has never been pulled.
    #[wasm_bindgen]
    pub fn server_seq(&self, server_id: String, channel_id: String) -> Option<f64> {
        self.inner
            .server_seq(&server_id, &channel_id)
            .map(|seq| seq as f64)
    }

    #[wasm_bindgen]
    pub fn seen(&self, message_id: String) -> bool {
        self.inner.seen(&message_id)
    }

    /// Canonical dump; deterministic, so a round trip compares byte for byte.
    #[wasm_bindgen]
    pub fn json(&self) -> String {
        self.inner.json()
    }
}

// --------------------------------------------------------------- keyring

/// One device's group key (todo.md DSR-44). `seal` turns a wire op JSON into
/// an encrypted relay envelope; `open_batch` decrypts a pulled page back into
/// op JSONs and advances the caller's receive position with the message ids
/// it opened, so a redelivery is a no-op even across a refresh (the receive
/// position rides in the snapshot).
///
/// The key material is provisioned by the pairing session or out of band; a
/// device only ever seals and opens — it never derives or distributes keys.
#[wasm_bindgen]
pub struct WasmKeyring {
    inner: handles::Keyring,
}

#[wasm_bindgen]
impl WasmKeyring {
    /// A keyring with a fresh random key at epoch 0 (the pairing initiator's
    /// side); the responder's side imports the exchanged key material.
    #[wasm_bindgen(constructor)]
    pub fn new(group_id: String) -> WasmKeyring {
        WasmKeyring {
            inner: handles::Keyring::new(&group_id),
        }
    }

    /// Rebuild a keyring from explicit key material (a rotated key handed to
    /// this device). `key` must be the 32-byte session key.
    #[wasm_bindgen]
    pub fn import(group_id: String, epoch: f64, key: Vec<u8>) -> Result<WasmKeyring, JsValue> {
        handles::Keyring::import(&group_id, epoch as u64, &key)
            .map(|inner| WasmKeyring { inner })
            .map_err(ffi_error)
    }

    #[wasm_bindgen(getter)]
    pub fn group_id(&self) -> String {
        self.inner.inner.group_id.clone()
    }

    #[wasm_bindgen]
    pub fn epoch(&self) -> f64 {
        self.inner.epoch() as f64
    }

    /// Seal one operation payload under this keyring's current epoch, as the
    /// relay wire envelope (camelCase + base64url). The output is directly
    /// appendable to a relay channel.
    #[wasm_bindgen]
    pub fn seal(&self, sender_device_id: String, plaintext: Vec<u8>) -> String {
        self.inner.seal_json(&sender_device_id, &plaintext)
    }

    /// Open one relay page back into operation payloads. Envelopes whose
    /// message id the receive position already records are skipped as
    /// redeliveries; the ids of the ones actually opened are marked seen
    /// only after the whole batch decrypts, so a page that fails leaves the
    /// receive position untouched (the host then re-pulls from its committed
    /// cursor and fails again for the same reason).
    #[wasm_bindgen]
    pub fn open_batch(
        &self,
        envelope_jsons: Vec<String>,
        receive: &mut WasmReceiveState,
    ) -> Result<Vec<String>, JsValue> {
        let mut fresh: Vec<Envelope> = Vec::new();
        for json in &envelope_jsons {
            let envelope: Envelope = serde_json::from_str(json)
                .map_err(|error| js_error(format!("invalid envelope json: {error}")))?;
            if receive
                .inner
                .0
                .seen_message_ids
                .contains(&envelope.message_id)
            {
                continue; // a redelivery the receive position already saw
            }
            fresh.push(envelope);
        }
        if fresh.is_empty() {
            return Ok(Vec::new());
        }
        let mut replay = HashSet::new();
        let operations = open_operations(&fresh, &self.inner.inner, &mut replay)
            .map_err(|error| js_error(error.to_string()))?;
        receive.inner.0.seen_message_ids.extend(replay);
        operations
            .iter()
            .map(|op| serde_json::to_string(op).map_err(js_error))
            .collect()
    }
}

// ------------------------------------------------------ conformance / versions

/// Runs a cross-language conformance fixture through the same canonical
/// runner the C ABI exposes, returning the report JSON. Thread-free; safe on
/// wasm32.
#[wasm_bindgen]
pub fn conformance_run(fixture_json: &str) -> Result<String, JsValue> {
    let fixture = std::ffi::CString::new(fixture_json).map_err(js_error)?;
    let report = unsafe { syncbond_ffi::abi::sb_conformance_run(fixture.as_ptr()) };
    if report.is_null() {
        return Err(js_error(format!(
            "conformance runner failed: {}",
            last_error_message()
        )));
    }
    let text = unsafe {
        std::ffi::CStr::from_ptr(report)
            .to_string_lossy()
            .into_owned()
    };
    syncbond_ffi::abi::sb_free_string(report);
    Ok(text)
}

#[wasm_bindgen]
pub fn protocol_version() -> u32 {
    syncbond_ffi::abi::sb_protocol_version()
}

#[wasm_bindgen]
pub fn abi_version() -> u32 {
    syncbond_ffi::abi::sb_abi_version()
}

// -------------------------------------------------------------- constants

#[wasm_bindgen]
pub fn pairing_role_initiator() -> i32 {
    SB_PAIR_ROLE_INITIATOR
}

#[wasm_bindgen]
pub fn pairing_role_responder() -> i32 {
    SB_PAIR_ROLE_RESPONDER
}

#[wasm_bindgen]
pub fn pairing_event_completed() -> i32 {
    SB_PAIR_EVENT_COMPLETED
}

#[wasm_bindgen]
pub fn pairing_event_failed() -> i32 {
    SB_PAIR_EVENT_FAILED
}

#[wasm_bindgen]
pub fn strategy_lww_hlc() -> u32 {
    syncbond_ffi::error::SB_STRATEGY_LWW_HLC
}

#[wasm_bindgen]
pub fn strategy_or_set() -> u32 {
    syncbond_ffi::error::SB_STRATEGY_OR_SET
}

#[wasm_bindgen]
pub fn strategy_pn_counter() -> u32 {
    syncbond_ffi::error::SB_STRATEGY_PN_COUNTER
}

/// A fresh pairing code for the host to display and send out of band; both
/// ends of an exchange are handed the same code.
#[wasm_bindgen]
pub fn generate_pairing_code() -> String {
    syncbond_core::codes::generate_code()
}

// --------------------------------------------------------------- helpers

fn js_error(message: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

/// The handle layer returns [`syncbond_ffi::error::FfiError`], which has no
/// `Display`; its `message` is the human-readable text.
fn ffi_error(error: syncbond_ffi::error::FfiError) -> JsValue {
    js_error(error.message)
}

/// A wall clock the replicator can actually call on this target. wasm32 does
/// not implement `SystemTime`; js-sys reads `Date.now()` instead.
fn wall_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| {
        #[cfg(target_arch = "wasm32")]
        {
            js_sys::Date::now() as u64
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0)
        }
    })
}

fn last_error_message() -> String {
    unsafe {
        let text = syncbond_ffi::abi::sb_last_error();
        if text.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(text)
                .to_string_lossy()
                .into_owned()
        }
    }
}
