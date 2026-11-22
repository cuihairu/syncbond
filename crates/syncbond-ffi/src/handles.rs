//! Handle-based inner API.
//!
//! This is the single semantic surface the C ABI, the Python bindings and
//! the Node bindings all consume. It performs serialization and resource
//! management only: protocol logic stays in syncbond-core.

use std::collections::{BTreeMap, HashSet};
#[cfg(feature = "relay")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(feature = "relay")]
use std::thread::JoinHandle;
#[cfg(feature = "relay")]
use std::time::Duration;

use syncbond_core::conflict::{LwwHlc, MergeStrategy, OrSetStrategy, PnCounterStrategy, Record};
use syncbond_core::crypto::{
    b64url_decode, b64url_encode, seal, EncryptedEnvelope, KeyRing, SessionKey,
};
use syncbond_core::hlc::HlcStamp;
use syncbond_core::identity::DeviceIdentity;
#[cfg(feature = "relay")]
use syncbond_core::outbox::{stage_operations, MemoryOutboxStore};
use syncbond_core::pairing::{accept, pair, PairingError, PairingSession};
use syncbond_core::pairing_driver::{DriverEvent, PairingDriver};
use syncbond_core::receive::{cursor_key, ReceiveState as CoreReceiveState, ServerCursor};
use syncbond_core::replication::{Operation, Replicator as CoreReplicator, SyncStats};
#[cfg(feature = "relay")]
use syncbond_core::storage::MemoryStorage;
use syncbond_core::storage::SyncState;
#[cfg(feature = "relay")]
use syncbond_core::sync_driver::{run_sync, DriverConfig, StopReason, SyncDriver};
use syncbond_core::transport::{MemoryTransport, Transport};
#[cfg(feature = "relay")]
use syncbond_relay_client::{DriverTransport, RelayClient, TlsPolicy};

use crate::error::{
    FfiError, SB_ERR_VERSION_MISMATCH, SB_PAIR_EVENT_COMPLETED, SB_PAIR_EVENT_FAILED,
    SB_PAIR_EVENT_NONE, SB_PAIR_ROLE_INITIATOR, SB_PAIR_ROLE_RESPONDER, SB_STATE_SNAPSHOT_VERSION,
    SB_STRATEGY_LWW_HLC, SB_STRATEGY_OR_SET, SB_STRATEGY_PN_COUNTER,
};
#[cfg(feature = "relay")]
use crate::error::{
    SB_DRIVER_STOP_CANCELLED, SB_DRIVER_STOP_EXHAUSTED, SB_DRIVER_STOP_FATAL, SB_DRIVER_STOP_NONE,
    SB_TLS_ACCEPT_INVALID, SB_TLS_VALIDATE, SB_TLS_VALIDATE_CA,
};

type Json = serde_json::Value;

/// Identity of one device.
pub struct Identity(pub DeviceIdentity);

impl Identity {
    pub fn generate() -> Self {
        Self(DeviceIdentity::generate())
    }

    pub fn import(secret_key: &[u8]) -> Result<Self, FfiError> {
        DeviceIdentity::from_secret_key_bytes(secret_key)
            .map(Self)
            .map_err(|error| FfiError::input(error.to_string()))
    }

    pub fn device_id(&self) -> String {
        self.0.device_id.clone()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.public_key
    }

    pub fn secret_key(&self) -> [u8; 64] {
        self.0.secret_key
    }
}

/// Both sessions produced by one pairing handshake.
pub struct PairResult {
    pub initiator: Arc<PairingSession>,
    pub responder: Arc<PairingSession>,
    pub code: String,
}

impl PairResult {
    /// Pair two freshly generated devices over an in-memory loopback. Both
    /// sides of the handshake run inside this call.
    pub fn memory(code: Option<&str>) -> Result<Self, FfiError> {
        let code = match code {
            Some(code) if !code.is_empty() => code.to_string(),
            Some(_) => return Err(FfiError::input("pairing code must not be empty")),
            None => syncbond_core::codes::generate_code(),
        };
        let (left_transport, right_transport) = MemoryTransport::pair();
        let left_identity = DeviceIdentity::generate();
        let right_identity = DeviceIdentity::generate();
        let left_code = code.clone();
        let left_transport = left_transport as Arc<dyn Transport>;
        let right_transport = right_transport as Arc<dyn Transport>;
        let handle = std::thread::spawn(move || pair(&left_code, &left_identity, left_transport));
        let right = accept(&code, &right_identity, right_transport)?;
        let left = handle
            .join()
            .map_err(|_| FfiError::internal("pairing thread panicked"))?;
        let left = left.map_err(FfiError::from)?;
        Ok(Self {
            initiator: Arc::new(left),
            responder: Arc::new(right),
            code,
        })
    }
}

/// One authenticated, encrypted session end.
pub struct Session(pub Arc<PairingSession>);

impl Session {
    pub fn group_id(&self) -> String {
        self.0.group_id.clone()
    }

    pub fn peer_device_id(&self) -> String {
        self.0.peer_identity.device_id.clone()
    }

    pub fn invalidated(&self) -> bool {
        self.0.is_invalidated()
    }

    pub fn send(&self, payload: &[u8]) -> Result<(), FfiError> {
        self.0.seal_and_send(payload).map_err(FfiError::from)
    }

    pub fn recv(&self) -> Result<Vec<u8>, FfiError> {
        self.0.recv_and_open().map_err(FfiError::from)
    }

    pub fn invalidate(&self) {
        self.0.invalidate();
    }
}

/// One end of an externally driven pairing exchange (todo.md DSR-34).
///
/// The host owns the wire and the event loop: it pulls the outbound protocol
/// frames with [`PairEnd::pop_outgoing`], feeds the inbound ones with
/// [`PairEnd::push`], and advances the machine with [`PairEnd::poll`] until
/// it reports [`SB_PAIR_EVENT_COMPLETED`] (take the session) or
/// [`SB_PAIR_EVENT_FAILED`] (read the reason). Both ends start from the
/// caller's existing [`Identity`], unlike [`PairResult::memory`] which
/// generates two fresh identities inside one call.
pub struct PairEnd {
    driver: PairingDriver,
    /// Set when poll observes [`DriverEvent::Completed`]; `take_session`
    /// moves it to the caller once.
    session: Option<PairingSession>,
    /// Set when poll observes [`DriverEvent::Failed`]; `failure` reads it.
    failure: Option<String>,
}

impl PairEnd {
    /// Start one end of the exchange from the caller's identity. `code` is
    /// required (both ends must be handed the same issued code) and is
    /// normalized exactly as [`PairResult::memory`] normalizes it, so a
    /// lower-case entry pairs with the upper-case issued code.
    pub fn new(identity: &Identity, role: i32, code: &str) -> Result<Self, FfiError> {
        if role != SB_PAIR_ROLE_INITIATOR && role != SB_PAIR_ROLE_RESPONDER {
            return Err(FfiError::input(format!("unknown pairing role {role}")));
        }
        // The driver needs a transport only for the session it assembles at
        // completion; the pairing frames themselves cross this handle, so
        // the loopback peer end is dropped on purpose. The session's
        // application channel is the host's to wire (its own frames, or the
        // relay driver), and must never silently look connected.
        let (own, _peer) = MemoryTransport::pair();
        let driver = match role {
            SB_PAIR_ROLE_INITIATOR => {
                PairingDriver::initiator(code, &identity.0, own as Arc<dyn Transport>)
            }
            _ => PairingDriver::responder(code, &identity.0, own as Arc<dyn Transport>),
        }
        .map_err(|error| match error {
            PairingError::Code(bad) => FfiError::input(format!("pairing code: {bad}")),
            other => FfiError::from(other),
        })?;
        Ok(Self {
            driver,
            session: None,
            failure: None,
        })
    }

    /// The next frame the machine wants on the wire, if any.
    pub fn pop_outgoing(&mut self) -> Option<Vec<u8>> {
        self.driver.pop_outgoing()
    }

    /// Feed one frame received from the wire. Ok even when the frame is a
    /// protocol violation — the violation becomes a [`SB_PAIR_EVENT_FAILED`]
    /// poll plus one queued abort frame, so the host's drain-send-poll loop
    /// delivers the goodbye without special-casing. Err means the exchange
    /// was already finished: the frame arrived too late, which is a host
    /// bug, not a peer one.
    pub fn push(&mut self, frame: &[u8]) -> Result<(), FfiError> {
        self.driver.push(frame).map_err(FfiError::from)
    }

    /// Advance the machine and report what it found, exactly once.
    pub fn poll(&mut self) -> i32 {
        match self.driver.poll() {
            None => SB_PAIR_EVENT_NONE,
            Some(DriverEvent::Completed(session)) => {
                self.session = Some(session);
                SB_PAIR_EVENT_COMPLETED
            }
            Some(DriverEvent::Failed(error)) => {
                self.failure = Some(error.to_string());
                SB_PAIR_EVENT_FAILED
            }
        }
    }

    /// Queue the goodbye frame (best effort, once), for a host that gives up
    /// for transport reasons.
    pub fn abort(&mut self) {
        self.driver.abort();
    }

    /// Whether the exchange reached its terminal transition. Finished ends
    /// refuse further frames, so a host routing inbound frames by state
    /// gates on this before calling [`PairEnd::push`].
    pub fn is_finished(&self) -> bool {
        self.driver.is_finished()
    }

    /// The failure the poll reported, if any; `None` while the exchange is
    /// still live or after it completed.
    pub fn failure(&self) -> Option<String> {
        self.failure.clone()
    }

    /// Take the completed session; ownership moves to the caller (free with
    /// `sb_session_free`). Only available once a [`SB_PAIR_EVENT_COMPLETED`]
    /// poll has handed the session over.
    pub fn take_session(&mut self) -> Result<Session, FfiError> {
        let session = self
            .session
            .take()
            .ok_or_else(|| FfiError::input("no completed session available"))?;
        Ok(Session(Arc::new(session)))
    }
}

/// One synchronizing device.
pub struct Replicator(pub CoreReplicator);

impl Replicator {
    pub fn new(node_id: &str, strategy: u32) -> Result<Self, FfiError> {
        Self::new_clock(node_id, strategy, 0)
    }

    /// `fixed_now_ms == 0` uses the wall clock.
    pub fn new_clock(node_id: &str, strategy: u32, fixed_now_ms: u64) -> Result<Self, FfiError> {
        if node_id.is_empty() {
            return Err(FfiError::input("node id must not be empty"));
        }
        let strategy = Self::strategy(strategy)?;
        let replicator = if fixed_now_ms == 0 {
            CoreReplicator::with_strategy(node_id, strategy)
        } else {
            CoreReplicator::with_fixed_clock(node_id, strategy, fixed_now_ms)
        };
        Ok(Self(replicator))
    }

    pub fn strategy(code: u32) -> Result<Arc<dyn MergeStrategy>, FfiError> {
        Ok(match code {
            SB_STRATEGY_LWW_HLC => Arc::new(LwwHlc),
            SB_STRATEGY_OR_SET => Arc::new(OrSetStrategy),
            SB_STRATEGY_PN_COUNTER => Arc::new(PnCounterStrategy),
            other => return Err(FfiError::input(format!("unknown merge strategy {other}"))),
        })
    }

    pub fn node_id(&self) -> String {
        self.0.node_id.clone()
    }

    pub fn record_count(&self) -> u32 {
        self.0.record_count() as u32
    }

    pub fn oplog_len(&self) -> u32 {
        self.0.oplog().len() as u32
    }

    pub fn put(&mut self, key: &str, payload: &[u8]) -> Result<(), FfiError> {
        if key.is_empty() {
            return Err(FfiError::input("key must not be empty"));
        }
        self.0
            .put(key, payload.to_vec())
            .map(|_| ())
            .map_err(|error| FfiError::protocol(error.to_string()))
    }

    pub fn delete(&mut self, key: &str) -> Result<(), FfiError> {
        if key.is_empty() {
            return Err(FfiError::input("key must not be empty"));
        }
        self.0
            .delete(key)
            .map(|_| ())
            .map_err(|error| FfiError::protocol(error.to_string()))
    }

    /// Payload of a live record; `None` when the key is missing or tombstoned.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.0
            .get(key)
            .filter(|record| !record.deleted)
            .map(|record| record.payload.clone())
    }

    pub fn live_keys_json(&self) -> String {
        serde_json::to_string(&self.0.live_keys()).expect("string list serialization is infallible")
    }

    /// Sorted list of keys that currently hold a live value.
    pub fn live_keys(&self) -> Vec<String> {
        self.0.live_keys()
    }

    /// Canonical, fully sorted dump of the local state as a JSON object.
    pub fn dump(&self) -> Json {
        dump_node(&self.0)
    }

    pub fn op_json(&self, index: u32) -> Result<String, FfiError> {
        let op = self
            .0
            .oplog()
            .get(index as usize)
            .ok_or_else(|| FfiError::input(format!("oplog index {index} out of range")))?;
        serde_json::to_string(op).map_err(|error| FfiError::protocol(error.to_string()))
    }

    /// Apply one wire op; `false` when it was a duplicate or was rejected
    /// because it would resurrect a garbage-collected delete.
    pub fn apply_remote_json(&mut self, op_json: &str) -> Result<bool, FfiError> {
        let op: Operation = serde_json::from_str(op_json)
            .map_err(|error| FfiError::input(format!("invalid op json: {error}")))?;
        self.0
            .apply_remote(&op)
            .map_err(|error| FfiError::protocol(error.to_string()))
    }

    pub fn sync(&mut self, session: &Session, send_first: bool) -> Result<SyncStats, FfiError> {
        self.0
            .sync_over(&session.0, send_first)
            .map_err(FfiError::from)
    }

    pub fn gc_tombstones(&mut self, now_ms: u64, older_than_ms: u64) -> Result<usize, FfiError> {
        Ok(self.0.gc_tombstones(now_ms, older_than_ms).collected.len())
    }

    /// Time-threshold tombstone GC (the degraded, dominance-free path the
    /// conformance runner drives for deterministic collection).
    pub fn gc_tombstones_time_only(
        &mut self,
        now_ms: u64,
        older_than_ms: u64,
    ) -> Result<usize, FfiError> {
        Ok(self
            .0
            .gc_tombstones_time_only(now_ms, older_than_ms)
            .collected
            .len())
    }

    /// Canonical, fully sorted dump of every record.
    pub fn records_json(&self) -> String {
        serde_json::to_string(&dump_node(&self.0)).expect("dump serialization is infallible")
    }

    /// Canonical, fully sorted dump of the collected tombstone barriers.
    pub fn gc_barriers_json(&self) -> String {
        let barriers: BTreeMap<String, Json> = self
            .0
            .gc_barriers()
            .iter()
            .map(|(key, record)| (key.clone(), dump_record(record)))
            .collect();
        serde_json::to_string(&barriers).expect("dump serialization is infallible")
    }

    /// Serialize the replicator's committed state together with a receive
    /// position into one versioned snapshot blob (todo.md DSR-35).
    ///
    /// The committed state is whatever the last `commit_receive` persisted:
    /// oplog (hence every applied record and tombstone), the local write
    /// cursor, the HLC high-water and the garbage-collection barriers — so a
    /// restart replays exactly what was committed and never invents a cursor
    /// ahead of its data. `identity`, `group_id` and `key_epoch` are the
    /// caller's group facts: the replicator does not hold them, and the
    /// snapshot embeds them so the restored device can open what it pulled.
    pub fn export_snapshot(
        &self,
        identity: &Identity,
        group_id: &str,
        key_epoch: u64,
        receive: &ReceiveState,
    ) -> Result<Vec<u8>, FfiError> {
        build_snapshot(&self.0, &identity.0, group_id, key_epoch, &receive.0)
    }
}

/// Assemble the versioned snapshot blob (todo.md DSR-35): the replicator's
/// committed state, the receive position that explains it, and the group
/// facts the restored device needs. Shared by [`Replicator::export_snapshot`],
/// the relay driver's state export and the WASM bindings' full state
/// recovery, so they can never drift.
pub fn build_snapshot(
    replicator: &CoreReplicator,
    identity: &DeviceIdentity,
    group_id: &str,
    key_epoch: u64,
    receive: &CoreReceiveState,
) -> Result<Vec<u8>, FfiError> {
    let state = replicator.snapshot_state(identity, group_id, key_epoch);
    let state = serde_json::to_value(&state)
        .map_err(|error| FfiError::internal(format!("state is not serializable: {error}")))?;
    let receive = serde_json::to_value(receive).map_err(|error| {
        FfiError::internal(format!("receive position is not serializable: {error}"))
    })?;
    let snapshot = Json::Object(
        std::iter::once(("version".to_string(), Json::from(SB_STATE_SNAPSHOT_VERSION)))
            .chain([
                ("state".to_string(), state),
                ("receive".to_string(), receive),
            ])
            .collect(),
    );
    serde_json::to_vec(&snapshot)
        .map_err(|error| FfiError::internal(format!("snapshot is not serializable: {error}")))
}

/// The receive-side pull position and dedup knowledge (todo.md DSR-35).
///
/// Kept apart from [`Replicator`] because it moves with a pulled page rather
/// than with a local write, and that is exactly what makes it worth carrying
/// in the snapshot: without it a restart would re-pull (and re-apply) every
/// remote operation it had already seen.
#[derive(Default)]
pub struct ReceiveState(pub CoreReceiveState);

impl ReceiveState {
    pub fn new() -> Self {
        Self::default()
    }

    /// The server-assigned sequence the next pull must start after, for one
    /// (server, channel). Upserts, so a page that goes further back still
    /// records itself.
    pub fn set_server_cursor(
        &mut self,
        server_id: &str,
        channel_id: &str,
        server_seq: u64,
    ) -> Result<(), FfiError> {
        if server_id.is_empty() || channel_id.is_empty() {
            return Err(FfiError::input("server and channel ids must not be empty"));
        }
        self.0.server_cursors.insert(
            cursor_key(server_id, channel_id),
            ServerCursor {
                server_id: server_id.to_string(),
                channel_id: channel_id.to_string(),
                server_seq,
            },
        );
        Ok(())
    }

    /// The highest local cursor seen for one replica's `"<node>:<n>"` op ids.
    pub fn set_source_cursor(&mut self, node_id: &str, seq: u64) -> Result<(), FfiError> {
        if node_id.is_empty() {
            return Err(FfiError::input("node id must not be empty"));
        }
        self.0.source_cursors.insert(node_id.to_string(), seq);
        Ok(())
    }

    /// Record one already-opened envelope so a redelivery is a no-op.
    pub fn mark_seen(&mut self, message_id: &str) -> Result<(), FfiError> {
        if message_id.is_empty() {
            return Err(FfiError::input("message id must not be empty"));
        }
        self.0.seen_message_ids.insert(message_id.to_string());
        Ok(())
    }

    /// `None` when this (server, channel) has never been pulled.
    pub fn server_seq(&self, server_id: &str, channel_id: &str) -> Option<u64> {
        self.0
            .cursor_for(server_id, channel_id)
            .map(|cursor| cursor.server_seq)
    }

    pub fn seen(&self, message_id: &str) -> bool {
        self.0.seen_message_ids.contains(message_id)
    }

    /// Canonical dump; deterministic because the maps and the set are
    /// ordered, so a round trip can be compared byte for byte.
    pub fn json(&self) -> String {
        serde_json::to_string(&self.0).expect("receive state serialization is infallible")
    }
}

/// One versioned snapshot: the replicator's committed state and the receive
/// position that explains it, moved together (todo.md DSR-35).
///
/// **This blob is private material.** The embedded `SyncState` carries the
/// device identity's Ed25519 secret key, so a snapshot leak forges that
/// device's identity and opens its sessions. Store it behind the
/// application's protected storage or encrypt it at rest — the SDK never
/// encrypts its own storage.
///
/// Laid out as `{"version": N, "state": ..., "receive": ...}` so a future
/// format change bumps the version without a schema of its own.
pub fn import_snapshot(blob: &[u8], strategy: u32) -> Result<(Replicator, ReceiveState), FfiError> {
    let (state, receive) = parse_snapshot(blob)?;
    let core = CoreReplicator::from_state(&state, Replicator::strategy(strategy)?)
        .map_err(|error| FfiError::protocol(format!("snapshot state is inconsistent: {error}")))?;
    Ok((Replicator(core), ReceiveState(receive)))
}

/// wasm-safe variant of [`import_snapshot`]: the host supplies the wall clock
/// (`js_sys::Date::now` on wasm32, where `SystemTime` is unavailable). The
/// blob format and the version check are identical — only the clock source
/// differs, so a snapshot exported by any binding imports on any other.
pub fn import_snapshot_with_clock(
    blob: &[u8],
    strategy: u32,
    now_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> Result<(Replicator, ReceiveState), FfiError> {
    let (state, receive) = parse_snapshot(blob)?;
    let core =
        CoreReplicator::from_state_with_clock(&state, Replicator::strategy(strategy)?, now_ms)
            .map_err(|error| {
                FfiError::protocol(format!("snapshot state is inconsistent: {error}"))
            })?;
    Ok((Replicator(core), ReceiveState(receive)))
}

/// The version check and the state/receive split, shared by both import
/// paths so the two can never drift in what they accept.
fn parse_snapshot(blob: &[u8]) -> Result<(SyncState, CoreReceiveState), FfiError> {
    let snapshot: Json = serde_json::from_slice(blob)
        .map_err(|error| FfiError::input(format!("snapshot is unreadable: {error}")))?;
    let version = snapshot
        .get("version")
        .and_then(Json::as_u64)
        .ok_or_else(|| FfiError::input("snapshot has no version"))?;
    if version != u64::from(SB_STATE_SNAPSHOT_VERSION) {
        return Err(FfiError::new(
            SB_ERR_VERSION_MISMATCH,
            format!("snapshot version {version} is not this build's {SB_STATE_SNAPSHOT_VERSION}"),
        ));
    }
    let state: SyncState = serde_json::from_value(
        snapshot
            .get("state")
            .cloned()
            .ok_or_else(|| FfiError::input("snapshot has no state"))?,
    )
    .map_err(|error| FfiError::input(format!("snapshot state is unreadable: {error}")))?;
    let receive: CoreReceiveState = serde_json::from_value(
        snapshot
            .get("receive")
            .cloned()
            .ok_or_else(|| FfiError::input("snapshot has no receive position"))?,
    )
    .map_err(|error| FfiError::input(format!("receive position is unreadable: {error}")))?;
    Ok((state, receive))
}

/// Group key material with replay tracking for one device.
pub struct Keyring {
    pub inner: KeyRing,
    seen: Mutex<HashSet<String>>,
}

impl Keyring {
    pub fn new(group_id: &str) -> Self {
        Self {
            inner: KeyRing::new(group_id),
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Import explicit key material, as a rotated key handed to this device.
    pub fn import(group_id: &str, epoch: u64, key: &[u8]) -> Result<Self, FfiError> {
        let bytes: SessionKey = key
            .try_into()
            .map_err(|_| FfiError::input("group key must be 32 bytes"))?;
        Ok(Self {
            inner: KeyRing::with_epoch(group_id, epoch, bytes),
            seen: Mutex::new(HashSet::new()),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.inner.current_epoch()
    }

    /// Mint the next epoch and return the new key for distribution.
    pub fn rotate(&mut self) -> (u64, SessionKey) {
        self.inner.rotate()
    }

    /// Seal under this keyring's current epoch; returns envelope JSON.
    pub fn seal_json(&self, sender_device_id: &str, plaintext: &[u8]) -> String {
        let envelope = seal(
            self.inner.current_key(),
            &self.inner.group_id,
            sender_device_id,
            self.epoch(),
            plaintext,
        );
        serde_json::to_string(&envelope).expect("envelope serialization is infallible")
    }

    /// Open with this keyring's current key and epoch, enforcing the version,
    /// group, epoch, replay and AEAD checks in that order.
    pub fn open_json(&self, envelope_json: &str) -> Result<Vec<u8>, FfiError> {
        let envelope: EncryptedEnvelope = serde_json::from_str(envelope_json)
            .map_err(|error| FfiError::input(format!("invalid envelope json: {error}")))?;
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        syncbond_core::crypto::open(
            self.inner.current_key(),
            &envelope,
            &mut syncbond_core::crypto::EnvelopeContext {
                group_id: &self.inner.group_id,
                current_key_epoch: self.epoch(),
                seen_message_ids: &mut seen,
            },
        )
        .map_err(|error| FfiError::crypto(&error))
    }
}

#[cfg(feature = "relay")]
/// One device's session against one relay channel, driven from the C ABI
/// (todo.md DSR-36).
///
/// The driver owns the network (a multi-thread tokio runtime, the relay
/// HTTP client and the bridge that serves the core driver seam), the device
/// state (replicator, receive position, keyring, identity, outbox, store)
/// and one worker thread that runs the core driver loop. The worker locks
/// the device state only while a cycle runs, releasing it during every
/// backoff and idle wait, so the host can interleave [`RelayDriver::write`]
/// and [`RelayDriver::delete`] between cycles; a concurrent call simply
/// waits for the current cycle to finish.
///
/// Lifecycle is explicit and single-threaded from the host's side:
/// - [`RelayDriver::new`] builds the runtime, the client and the transport.
/// - [`RelayDriver::start`] spawns exactly one worker thread.
/// - [`RelayDriver::stop`] cancels the loop and joins the thread; it is
///   idempotent and safe on an already-stopped driver.
/// - [`RelayDriver::drop`] stops first, so the runtime always outlives the
///   worker that blocks on it.
///
/// Progress is polled, never delivered by callback: [`RelayDriver::running`]
/// and [`RelayDriver::counters`] report what the worker has accumulated and
/// [`RelayDriver::stop_reason`] reports why the loop ended. The worker never
/// outlives the handle and no pointer into its frame is ever handed out, so
/// the resource lifetime is bounded by the handle's own.
pub struct RelayDriver {
    // Held for its Drop only: the transport's Handle must stay valid until
    // the worker thread joins, which `Drop` guarantees by stopping first.
    #[allow(dead_code)]
    runtime: tokio::runtime::Runtime,
    transport: DriverTransport,
    config: Mutex<DriverConfig>,
    group: String,
    key_epoch: u64,
    server_id: String,
    channel_id: String,
    inner: Arc<Mutex<DriverInner>>,
    progress: Arc<Mutex<DriverProgress>>,
    outcome: Arc<Mutex<Option<StopOutcome>>>,
    cancel: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[cfg(feature = "relay")]
/// The device state the worker locks around each cycle.
struct DriverInner {
    replicator: CoreReplicator,
    receive: CoreReceiveState,
    keyring: KeyRing,
    identity: DeviceIdentity,
    outbox: MemoryOutboxStore,
    store: MemoryStorage,
}

/// Monotonic counters the host polls; a running driver keeps the numbers
/// growing across cycles.
#[cfg(feature = "relay")]
#[derive(Default, Clone)]
pub struct DriverProgress {
    pub running: bool,
    pub cycles: u64,
    pub sent_batches: u64,
    pub sent_envelopes: u64,
    pub pages_pulled: u64,
    pub applied: u64,
}

/// Why the worker loop ended, in C-friendly form.
#[cfg(feature = "relay")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    Cancelled,
    Exhausted(String),
    Fatal(String),
}

#[cfg(feature = "relay")]
impl StopOutcome {
    /// The `SB_DRIVER_STOP_*` code.
    pub fn code(&self) -> i32 {
        match self {
            StopOutcome::Cancelled => SB_DRIVER_STOP_CANCELLED,
            StopOutcome::Exhausted(_) => SB_DRIVER_STOP_EXHAUSTED,
            StopOutcome::Fatal(_) => SB_DRIVER_STOP_FATAL,
        }
    }

    fn from_reason(reason: StopReason) -> Self {
        match reason {
            StopReason::Cancelled => StopOutcome::Cancelled,
            StopReason::Exhausted(error) => StopOutcome::Exhausted(error.to_string()),
            StopReason::Fatal(error) => StopOutcome::Fatal(error.to_string()),
        }
    }
}

#[cfg(feature = "relay")]
impl RelayDriver {
    /// Build the driver over a live relay channel. `channel_id` and
    /// `channel_token` are the relay's own id and the credential that
    /// authorizes this device to append and pull it; `server_id` and
    /// `cursor_channel` are the local cursor labels the receive position
    /// uses (they may, but need not, mirror the relay names). The last four
    /// handles transfer ownership to the driver and are freed with it.
    // One explicit positional constructor for the C ABI; bundling the
    // connection facts into a struct would add a handle without removing
    // any of the facts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay_url: &str,
        channel_id: &str,
        channel_token: &str,
        server_id: &str,
        cursor_channel: &str,
        group_id: &str,
        key_epoch: u64,
        identity: Identity,
        keyring: Keyring,
        replicator: Replicator,
        receive: ReceiveState,
        timeout_ms: u64,
        tls_mode: u32,
        ca_der: &[u8],
    ) -> Result<Self, FfiError> {
        if channel_id.is_empty()
            || channel_token.is_empty()
            || server_id.is_empty()
            || cursor_channel.is_empty()
            || group_id.is_empty()
        {
            return Err(FfiError::input("driver ids must not be empty"));
        }
        if timeout_ms == 0 {
            return Err(FfiError::input("timeout must be positive"));
        }
        let tls = match tls_mode {
            SB_TLS_VALIDATE => TlsPolicy::Validate,
            SB_TLS_VALIDATE_CA => {
                if ca_der.is_empty() {
                    return Err(FfiError::input("pinned CA must not be empty"));
                }
                TlsPolicy::ValidateCa(ca_der.to_vec())
            }
            SB_TLS_ACCEPT_INVALID => TlsPolicy::AcceptInvalid,
            other => return Err(FfiError::input(format!("unknown tls mode {other}"))),
        };
        let client = RelayClient::new(relay_url, tls, Duration::from_millis(timeout_ms))
            .map_err(|error| FfiError::input(format!("relay url: {error}")))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| FfiError::internal(format!("relay runtime: {error}")))?;
        let transport =
            DriverTransport::new(client, channel_id, channel_token, runtime.handle().clone());

        let Identity(identity) = identity;
        let Keyring {
            inner: keyring,
            seen: _,
        } = keyring;
        let Replicator(replicator) = replicator;
        let ReceiveState(receive) = receive;

        Ok(Self {
            runtime,
            transport,
            config: Mutex::new(DriverConfig::default()),
            group: group_id.to_string(),
            key_epoch,
            server_id: server_id.to_string(),
            channel_id: cursor_channel.to_string(),
            inner: Arc::new(Mutex::new(DriverInner {
                replicator,
                receive,
                keyring,
                identity,
                outbox: MemoryOutboxStore::default(),
                store: MemoryStorage::new(),
            })),
            progress: Arc::new(Mutex::new(DriverProgress::default())),
            outcome: Arc::new(Mutex::new(None)),
            cancel: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
        })
    }

    /// Replace the loop's pacing knobs; only effective before [`start`]
    /// (the running thread already holds the config it started with).
    ///
    /// [`start`]: RelayDriver::start
    pub fn set_config(&self, config: DriverConfig) {
        *self.config.lock().unwrap() = config;
    }

    /// Spawn the worker thread. Idempotent per lifecycle: a second call
    /// while running is an input error; after [`stop`] the driver may be
    /// started again (it resumes from the state it holds).
    ///
    /// [`stop`]: RelayDriver::stop
    pub fn start(&self) -> Result<(), FfiError> {
        {
            let thread = self.thread.lock().unwrap();
            if thread.is_some() {
                return Err(FfiError::input("driver is already running"));
            }
        }
        self.cancel.store(false, Ordering::Relaxed);
        *self.progress.lock().unwrap() = DriverProgress {
            running: true,
            ..DriverProgress::default()
        };
        *self.outcome.lock().unwrap() = None;

        let inner = Arc::clone(&self.inner);
        let progress = Arc::clone(&self.progress);
        let outcome = Arc::clone(&self.outcome);
        let cancel = Arc::clone(&self.cancel);
        let transport = self.transport.clone();
        let config = self.config.lock().unwrap().clone();
        let group = self.group.clone();
        let key_epoch = self.key_epoch;
        let server_id = self.server_id.clone();
        let channel_id = self.channel_id.clone();

        let handle = std::thread::Builder::new()
            .name("syncbond-relay-driver".to_string())
            .spawn(move || {
                let stop = run_sync(&config, &cancel, || {
                    let report = {
                        let mut guard = inner.lock().unwrap();
                        let DriverInner {
                            replicator,
                            receive,
                            keyring,
                            identity,
                            outbox,
                            store,
                        } = &mut *guard;
                        let mut driver = SyncDriver {
                            replicator,
                            receive,
                            store,
                            keyring,
                            identity,
                            group: &group,
                            key_epoch,
                            outbox,
                            transport: &transport,
                            server_id: &server_id,
                            channel_id: &channel_id,
                            config: config.clone(),
                        };
                        driver.sync_once()
                    };
                    if let Ok(report) = &report {
                        let mut p = progress.lock().unwrap();
                        p.cycles += 1;
                        p.sent_batches += report.sent_batches as u64;
                        p.sent_envelopes += report.sent_envelopes as u64;
                        p.pages_pulled += report.pages_pulled as u64;
                        p.applied += report.applied as u64;
                    }
                    report
                });
                *outcome.lock().unwrap() = Some(StopOutcome::from_reason(stop));
                progress.lock().unwrap().running = false;
            })
            .map_err(|error| FfiError::internal(format!("spawn relay driver thread: {error}")))?;
        *self.thread.lock().unwrap() = Some(handle);
        Ok(())
    }

    /// Cancel the loop and join the worker. Idempotent: stopping an
    /// already-stopped driver is a no-op. The stop reason and any error
    /// text remain queryable via [`stop_reason`] and [`stop_error`].
    ///
    /// [`stop_reason`]: RelayDriver::stop_reason
    /// [`stop_error`]: RelayDriver::stop_error
    pub fn stop(&self) -> Result<(), FfiError> {
        self.cancel.store(true, Ordering::Relaxed);
        let handle = self.thread.lock().unwrap().take();
        if let Some(handle) = handle {
            handle
                .join()
                .map_err(|_| FfiError::internal("relay driver thread panicked"))?;
        }
        Ok(())
    }

    /// Local write: stage and persist, so it survives a crash and the next
    /// cycle sends it. Waits for any cycle currently holding the state.
    pub fn write(&self, key: &str, payload: &[u8]) -> Result<(), FfiError> {
        if key.is_empty() {
            return Err(FfiError::input("key must not be empty"));
        }
        let mut guard = self.inner.lock().unwrap();
        let op = guard
            .replicator
            .put(key, payload.to_vec())
            .map_err(|error| FfiError::protocol(error.to_string()))?;
        stage_operations(
            &guard.outbox,
            &[op],
            &guard.keyring,
            &guard.identity.device_id,
        )
        .map_err(|error| FfiError::protocol(error.to_string()))?;
        let state = guard
            .replicator
            .snapshot_state(&guard.identity, &self.group, self.key_epoch);
        syncbond_core::commit_receive(&guard.store, &state, &guard.receive)
            .map_err(|error| FfiError::protocol(error.to_string()))?;
        Ok(())
    }

    /// Local delete: the tombstone is staged and persisted like a write.
    pub fn delete(&self, key: &str) -> Result<(), FfiError> {
        if key.is_empty() {
            return Err(FfiError::input("key must not be empty"));
        }
        let mut guard = self.inner.lock().unwrap();
        let op = guard
            .replicator
            .delete(key)
            .map_err(|error| FfiError::protocol(error.to_string()))?;
        stage_operations(
            &guard.outbox,
            &[op],
            &guard.keyring,
            &guard.identity.device_id,
        )
        .map_err(|error| FfiError::protocol(error.to_string()))?;
        let state = guard
            .replicator
            .snapshot_state(&guard.identity, &self.group, self.key_epoch);
        syncbond_core::commit_receive(&guard.store, &state, &guard.receive)
            .map_err(|error| FfiError::protocol(error.to_string()))?;
        Ok(())
    }

    /// Payload of a live record; `None` when missing or tombstoned.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let guard = self.inner.lock().unwrap();
        guard
            .replicator
            .get(key)
            .filter(|record| !record.deleted)
            .map(|record| record.payload.clone())
    }

    pub fn running(&self) -> bool {
        self.progress.lock().unwrap().running
    }

    /// `(cycles, sent_batches, sent_envelopes, pages_pulled, applied)`.
    pub fn counters(&self) -> (u64, u64, u64, u64, u64) {
        let progress = self.progress.lock().unwrap();
        (
            progress.cycles,
            progress.sent_batches,
            progress.sent_envelopes,
            progress.pages_pulled,
            progress.applied,
        )
    }

    /// `SB_DRIVER_STOP_NONE` while running or before it ever ran.
    pub fn stop_reason(&self) -> i32 {
        self.outcome
            .lock()
            .unwrap()
            .as_ref()
            .map(StopOutcome::code)
            .unwrap_or(SB_DRIVER_STOP_NONE)
    }

    /// The stop error text, when the loop ended with one. A deliberate
    /// stop (or a driver that has not ended) is `None`.
    pub fn stop_error(&self) -> Option<String> {
        match self.outcome.lock().unwrap().as_ref() {
            Some(StopOutcome::Cancelled) | None => None,
            Some(StopOutcome::Exhausted(message)) | Some(StopOutcome::Fatal(message)) => {
                Some(message.clone())
            }
        }
    }

    /// The device state plus the receive position, as one versioned snapshot
    /// (the same blob `sb_state_export` writes).
    pub fn export_state(&self) -> Result<Vec<u8>, FfiError> {
        let guard = self.inner.lock().unwrap();
        build_snapshot(
            &guard.replicator,
            &guard.identity,
            &self.group,
            self.key_epoch,
            &guard.receive,
        )
    }
}

#[cfg(feature = "relay")]
impl Drop for RelayDriver {
    fn drop(&mut self) {
        // Join the worker before the runtime is dropped: a worker mid-`block_on`
        // must never outlive the runtime it blocks on.
        let _ = self.stop();
    }
}

/// Decode a base64url fixture payload.
pub fn decode_b64url(text: &str) -> Result<Vec<u8>, FfiError> {
    b64url_decode(text).map_err(|error| FfiError::input(format!("invalid base64url: {error}")))
}

/// Canonical dump of one node: sorted records plus sorted live keys.
pub fn dump_node(replicator: &CoreReplicator) -> Json {
    let records: BTreeMap<String, Json> = replicator
        .records_snapshot()
        .into_iter()
        .map(|(key, record)| (key, dump_record(&record)))
        .collect();
    let live_keys: Vec<Json> = replicator
        .live_keys()
        .iter()
        .map(|key| Json::String(key.clone()))
        .collect();
    let mut node: BTreeMap<String, Json> = BTreeMap::new();
    node.insert(
        "records".to_string(),
        serde_json::to_value(&records).expect("dump serialization is infallible"),
    );
    node.insert("live_keys".to_string(), Json::Array(live_keys));
    serde_json::to_value(&node).expect("dump serialization is infallible")
}

/// Canonical dump of one record: sorted keys, stable timestamp shape.
pub fn dump_record(record: &Record) -> Json {
    let witness: BTreeMap<String, Json> = record
        .witness
        .iter()
        .map(|(node, stamp)| (node.clone(), stamp_json(stamp)))
        .collect();
    let mut conflicts: Vec<Json> = record
        .conflicts
        .iter()
        .map(|conflict| stamp_json(&conflict.stamp))
        .collect();
    conflicts.sort_by_key(|value| value.to_string());
    let mut record_map: BTreeMap<String, Json> = BTreeMap::new();
    record_map.insert("deleted".to_string(), Json::Bool(record.deleted));
    record_map.insert(
        "payload".to_string(),
        Json::String(b64url_encode(&record.payload)),
    );
    record_map.insert("stamp".to_string(), stamp_json(&record.stamp));
    record_map.insert(
        "witness".to_string(),
        serde_json::to_value(&witness).expect("dump serialization is infallible"),
    );
    record_map.insert("conflicts".to_string(), Json::Array(conflicts));
    serde_json::to_value(&record_map).expect("dump serialization is infallible")
}

fn stamp_json(stamp: &HlcStamp) -> Json {
    let mut stamp_map: BTreeMap<String, Json> = BTreeMap::new();
    stamp_map.insert("ct".to_string(), Json::from(stamp.ct));
    stamp_map.insert("id".to_string(), Json::String(stamp.id.clone()));
    stamp_map.insert("pt".to_string(), Json::from(stamp.pt));
    serde_json::to_value(&stamp_map).expect("stamp serialization is infallible")
}
