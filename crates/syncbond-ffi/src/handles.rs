//! Handle-based inner API.
//!
//! This is the single semantic surface the C ABI, the Python bindings and
//! the Node bindings all consume. It performs serialization and resource
//! management only: protocol logic stays in syncbond-core.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use syncbond_core::conflict::{LwwHlc, MergeStrategy, OrSetStrategy, PnCounterStrategy, Record};
use syncbond_core::crypto::{
    b64url_decode, b64url_encode, seal, EncryptedEnvelope, KeyRing, SessionKey,
};
use syncbond_core::hlc::HlcStamp;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::{accept, pair, PairingSession};
use syncbond_core::replication::{Operation, Replicator as CoreReplicator, SyncStats};
use syncbond_core::transport::{MemoryTransport, Transport};

use crate::error::{FfiError, SB_STRATEGY_LWW_HLC, SB_STRATEGY_OR_SET, SB_STRATEGY_PN_COUNTER};

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
        self.0.put(key, payload.to_vec());
        Ok(())
    }

    pub fn delete(&mut self, key: &str) -> Result<(), FfiError> {
        if key.is_empty() {
            return Err(FfiError::input("key must not be empty"));
        }
        self.0.delete(key);
        Ok(())
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
        Ok(self.0.apply_remote(&op))
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
