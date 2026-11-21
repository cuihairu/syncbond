//! Example-grade persistence and device assembly for the two-process demo.
//!
//! A device keeps three files in its data directory: `state.json` (the
//! whole sync snapshot via the [`SyncStorage`] trait — identity, oplog,
//! cursor, receive state), `outbox.json` (the pending envelopes via the
//! [`OutboxStore`] trait), and `group.json` (the replication group's key
//! facts, which the snapshot deliberately does not carry). These are the
//! simplest possible backends; a real deployment uses SQLite or a KVS
//! behind the same two traits.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use syncbond_core::conflict::LwwHlc;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::outbox::{OutboxBatch, OutboxError, OutboxStore};
use syncbond_core::receive::{commit_receive, load_receive, ReceiveState};
use syncbond_core::replication::Replicator;
use syncbond_core::storage::{StorageError, SyncStorage};
use syncbond_core::KeyRing;
use syncbond_relay_protocol::dto::Envelope;

/// The replication group's key facts. The snapshot carries `group_id` and
/// `key_epoch` but never the key, so the example keeps the key beside it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupFacts {
    pub group_id: String,
    pub key_epoch: u64,
    pub key: [u8; 32],
}

impl GroupFacts {
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        let path = data_dir.join("group.json");
        let bytes = std::fs::read(&path).map_err(|error| format!("group.json: {error}"))?;
        serde_json::from_slice(&bytes).map_err(|error| format!("group.json: {error}"))
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(data_dir).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        write_atomic(&data_dir.join("group.json"), &bytes).map_err(|error| error.to_string())
    }
}

/// `SyncStorage` over one file: the whole snapshot is replaced atomically
/// on save. Plaintext by design (the snapshot carries the identity secret);
/// a real deployment stores it protected or encrypted.
pub struct FileStorage {
    path: PathBuf,
}

impl FileStorage {
    pub fn new(data_dir: &Path) -> Self {
        std::fs::create_dir_all(data_dir).ok();
        Self {
            path: data_dir.join("state.json"),
        }
    }
}

impl SyncStorage for FileStorage {
    fn save(&self, state: &[u8]) -> Result<(), StorageError> {
        write_atomic(&self.path, state).map_err(|error| StorageError::Backend(error.to_string()))
    }

    fn load(&self) -> Result<Option<Vec<u8>>, StorageError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StorageError::Backend(error.to_string())),
        }
    }
}

/// `OutboxStore` over one file: unconfirmed batches, replaced atomically
/// on every mutation. [`OutboxBatch`] has no serde impl of its own, so the
/// file mirrors the two fields it carries.
#[derive(Default)]
pub struct FileOutboxStore {
    path: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredBatch {
    batch_id: String,
    envelopes: Vec<Envelope>,
}

impl FileOutboxStore {
    pub fn new(data_dir: &Path) -> Self {
        std::fs::create_dir_all(data_dir).ok();
        Self {
            path: data_dir.join("outbox.json"),
        }
    }

    fn load_batches(&self) -> Vec<OutboxBatch> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(_) => return Vec::new(),
        };
        let stored: Vec<StoredBatch> = match serde_json::from_slice(&bytes) {
            Ok(stored) => stored,
            Err(_) => return Vec::new(),
        };
        stored
            .into_iter()
            .map(|batch| OutboxBatch {
                batch_id: batch.batch_id,
                envelopes: batch.envelopes,
            })
            .collect()
    }

    fn save_batches(&self, batches: &[OutboxBatch]) -> Result<(), OutboxError> {
        let stored: Vec<StoredBatch> = batches
            .iter()
            .map(|batch| StoredBatch {
                batch_id: batch.batch_id.clone(),
                envelopes: batch.envelopes.clone(),
            })
            .collect();
        let bytes =
            serde_json::to_vec(&stored).map_err(|error| OutboxError::Storage(error.to_string()))?;
        write_atomic(&self.path, &bytes).map_err(|error| OutboxError::Storage(error.to_string()))
    }
}

impl OutboxStore for FileOutboxStore {
    fn insert(&self, batch: OutboxBatch) -> Result<(), OutboxError> {
        let mut batches = self.load_batches();
        batches.push(batch);
        self.save_batches(&batches)
    }

    fn pending(&self) -> Result<Vec<OutboxBatch>, OutboxError> {
        Ok(self.load_batches())
    }

    fn confirm(&self, message_ids: &[String]) -> Result<(), OutboxError> {
        let mut batches = self.load_batches();
        for batch in &mut batches {
            batch
                .envelopes
                .retain(|envelope| !message_ids.contains(&envelope.message_id));
        }
        batches.retain(|batch| !batch.envelopes.is_empty());
        self.save_batches(&batches)
    }
}

/// A bootstrapped device: replicator, receive cursor, group keyring, and
/// the long-term identity the snapshot carries.
pub struct Device {
    pub replicator: Replicator,
    pub receive: ReceiveState,
    pub keyring: KeyRing,
    pub identity: DeviceIdentity,
    pub facts: GroupFacts,
}

/// First run: write the identity into an empty snapshot and remember the
/// group facts. Called by the pairing subcommands, after the group key is
/// agreed over the session.
pub fn bootstrap(
    data_dir: &Path,
    identity: &DeviceIdentity,
    facts: &GroupFacts,
) -> Result<(), String> {
    facts.save(data_dir)?;
    let store = FileStorage::new(data_dir);
    let replicator = Replicator::new(identity.device_id.clone());
    let receive = ReceiveState::default();
    let state = replicator.snapshot_state(identity, &facts.group_id, facts.key_epoch);
    commit_receive(&store, &state, &receive)
        .map_err(|error| format!("bootstrap snapshot: {error}"))?;
    Ok(())
}

/// Load a bootstrapped device from its storage, replaying the snapshot.
pub fn load_device(data_dir: &Path, facts: &GroupFacts) -> Result<Device, String> {
    let store = FileStorage::new(data_dir);
    let (state, receive) = load_receive(&store)
        .map_err(|error| format!("state: {error}"))?
        .ok_or_else(|| "no state yet; pair first".to_string())?;
    let identity = state.identity.clone();
    let replicator = Replicator::from_state(&state, Arc::new(LwwHlc))
        .map_err(|error| format!("replay: {error}"))?;
    let keyring = KeyRing::with_epoch(&facts.group_id, facts.key_epoch, facts.key);
    Ok(Device {
        replicator,
        receive,
        keyring,
        identity,
        facts: facts.clone(),
    })
}

/// Persist the current snapshot (oplog, cursor, receive state) back to
/// storage. The sync driver commits its own pages; local writes persist
/// here.
pub fn persist(store: &FileStorage, device: &Device) -> Result<(), String> {
    let state = device.replicator.snapshot_state(
        &device.identity,
        &device.facts.group_id,
        device.facts.key_epoch,
    );
    commit_receive(store, &state, &device.receive).map_err(|error| format!("persist: {error}"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}
