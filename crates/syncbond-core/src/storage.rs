//! Swappable persistence. The SDK keeps its full state as one serializable
//! snapshot; applications store it however they like (file, SQLite, KVS).
//! Crash-restart consistency is a release-blocking test: identity, cursor
//! and oplog must all survive a reload from `SyncStorage`.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Storage backend interface. `save` replaces the stored snapshot.
pub trait SyncStorage: Send + Sync {
    fn save(&self, state: &[u8]) -> Result<(), StorageError>;
    fn load(&self) -> Result<Option<Vec<u8>>, StorageError>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum StorageError {
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// In-memory backend for tests and examples (state survives process restart
/// only within the same process, which is exactly what the recovery test needs).
#[derive(Default)]
pub struct MemoryStorage {
    slot: Mutex<Option<Vec<u8>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SyncStorage for MemoryStorage {
    fn save(&self, state: &[u8]) -> Result<(), StorageError> {
        *self.slot.lock().unwrap() = Some(state.to_vec());
        Ok(())
    }

    fn load(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.slot.lock().unwrap().clone())
    }
}

/// Everything a device must persist: its long-term identity, replication
/// cursor, oplog, group membership, key epoch, and compaction barriers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub node_id: String,
    pub identity: crate::identity::DeviceIdentity,
    pub group_id: String,
    pub key_epoch: u64,
    pub cursor: u64,
    pub oplog: Vec<crate::replication::Operation>,
    /// Compacted tombstones that must outlive the oplog (default empty for
    /// snapshots taken before GC existed).
    #[serde(default)]
    pub gc_barriers: std::collections::BTreeMap<String, crate::conflict::Record>,
}
