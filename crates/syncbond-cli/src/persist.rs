//! File-backed persistence for the demos: a [`SyncStorage`] snapshot file
//! and the relay demo's per-device state (relay pull cursor plus core
//! snapshot). Both reload across process restarts, which is what the relay
//! demo's resume step proves.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use syncbond_core::storage::{StorageError, SyncState, SyncStorage};

/// Stores the full [`SyncState`] snapshot as one JSON file (atomic replace).
pub struct FileStorage {
    path: PathBuf,
}

impl FileStorage {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl SyncStorage for FileStorage {
    fn save(&self, state: &[u8]) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| StorageError::Backend(error.to_string()))?;
        }
        let temp = self.path.with_extension("tmp");
        std::fs::write(&temp, state).map_err(|error| StorageError::Backend(error.to_string()))?;
        std::fs::rename(&temp, &self.path).map_err(|error| StorageError::Backend(error.to_string()))
    }

    fn load(&self) -> Result<Option<Vec<u8>>, StorageError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StorageError::Backend(error.to_string())),
        }
    }
}

/// What one relay-demo device persists across restarts: its core snapshot
/// (identity, oplog, cursor), its cursor into the shared relay log, and the
/// remote ops it applied from the relay. The core snapshot's oplog carries
/// only locally issued ops (received ops are merged into the record map but
/// not appended to the outbound log), so the demo replays `applied_remote`
/// after a reload to rebuild the received side of its state.
#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedDevice {
    pub pull_cursor: u64,
    #[serde(default)]
    pub applied_remote: Vec<syncbond_core::replication::Operation>,
    pub state: SyncState,
}

pub fn save_device(path: &Path, device: &PersistedDevice) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec_pretty(device)
        .map_err(|error| StorageError::Backend(error.to_string()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| StorageError::Backend(error.to_string()))?;
    }
    std::fs::write(path, bytes).map_err(|error| StorageError::Backend(error.to_string()))
}

pub fn load_device(path: &Path) -> Result<Option<PersistedDevice>, StorageError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| StorageError::Backend(error.to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StorageError::Backend(error.to_string())),
    }
}
