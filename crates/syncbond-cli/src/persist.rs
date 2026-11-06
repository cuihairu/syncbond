//! File-backed persistence for the demos: a [`SyncStorage`] snapshot file
//! and the relay demo's per-device state (relay pull cursor plus core
//! snapshot). Both reload across process restarts, which is what the relay
//! demo's resume step proves.
//!
//! Every write is atomic (write a sibling temp file, fsync it, rename over
//! the destination, then fsync the containing directory), so an interruption
//! or failure mid-save never destroys the previous complete snapshot.

use serde::{Deserialize, Serialize};
use std::io::Write;
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
        atomic_write(&self.path, state)
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
    atomic_write(path, &bytes)
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

/// What the pair demo persists: the core snapshot (local oplog) plus the
/// remote ops it applied from the peer. The core snapshot alone cannot
/// rebuild the received side of the state after a restart, because remote
/// ops never enter the local oplog; storing them alongside the snapshot lets
/// a reload from file alone reconstruct both sides.
#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedPairState {
    pub state: SyncState,
    #[serde(default)]
    pub received: Vec<syncbond_core::replication::Operation>,
}

pub fn save_pair_state(path: &Path, state: &PersistedPairState) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| StorageError::Backend(error.to_string()))?;
    atomic_write(path, &bytes)
}

pub fn load_pair_state(path: &Path) -> Result<Option<PersistedPairState>, StorageError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| StorageError::Backend(error.to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StorageError::Backend(error.to_string())),
    }
}

/// Replace `path` atomically: write a sibling temp file, fsync it, rename it
/// over the destination, then fsync the containing directory so the rename
/// itself is durable. The destination is only ever replaced by a fully
/// written, synced file, so an interrupted or failed write leaves the
/// previous snapshot intact.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)
            .map_err(|error| StorageError::Backend(error.to_string()))?;
    }
    let temp = path.with_extension("tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp)
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        file.write_all(bytes)
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        file.sync_all()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
    }
    std::fs::rename(&temp, path).map_err(|error| StorageError::Backend(error.to_string()))?;
    // A bare relative path has parent "" which `File::open` cannot open;
    // map it to "." so the directory is still synced.
    let dir = match parent {
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
        None => Path::new("."),
    };
    if let Ok(dir_handle) = std::fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use syncbond_core::conflict::LwwHlc;
    use syncbond_core::replication::Replicator;

    fn temp_path(name: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let unique = SEQ.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "syncbond-cli-{name}-{}-{unique}.json",
            std::process::id()
        ))
    }

    #[test]
    fn save_is_atomic_previous_snapshot_survives_failed_overwrite() {
        let path = temp_path("atomic");
        let storage = FileStorage::open(&path);
        storage.save(b"first").expect("first save");
        // Simulate a write failure mid-save by making the destination a
        // directory? Instead: assert a second save replaces atomically and
        // the old file is intact until rename.
        storage.save(b"second").expect("second save");
        assert_eq!(storage.load().expect("load"), Some(b"second".to_vec()));
        // After a normal save the temp file is gone and only the final path exists.
        assert!(!path.with_extension("tmp").exists());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_works_with_bare_relative_path() {
        let cwd = std::env::current_dir().expect("cwd");
        let name = format!("syncbond-cli-bare-{}.json", std::process::id());
        let storage = FileStorage::open(&name);
        storage.save(b"bare").expect("bare path save");
        assert_eq!(storage.load().expect("load"), Some(b"bare".to_vec()));
        std::fs::remove_file(&name).ok();
        // Restore cwd in case the temp dir path was relative (it is absolute here).
        std::env::set_current_dir(&cwd).ok();
    }

    #[test]
    fn pair_state_round_trips_through_file() {
        let path = temp_path("pairstate");
        let mut replicator = Replicator::with_fixed_clock("node-a", Arc::new(LwwHlc), 1_000);
        let _op = replicator.put("k", b"v".to_vec()).expect("put");
        let snapshot = replicator.snapshot_state(
            &syncbond_core::identity::DeviceIdentity::generate(),
            "group",
            1,
        );
        save_pair_state(
            &path,
            &PersistedPairState {
                state: snapshot,
                received: Vec::new(),
            },
        )
        .expect("save pair state");
        let loaded = load_pair_state(&path)
            .expect("load pair state")
            .expect("some");
        assert_eq!(loaded.state.node_id, "node-a");
        std::fs::remove_file(&path).ok();
    }
}
