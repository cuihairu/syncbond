//! Minimal durable relay protocol.

use crate::replication::Operation;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PullRequest {
    pub channel: String,
    pub after: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum RelayError {
    #[error("relay serialization: {0}")]
    Encoding(String),
}

pub trait RelayStore: Send + Sync {
    fn append(&self, channel: &str, operation: &Operation) -> Result<(), RelayError>;
    fn pull_after(&self, channel: &str, after: u64) -> Result<PullResponse, RelayError>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PullResponse {
    pub after: u64,
    pub ops: Vec<Operation>,
    pub has_more: bool,
}

pub fn apply_pull_response(
    replicator: &mut crate::replication::Replicator,
    response: &PullResponse,
) -> Result<usize, RelayError> {
    Ok(response
        .ops
        .iter()
        .filter(|operation| replicator.apply_remote(operation))
        .count())
}

#[derive(Default)]
pub struct MemoryRelayStore {
    logs: Mutex<HashMap<String, Vec<Operation>>>,
}

impl MemoryRelayStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn read_log<F, T>(&self, channel: &str, action: F) -> Result<T, RelayError>
    where
        F: FnOnce(&[Operation]) -> Result<T, RelayError>,
    {
        let logs = self.lock()?;
        action(logs.get(channel).map(Vec::as_slice).unwrap_or(&[]))
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, Vec<Operation>>>, RelayError> {
        self.logs
            .lock()
            .map_err(|_| RelayError::Encoding("relay lock poisoned".to_string()))
    }
}

impl RelayStore for MemoryRelayStore {
    fn append(&self, channel: &str, operation: &Operation) -> Result<(), RelayError> {
        let mut logs = self.lock()?;
        let log = logs.entry(channel.to_string()).or_default();
        append_deduplicated(log, operation.clone());
        Ok(())
    }

    fn pull_after(&self, channel: &str, after: u64) -> Result<PullResponse, RelayError> {
        self.read_log(channel, |log| Ok(page_after(log, after)))
    }
}

/// Append-only relay log persisted as one JSON snapshot per save. This is the
/// smallest durable server implementation; production servers can replace it
/// behind the same `RelayStore` interface with an append-only WAL or database.
pub struct FileRelayStore {
    path: PathBuf,
    state: Mutex<RelayLogState>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RelayLogState {
    channels: BTreeMap<String, Vec<Operation>>,
}

impl FileRelayStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RelayError> {
        let path = path.into();
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| RelayError::Encoding(error.to_string()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => RelayLogState::default(),
            Err(error) => return Err(RelayError::Encoding(error.to_string())),
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RelayLogState>, RelayError> {
        self.state
            .lock()
            .map_err(|_| RelayError::Encoding("relay lock poisoned".to_string()))
    }

    fn persist(&self, state: &RelayLogState) -> Result<(), RelayError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| RelayError::Encoding(error.to_string()))?;
        }
        let temp_path = self.path.with_extension("tmp");
        let bytes =
            serde_json::to_vec(state).map_err(|error| RelayError::Encoding(error.to_string()))?;
        std::fs::write(&temp_path, bytes)
            .map_err(|error| RelayError::Encoding(error.to_string()))?;
        std::fs::rename(&temp_path, &self.path)
            .map_err(|error| RelayError::Encoding(error.to_string()))
    }
}

impl RelayStore for FileRelayStore {
    fn append(&self, channel: &str, operation: &Operation) -> Result<(), RelayError> {
        let mut state = self.lock()?;
        let log = state.channels.entry(channel.to_string()).or_default();
        append_deduplicated(log, operation.clone());
        self.persist(&state)
    }

    fn pull_after(&self, channel: &str, after: u64) -> Result<PullResponse, RelayError> {
        let state = self.lock()?;
        let log = state
            .channels
            .get(channel)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        Ok(page_after(log, after))
    }
}

fn append_deduplicated(log: &mut Vec<Operation>, operation: Operation) {
    if log.iter().any(|existing| existing.op_id == operation.op_id) {
        return;
    }
    log.push(operation);
}

fn page_after(log: &[Operation], after: u64) -> PullResponse {
    if after >= log.len() as u64 {
        return PullResponse {
            after: log.len() as u64,
            ops: Vec::new(),
            has_more: false,
        };
    }
    PullResponse {
        after: log.len() as u64,
        ops: log[after as usize..].to_vec(),
        has_more: false,
    }
}
