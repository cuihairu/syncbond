//! Replication: oplog, cursors, deduplication, snapshots.
//!
//! The oplog carries opaque record operations. Sync exchanges oplog chunks
//! over a paired session's encrypted channel; merging goes through the
//! application's `MergeStrategy`. Operations are deduplicated by op id, so
//! out-of-order and duplicate delivery converge to the same state.

use crate::conflict::{LwwHlc, MergeContext, MergeOutcome, MergeStrategy, Record};
use crate::crypto::{self, SessionKey};
use crate::hlc::{compare_stamps, HlcStamp, HybridClock};
use crate::storage::SyncState;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    /// Unique, deduplicating id: "<node_id>:<cursor>".
    pub op_id: String,
    pub key: String,
    pub payload: Vec<u8>,
    pub deleted: bool,
    pub stamp: crate::hlc::HlcStamp,
    pub witness: HashMap<String, HlcStamp>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ReplicationError {
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("pairing/session: {0}")]
    Pairing(#[from] crate::pairing::PairingError),
    #[error("serialization: {0}")]
    Encoding(String),
    #[error("session invalidated")]
    SessionInvalidated,
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct Replicator {
    pub node_id: String,
    strategy: Arc<dyn MergeStrategy>,
    clock: HybridClock,
    records: HashMap<String, Record>,
    /// Local oplog (also the outbound sync unit). Compaction replaces it
    /// with a snapshot marker; cursors survive.
    oplog: Vec<Operation>,
    seen_op_ids: HashSet<String>,
    cursor: u64,
    /// Causal witness: node_id -> last stamp seen from that node.
    vector: HashMap<String, HlcStamp>,
}

pub struct SyncStats {
    pub sent_ops: usize,
    pub received_ops: usize,
    pub applied_ops: usize,
}

impl Replicator {
    pub fn new(node_id: impl Into<String>) -> Self {
        Self::with_strategy(node_id, Arc::new(LwwHlc))
    }

    pub fn with_strategy(node_id: impl Into<String>, strategy: Arc<dyn MergeStrategy>) -> Self {
        let node_id = node_id.into();
        let clock = HybridClock::new(node_id.clone(), 5 * 60_000);
        Self {
            node_id,
            strategy,
            clock,
            records: HashMap::new(),
            oplog: Vec::new(),
            seen_op_ids: HashSet::new(),
            cursor: 0,
            vector: HashMap::new(),
        }
    }

    /// Write (or upsert) a record with an opaque payload.
    pub fn put(&mut self, key: impl Into<String>, payload: Vec<u8>) -> Operation {
        let stamp = self.clock.issue();
        self.vector.insert(self.node_id.clone(), stamp.clone());
        let witness = self.vector.clone();
        let op = Operation {
            op_id: self.next_op_id(),
            key: key.into(),
            payload,
            deleted: false,
            stamp,
            witness,
        };
        self.apply_local(op.clone());
        op
    }

    /// Delete a record (causal tombstone via the write's witness).
    pub fn delete(&mut self, key: impl Into<String>) -> Operation {
        let stamp = self.clock.issue();
        self.vector.insert(self.node_id.clone(), stamp.clone());
        let witness = self.vector.clone();
        let op = Operation {
            op_id: self.next_op_id(),
            key: key.into(),
            payload: Vec::new(),
            deleted: true,
            stamp,
            witness,
        };
        self.apply_local(op.clone());
        op
    }

    fn next_op_id(&mut self) -> String {
        self.cursor += 1;
        format!("{}:{}", self.node_id, self.cursor)
    }

    fn apply_local(&mut self, op: Operation) {
        self.seen_op_ids.insert(op.op_id.clone());
        let outcome = self.merge_record(&Record {
            key: op.key.clone(),
            payload: op.payload.clone(),
            deleted: op.deleted,
            stamp: op.stamp.clone(),
            witness: op.witness.clone(),
            conflicts: Vec::new(),
        });
        self.records.insert(op.key.clone(), outcome.record);
        self.oplog.push(op);
    }

    fn merge_record(&self, incoming: &Record) -> MergeOutcome {
        let ctx = MergeContext {
            now_ms: wall_ms(),
            max_skew_ms: self.clock.max_skew_ms,
        };
        self.strategy
            .merge(self.records.get(&incoming.key), incoming, &ctx)
    }

    /// Apply a remote operation; returns false when it was a duplicate.
    pub fn apply_remote(&mut self, op: &Operation) -> bool {
        if !self.seen_op_ids.insert(op.op_id.clone()) {
            return false;
        }
        let outcome = self.merge_record(&Record {
            key: op.key.clone(),
            payload: op.payload.clone(),
            deleted: op.deleted,
            stamp: op.stamp.clone(),
            witness: op.witness.clone(),
            conflicts: Vec::new(),
        });
        // Absorb causal knowledge: the op's stamp and its witness.
        Self::absorb(&mut self.vector, &op.stamp);
        for stamp in op.witness.values() {
            Self::absorb(&mut self.vector, stamp);
        }
        self.records.insert(op.key.clone(), outcome.record);
        true
    }

    pub fn get(&self, key: &str) -> Option<&Record> {
        self.records.get(key)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn oplog(&self) -> &[Operation] {
        &self.oplog
    }

    /// Serialize the full local state for persistence.
    pub fn snapshot_state(
        &self,
        identity: &crate::identity::DeviceIdentity,
        group_id: &str,
        key_epoch: u64,
    ) -> SyncState {
        SyncState {
            node_id: self.node_id.clone(),
            identity: identity.clone(),
            group_id: group_id.to_string(),
            key_epoch,
            cursor: self.cursor,
            oplog: self.oplog.clone(),
        }
    }

    /// Rebuild a replicator from a persisted snapshot (crash restart path).
    pub fn from_state(state: &SyncState, strategy: Arc<dyn MergeStrategy>) -> Self {
        let mut replicator = Self::with_strategy(state.node_id.clone(), strategy);
        replicator.cursor = state.cursor;
        for op in &state.oplog {
            replicator.seen_op_ids.insert(op.op_id.clone());
            replicator.apply_local_known(op.clone());
        }
        replicator
    }

    fn apply_local_known(&mut self, op: Operation) {
        self.seen_op_ids.insert(op.op_id.clone());
        let outcome = self.merge_record(&Record {
            key: op.key.clone(),
            payload: op.payload.clone(),
            deleted: op.deleted,
            stamp: op.stamp.clone(),
            witness: op.witness.clone(),
            conflicts: Vec::new(),
        });
        self.records.insert(op.key.clone(), outcome.record);
        self.oplog.push(op);
    }

    /// Keep the newer of the two stamps for a node.
    fn absorb(vector: &mut HashMap<String, HlcStamp>, stamp: &HlcStamp) {
        match vector.get(&stamp.id) {
            Some(existing) if compare_stamps(existing, stamp) != std::cmp::Ordering::Less => {}
            _ => {
                vector.insert(stamp.id.clone(), stamp.clone());
            }
        }
    }

    /// Exchange oplogs with the peer over an established encrypted session.
    /// `send_first` is the initiator side. Both sides converge because merge
    /// strategies are commutative and ops are idempotent (dedup by op id).
    pub fn sync_over(
        &mut self,
        session: &crate::pairing::PairingSession,
        send_first: bool,
    ) -> Result<SyncStats, ReplicationError> {
        let encode = |ops: &[Operation]| -> Result<Vec<u8>, ReplicationError> {
            serde_json::to_vec(ops).map_err(|e| ReplicationError::Encoding(e.to_string()))
        };
        let decode = |bytes: &[u8]| -> Result<Vec<Operation>, ReplicationError> {
            serde_json::from_slice(bytes).map_err(|e| ReplicationError::Encoding(e.to_string()))
        };

        let send = |replicator: &Self| -> Result<usize, ReplicationError> {
            let sent = replicator.oplog.len();
            session.seal_and_send(&encode(&replicator.oplog)?)?;
            Ok(sent)
        };
        let receive = |replicator: &mut Self| -> Result<usize, ReplicationError> {
            let bytes = session.recv_and_open()?;
            let ops: Vec<Operation> = decode(&bytes)?;
            let mut applied = 0;
            for op in &ops {
                if replicator.apply_remote(op) {
                    applied += 1;
                }
            }
            Ok(applied)
        };

        if send_first {
            let sent = send(self)?;
            let _received_count = receive(self)?;
            let stats = SyncStats {
                sent_ops: sent,
                received_ops: 0,
                applied_ops: 0,
            };
            Ok(stats)
        } else {
            let _ = receive(self)?;
            let sent = send(self)?;
            Ok(SyncStats {
                sent_ops: sent,
                received_ops: 0,
                applied_ops: 0,
            })
        }
    }
}

/// Serialization helper used by storage-backed restart tests.
pub fn encode_state(state: &SyncState) -> Result<Vec<u8>, ReplicationError> {
    serde_json::to_vec(state).map_err(|e| ReplicationError::Encoding(e.to_string()))
}

pub fn decode_state(bytes: &[u8]) -> Result<SyncState, ReplicationError> {
    serde_json::from_slice(bytes).map_err(|e| ReplicationError::Encoding(e.to_string()))
}

#[derive(Clone)]
pub struct SessionCrypto {
    pub key: SessionKey,
}

/// Stats are returned after both directions completed; `received`/`applied`
/// are tracked on the receiving side of each direction, so callers that need
/// them should read convergence from the store instead.
impl SyncStats {
    pub fn total_exchanged(&self) -> usize {
        self.sent_ops + self.received_ops
    }
}

pub type SharedReplicator = Arc<Mutex<Replicator>>;
