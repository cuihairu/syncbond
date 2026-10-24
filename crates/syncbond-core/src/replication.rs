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
use std::collections::{BTreeMap, HashMap, HashSet};
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

/// Summary of one `gc_tombstones` pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcReport {
    /// Tombstoned records inspected.
    pub scanned: usize,
    /// Keys collected into compact barriers (sorted).
    pub collected: Vec<String>,
    /// Oplog entries dropped when collapsing each collected key's history
    /// down to its single tombstone op.
    pub oplog_entries_removed: usize,
}

/// How aggressively tombstones may be collected. The public API only offers
/// the dominance-checked mode.
///
/// The time-only mode is an internal/test switch: it waives the evidence
/// requirement, so a collected key can be re-materialized from a peer that
/// still carries the pre-delete history. It is never reachable from the
/// public API or the FFI surface and is deliberately undocumented outside
/// this crate (docs/design/merge.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GcMode {
    Dominance,
    #[allow(dead_code)]
    TimeOnly,
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

fn incoming_record(op: &Operation) -> Record {
    Record {
        key: op.key.clone(),
        payload: op.payload.clone(),
        deleted: op.deleted,
        stamp: op.stamp.clone(),
        witness: op.witness.clone(),
        conflicts: Vec::new(),
    }
}

/// Tombstone with payload and retained conflicts stripped: the compact form
/// that keeps the causal barrier while dropping dead data.
fn compact_tombstone(record: &Record) -> Record {
    Record {
        key: record.key.clone(),
        payload: Vec::new(),
        deleted: true,
        stamp: record.stamp.clone(),
        witness: record.witness.clone(),
        conflicts: Vec::new(),
    }
}

pub struct Replicator {
    pub node_id: String,
    strategy: Arc<dyn MergeStrategy>,
    clock: HybridClock,
    /// Wall-clock source for merge skew checks and GC thresholds; injectable
    /// so fixture-driven tests are deterministic.
    now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
    records: HashMap<String, Record>,
    /// Compacted tombstones (payload and conflicts stripped) that passed GC.
    /// They keep the causal barrier that stops pre-delete writes from
    /// resurrecting a collected delete.
    gc_barriers: BTreeMap<String, Record>,
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
        Self::with_parts(node_id, strategy, clock, Box::new(wall_ms))
    }

    /// Deterministic clock: every stamp and merge check uses `fixed_ms`.
    pub fn with_fixed_clock(node_id: impl Into<String>, fixed_ms: u64) -> Self {
        let node_id = node_id.into();
        let clock =
            HybridClock::with_clock(node_id.clone(), 5 * 60_000, Box::new(move || fixed_ms));
        Self::with_parts(node_id, Arc::new(LwwHlc), clock, Box::new(move || fixed_ms))
    }

    fn with_parts(
        node_id: impl Into<String>,
        strategy: Arc<dyn MergeStrategy>,
        clock: HybridClock,
        now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        let node_id = node_id.into();
        Self {
            node_id,
            strategy,
            clock,
            now_ms,
            records: HashMap::new(),
            gc_barriers: BTreeMap::new(),
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
        // A local write supersedes any compacted delete for the key: it is
        // the same "recreate after delete" the merge would allow pre-GC.
        self.gc_barriers.remove(&op.key);
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
        self.merge_against(self.records.get(&incoming.key), incoming)
    }

    fn merge_against(&self, local: Option<&Record>, incoming: &Record) -> MergeOutcome {
        let ctx = MergeContext {
            now_ms: (self.now_ms)(),
            max_skew_ms: self.clock.max_skew_ms,
        };
        self.strategy.merge(local, incoming, &ctx)
    }

    /// Apply a remote operation; returns false when it was a duplicate or
    /// when it was rejected because it would resurrect a garbage-collected
    /// delete (docs/design/merge.md).
    pub fn apply_remote(&mut self, op: &Operation) -> bool {
        if self.seen_op_ids.contains(&op.op_id) {
            return false;
        }
        self.ingest(op)
    }

    fn ingest(&mut self, op: &Operation) -> bool {
        let incoming = incoming_record(op);
        let had_barrier = self.gc_barriers.contains_key(&op.key);
        let outcome = match self.gc_barriers.get(&op.key) {
            Some(barrier) => self.merge_against(Some(barrier), &incoming),
            None => self.merge_record(&incoming),
        };
        if had_barrier && !op.deleted && outcome.record.deleted {
            // A live write that loses to a collected tombstone is exactly
            // the resurrection GC must prevent: reject it outright.
            return false;
        }
        self.seen_op_ids.insert(op.op_id.clone());
        // Absorb causal knowledge: the op's stamp and its witness.
        Self::absorb(&mut self.vector, &op.stamp);
        for stamp in op.witness.values() {
            Self::absorb(&mut self.vector, stamp);
        }
        if had_barrier {
            if outcome.record.deleted {
                // A newer tombstone arrived over a collected key: keep the
                // compacted representation and refresh the barrier.
                self.gc_barriers
                    .insert(op.key.clone(), compact_tombstone(&outcome.record));
                self.oplog.push(op.clone());
                return true;
            }
            // A live write won against the barrier; the record is live again.
            self.gc_barriers.remove(&op.key);
        }
        self.records.insert(op.key.clone(), outcome.record);
        true
    }

    /// Garbage-collect tombstones that are both old enough and causally
    /// dominated by every known replica.
    ///
    /// A collected tombstone is not deleted: it is compacted into a
    /// `gc_barriers` entry (payload and conflicts stripped) that keeps the
    /// causal barrier, so a pre-delete write redelivered later is rejected
    /// instead of resurrecting the delete. The key's oplog history is
    /// collapsed to its single tombstone op, so a fresh replica still learns
    /// about the delete and the barrier keeps costing O(1) per deleted key.
    ///
    /// The dominance check reads the replica vector built from op witnesses
    /// (the heartbeat that arrives with relay sync): a replica whose evidence
    /// is missing simply blocks collection until it is heard from again.
    pub fn gc_tombstones(&mut self, now_ms: u64, older_than_ms: u64) -> GcReport {
        self.gc_tombstones_with_mode(now_ms, older_than_ms, GcMode::Dominance)
    }

    fn gc_tombstones_with_mode(
        &mut self,
        now_ms: u64,
        older_than_ms: u64,
        mode: GcMode,
    ) -> GcReport {
        let mut report = GcReport {
            scanned: 0,
            collected: Vec::new(),
            oplog_entries_removed: 0,
        };
        let tombstoned: Vec<String> = self
            .records
            .iter()
            .filter(|(_, record)| record.deleted)
            .map(|(key, _)| key.clone())
            .collect();
        for key in tombstoned {
            report.scanned += 1;
            let Some(record) = self.records.get(&key) else {
                continue;
            };
            if now_ms.saturating_sub(record.stamp.pt) < older_than_ms {
                continue;
            }
            if !matches!(mode, GcMode::TimeOnly) && !self.vector_dominates(&record.stamp) {
                continue;
            }
            let tombstone_op = self
                .oplog
                .iter()
                .rev()
                .find(|op| op.key == key && op.deleted)
                .cloned();
            let kept = self.oplog.len();
            self.oplog.retain(|op| op.key != key);
            report.oplog_entries_removed += kept - self.oplog.len();
            if let Some(op) = tombstone_op {
                self.oplog.push(op);
            }
            self.gc_barriers
                .insert(key.clone(), compact_tombstone(record));
            self.records.remove(&key);
            report.collected.push(key);
        }
        report.collected.sort();
        report
    }

    /// Every node we have evidence about has been at or past `stamp`.
    fn vector_dominates(&self, stamp: &HlcStamp) -> bool {
        self.vector
            .values()
            .all(|seen| compare_stamps(seen, stamp) != std::cmp::Ordering::Less)
    }

    pub fn get(&self, key: &str) -> Option<&Record> {
        self.records.get(key)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Keys of live (non-tombstoned) records, sorted.
    pub fn live_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .records
            .iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(key, _)| key.clone())
            .collect();
        keys.sort();
        keys
    }

    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn oplog(&self) -> &[Operation] {
        &self.oplog
    }

    /// All records (live and tombstoned) sorted by key; used for
    /// deterministic state dumps.
    pub fn records_snapshot(&self) -> Vec<(String, Record)> {
        let mut pairs: Vec<(String, Record)> = self
            .records
            .iter()
            .map(|(key, record)| (key.clone(), record.clone()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    }

    /// Compacted tombstones kept as causal barriers, sorted by key.
    pub fn gc_barriers(&self) -> &BTreeMap<String, Record> {
        &self.gc_barriers
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
            gc_barriers: self.gc_barriers.clone(),
        }
    }

    /// Rebuild a replicator from a persisted snapshot (crash restart path).
    pub fn from_state(state: &SyncState, strategy: Arc<dyn MergeStrategy>) -> Self {
        let mut replicator = Self::with_strategy(state.node_id.clone(), strategy);
        replicator.cursor = state.cursor;
        replicator.gc_barriers = state.gc_barriers.clone();
        // The persisted oplog is authoritative; replay rebuilds records and
        // the witness vector without appending entries again.
        replicator.oplog = state.oplog.clone();
        for op in &state.oplog {
            replicator.seen_op_ids.insert(op.op_id.clone());
            replicator.apply_known(op);
        }
        replicator
    }

    /// Replay a persisted oplog entry without appending it again.
    fn apply_known(&mut self, op: &Operation) {
        let incoming = incoming_record(op);
        let had_barrier = self.gc_barriers.contains_key(&op.key);
        let outcome = match self.gc_barriers.get(&op.key) {
            Some(barrier) => self.merge_against(Some(barrier), &incoming),
            None => self.merge_record(&incoming),
        };
        Self::absorb(&mut self.vector, &op.stamp);
        for stamp in op.witness.values() {
            Self::absorb(&mut self.vector, stamp);
        }
        if had_barrier {
            if outcome.record.deleted {
                self.gc_barriers
                    .insert(op.key.clone(), compact_tombstone(&outcome.record));
                return;
            }
            self.gc_barriers.remove(&op.key);
        }
        self.records.insert(op.key.clone(), outcome.record);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str) -> Replicator {
        Replicator::with_fixed_clock(id, 1_000)
    }

    /// Build the situation where the collector has no evidence that every
    /// known replica has seen the delete.
    fn tombstoned_without_evidence() -> (Replicator, Replicator, Operation) {
        let mut a = node("node-a");
        let mut b = node("node-b");
        a.put("k", b"value".to_vec());
        let stale = b.put("k", b"offline".to_vec()); // concurrent, b never saw `created`
        a.apply_remote(&stale);
        a.delete("k");
        (a, b, stale)
    }

    #[test]
    fn degraded_time_only_mode_skips_the_evidence_check() {
        // Internal switch only: the public gc_tombstones() refuses this case.
        let (mut a, _b, stale) = tombstoned_without_evidence();

        let gated = a.gc_tombstones_with_mode(1_000, 0, GcMode::Dominance);
        assert_eq!(gated.scanned, 1);
        assert!(gated.collected.is_empty(), "b has not seen the delete");

        let degraded = a.gc_tombstones_with_mode(1_000, 0, GcMode::TimeOnly);
        assert_eq!(degraded.collected, vec!["k".to_string()]);
        assert!(a.get("k").is_none());
        assert!(
            a.gc_barriers.contains_key("k"),
            "the barrier always survives"
        );

        // Even the unsafe mode keeps the causal barrier.
        assert!(!a.apply_remote(&stale));
        assert!(a.get("k").is_none());
    }
}
