//! Receive state and the atomic receive commit (todo.md DSR-30).
//!
//! A pulled page is opened (DSR-28), applied to the replicator, and then
//! committed as **one** snapshot that carries all four of these together:
//! the oplog, the replay/dedup knowledge, the HLC high-water, and the
//! receive cursor. `SyncStorage::save` replaces the stored blob in a
//! single call, so there is no window in which the cursor is ahead of
//! the data it names:
//!
//! - **A failed commit loses the page, not the data.** If the storage
//!   write fails, nothing was committed — oplog, dedup and cursor all
//!   stay at the previous snapshot, and a restart re-pulls the same page
//!   and re-applies it. Re-application is a no-op by construction
//!   (`apply_remote` dedups on `op_id`), so the retry is harmless and
//!   **nothing is skipped**.
//! - **Three sequence numbers, never mixed.** The server-assigned
//!   sequence (the pull position per server + channel), the source-local
//!   cursor (the numeric half of the replica's own `op_id`), and the
//!   replicator's local write cursor are stored as separate fields.
//!   Advancing one never advances another.
//! - **Dedup rides the same commit as the data it guards.** Message ids
//!   already opened are skipped before decryption (a redelivery, not an
//!   error), and the ids of a page are committed only with that page's
//!   operations.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use syncbond_relay_protocol::dto::{Envelope, PullEntry};

use crate::conflict::MergeError;
use crate::crypto::KeyRing;
use crate::replication::Replicator;
use crate::storage::{SyncState, SyncStorage};

/// Typed failures of receive application and its commit.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error("storage backend error: {0}")]
    Storage(String),
    /// The stored snapshot is present but unreadable. Fail closed — never
    /// truncate the backend, and never assume an empty receive state.
    #[error("persisted receive state is unreadable: {0}")]
    Decode(String),
    #[error("receive state is not serializable: {0}")]
    Encode(String),
    #[error(transparent)]
    Batch(#[from] crate::batch::BatchError),
    #[error("merge failed: {0}")]
    Merge(MergeError),
}

impl From<crate::storage::StorageError> for ReceiveError {
    fn from(error: crate::storage::StorageError) -> Self {
        ReceiveError::Storage(error.to_string())
    }
}

/// The pull position for one (server, channel): the server-assigned
/// sequence of the last committed entry. An empty channel reads 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCursor {
    pub server_id: String,
    pub channel_id: String,
    pub server_seq: u64,
}

/// Everything the receive side must persist, kept apart from `SyncState`
/// because it moves with a page rather than with a local write.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveState {
    /// Server-assigned sequence per `(server, channel)` — the pull
    /// position. Keyed by [`cursor_key`].
    pub server_cursors: BTreeMap<String, ServerCursor>,
    /// Highest numeric local cursor seen per replica node: the numeric
    /// half of that replica's `"<node>:<n>"` op ids. Stored numerically
    /// so `"a:9"` never looks newer than `"a:10"`.
    pub source_cursors: BTreeMap<String, u64>,
    /// Envelope message ids already opened and applied.
    pub seen_message_ids: BTreeSet<String>,
}

impl ReceiveState {
    pub fn cursor_for(&self, server_id: &str, channel_id: &str) -> Option<&ServerCursor> {
        self.server_cursors.get(&cursor_key(server_id, channel_id))
    }

    pub fn source_cursor_for(&self, node_id: &str) -> Option<u64> {
        self.source_cursors.get(node_id).copied()
    }
}

/// `cursor_key` is the only place a (server, channel) pair is folded into
/// one map key.
pub fn cursor_key(server_id: &str, channel_id: &str) -> String {
    format!("{server_id}/{channel_id}")
}

/// One relay page about to be applied.
pub struct ReceivedPage<'a> {
    pub server_id: &'a str,
    pub channel_id: &'a str,
    pub entries: &'a [PullEntry],
}

/// What a page did, for the caller to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyReport {
    /// Envelopes decrypted and applied (dedup-skipped ones excluded).
    pub applied: usize,
    /// Envelopes already known — redeliveries, applied as no-ops.
    pub duplicates: usize,
    /// The server sequence this page ends at; `None` for an empty page.
    pub server_seq: Option<u64>,
}

/// Open a page, apply it to the replicator, and move the in-memory
/// receive state with it. Nothing is durable here: durability is
/// [`commit_receive`], which must follow for the cursor to count.
///
/// A page that fails decryption or merge must not be committed; the
/// caller then restarts from the committed snapshot (the authoritative
/// one), and the page re-applies idempotently or fails again for the
/// same reason.
pub fn apply_page(
    replicator: &mut Replicator,
    receive: &mut ReceiveState,
    keyring: &KeyRing,
    page: &ReceivedPage,
) -> Result<ApplyReport, ReceiveError> {
    let mut fresh: Vec<Envelope> = Vec::new();
    let mut duplicates = 0usize;
    for entry in page.entries {
        if receive
            .seen_message_ids
            .contains(&entry.envelope.message_id)
        {
            duplicates += 1;
        } else {
            fresh.push(entry.envelope.clone());
        }
    }
    // The operations come back in the order of the entries that were
    // still fresh — duplicates were dropped, so the two lists are not
    // index-aligned and must never be zipped together.
    // `open_operations` takes its replay set as a hash set, while the
    // committed state keeps a deterministic tree set. Pre-filtering
    // against the committed ids is what keeps them consistent.
    let mut replay = std::collections::HashSet::new();
    let operations = if fresh.is_empty() {
        Vec::new()
    } else {
        crate::batch::open_operations(&fresh, keyring, &mut replay)?
    };
    receive.seen_message_ids.extend(replay);

    let mut applied = 0usize;
    for operation in &operations {
        absorb_source_cursor(&mut receive.source_cursors, &operation.op_id);
        if replicator
            .apply_remote(operation)
            .map_err(ReceiveError::Merge)?
        {
            applied += 1;
        }
    }

    // The cursor is the position of every entry handed over — applied
    // now, deduped earlier, or skipped as a duplicate alike: the server
    // will not re-send it, so the position is permanent.
    let server_seq = page.entries.iter().map(|entry| entry.seq).max();
    if let Some(server_seq) = server_seq {
        receive.server_cursors.insert(
            cursor_key(page.server_id, page.channel_id),
            ServerCursor {
                server_id: page.server_id.to_owned(),
                channel_id: page.channel_id.to_owned(),
                server_seq,
            },
        );
    }

    Ok(ApplyReport {
        applied,
        duplicates,
        server_seq,
    })
}

/// Commit `state` and `receive` as one blob. `state` is the caller's
/// `replicator.snapshot_state(...)`: oplog, HLC high-water and the local
/// write cursor in there, receive cursors and dedup ids in `receive`.
pub fn commit_receive<S: SyncStorage + ?Sized>(
    store: &S,
    state: &SyncState,
    receive: &ReceiveState,
) -> Result<(), ReceiveError> {
    let bytes = serde_json::to_vec(&ReceiveSnapshot {
        state: state.clone(),
        receive: receive.clone(),
    })
    .map_err(|error| ReceiveError::Encode(error.to_string()))?;
    store.save(&bytes)?;
    Ok(())
}

/// The last committed pair, or `None` when the backend holds nothing yet.
pub fn load_receive<S: SyncStorage>(
    store: &S,
) -> Result<Option<(SyncState, ReceiveState)>, ReceiveError> {
    match store.load()? {
        None => Ok(None),
        Some(bytes) => {
            let snapshot: ReceiveSnapshot = serde_json::from_slice(&bytes)
                .map_err(|error| ReceiveError::Decode(error.to_string()))?;
            Ok(Some((snapshot.state, snapshot.receive)))
        }
    }
}

/// The highest numeric source cursor for one replica's op ids.
fn absorb_source_cursor(cursors: &mut BTreeMap<String, u64>, op_id: &str) {
    if let Some((node_id, suffix)) = op_id.split_once(':') {
        if let Ok(cursor) = suffix.parse::<u64>() {
            let entry = cursors.entry(node_id.to_owned()).or_insert(0);
            *entry = (*entry).max(cursor);
        }
    }
}

/// One blob, atomically replaced by `save`: local state and receive
/// state cross the same write.
#[derive(Serialize, Deserialize)]
struct ReceiveSnapshot {
    state: SyncState,
    receive: ReceiveState,
}
