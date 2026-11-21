//! Persistent outbox and ACK confirmation (todo.md DSR-29): operations
//! cross the relay only after they are durably recorded, and only the
//! relay's own acknowledgements remove them. Three rules, pinned here
//! because the acceptance depends on each one holding under a crash
//! between any two steps:
//!
//! - **Staged before sent.** [`stage_operations`] seals (DSR-28) and
//!   records the sealed wire envelopes in the [`OutboxStore`] before any
//!   send attempt. A crash after staging, before sending, leaves the
//!   batches recoverable via `pending()`.
//! - **Resend is byte-stable.** The envelopes are sealed exactly once, at
//!   staging time. A retry resends the same wire bytes — the same message
//!   ids — so the relay's `(channel, messageId)` idempotency (DSR-13)
//!   answers with the original seqs and appends nothing twice. Re-sealing
//!   would mint fresh ids and defeat the dedup; it cannot happen, because
//!   the outbox stores sealed envelopes, not operations.
//! - **Removed only after the relay committed.** The sender closure
//!   returns acks only when the server answered a committed append (the
//!   server, in turn, constructs acks only after its transaction
//!   commits). [`drain`] confirms strictly what was acked — nothing is
//!   deleted on a lost response, so unacknowledged data always remains
//!   pending.
//!
//! The store trait is the durability seam: hosts back it with SQLite (or
//! any store that outlives the process); [`MemoryOutboxStore`] exists for
//! tests and as the reference semantics. The network seam is the sender
//! closure of [`drain`] — the real HTTP driver plugs in there.

use std::collections::BTreeMap;
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use syncbond_relay_protocol::dto::{Envelope, EnvelopeAck};

use crate::crypto::KeyRing;
use crate::replication::Operation;

/// One sealed batch awaiting acknowledgement. `batch_id` is outbox-local
/// (for logs and store keys); the relay knows nothing about it —
/// envelopes are confirmed by their `message_id`s, which ride in the
/// server's acks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxBatch {
    pub batch_id: String,
    pub envelopes: Vec<Envelope>,
}

/// Outbox storage failures. The memory store cannot fail; the variants
/// exist for durable backends (full disk, locked database, …).
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum OutboxError {
    #[error("outbox storage: {0}")]
    Storage(String),
    #[error("outbox already holds batch {0}")]
    DuplicateBatch(String),
}

/// The durability contract of the outbox. Implementations must make
/// `insert` observable to a later `pending()` — that is the whole of
/// "recoverable before send".
pub trait OutboxStore: Send + Sync {
    fn insert(&self, batch: OutboxBatch) -> Result<(), OutboxError>;
    /// Unconfirmed batches, oldest first. This is what a restart reads.
    fn pending(&self) -> Result<Vec<OutboxBatch>, OutboxError>;
    /// Remove exactly the acknowledged envelopes (by `message_id`).
    /// Unknown ids are a no-op: a retry can deliver acks for envelopes an
    /// earlier confirm already removed, and that must not error.
    fn confirm(&self, message_ids: &[String]) -> Result<(), OutboxError>;
}

/// In-memory reference store. The value itself is the durable artifact:
/// sharing it across "restarts" (a fresh drain over the same store) is
/// the recovery test surface.
#[derive(Default)]
pub struct MemoryOutboxStore {
    inner: Mutex<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    next_order: u64,
    batches: BTreeMap<u64, OutboxBatch>,
}

impl OutboxStore for MemoryOutboxStore {
    fn insert(&self, batch: OutboxBatch) -> Result<(), OutboxError> {
        let mut inner = self.inner.lock().expect("outbox mutex");
        if inner
            .batches
            .values()
            .any(|existing| existing.batch_id == batch.batch_id)
        {
            return Err(OutboxError::DuplicateBatch(batch.batch_id));
        }
        let order = inner.next_order;
        inner.next_order += 1;
        inner.batches.insert(order, batch);
        Ok(())
    }

    fn pending(&self) -> Result<Vec<OutboxBatch>, OutboxError> {
        let inner = self.inner.lock().expect("outbox mutex");
        Ok(inner.batches.values().cloned().collect())
    }

    fn confirm(&self, message_ids: &[String]) -> Result<(), OutboxError> {
        let mut inner = self.inner.lock().expect("outbox mutex");
        for batch in inner.batches.values_mut() {
            batch
                .envelopes
                .retain(|envelope| !message_ids.contains(&envelope.message_id));
        }
        inner.batches.retain(|_, batch| !batch.envelopes.is_empty());
        Ok(())
    }
}

/// Seal operations (DSR-28) and record every batch before anything is
/// sent. Returns the number of staged batches. The caller may now crash:
/// the batches sit in the store.
pub fn stage_operations(
    store: &dyn OutboxStore,
    operations: &[Operation],
    keyring: &KeyRing,
    sender_device_id: &str,
) -> Result<usize, StageError> {
    let batches = crate::batch::seal_operations(operations, keyring, sender_device_id)
        .map_err(StageError::Batch)?;
    let mut staged = 0;
    for envelopes in batches {
        let batch = OutboxBatch {
            batch_id: random_batch_id(),
            envelopes,
        };
        store.insert(batch).map_err(StageError::Storage)?;
        staged += 1;
    }
    Ok(staged)
}

/// Send every pending batch through `send`, confirming exactly what the
/// server acked. Stops at the first failure and reports it — batches
/// confirmed before the failure stay confirmed (they were committed
/// server-side), the failed one and everything after it stay pending.
/// An empty outbox drains to `Ok(0)` without calling `send`.
pub fn drain<S, F, E>(store: &S, mut send: F) -> Result<usize, DrainFailure<E>>
where
    S: OutboxStore,
    F: FnMut(&OutboxBatch) -> Result<Vec<EnvelopeAck>, E>,
{
    let pending = store.pending().map_err(DrainFailure::Storage)?;
    let mut committed = 0;
    for batch in &pending {
        let acks = send(batch).map_err(DrainFailure::Send)?;
        let acked: Vec<String> = acks.iter().map(|ack| ack.message_id.clone()).collect();
        store.confirm(&acked).map_err(DrainFailure::Storage)?;
        committed += 1;
    }
    Ok(committed)
}

/// Why a drain stopped. `Send` carries the sender's own error; the
/// outbox is untouched for that batch — nothing was confirmed, nothing
/// was lost.
#[derive(Debug, thiserror::Error)]
pub enum DrainFailure<E> {
    #[error(transparent)]
    Storage(#[from] OutboxError),
    #[error("{0}")]
    Send(E),
}

/// Why staging stopped. A storage failure leaves the operations
/// unstaged-and-unsent (the caller still holds them); a batch failure
/// means nothing reached the store.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    #[error(transparent)]
    Batch(#[from] crate::batch::BatchError),
    #[error(transparent)]
    Storage(#[from] OutboxError),
}

fn random_batch_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    crate::identity::hex(&bytes)
}
