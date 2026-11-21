//! The sync driver (todo.md DSR-31): one seam, two directions, bounded
//! patience.
//!
//! The driver composes the three pieces that came before it: it sends
//! through the outbox (DSR-29 — only acked envelopes leave the outbox,
//! so a broken connection loses nothing that was not confirmed), it
//! receives page by page through the atomic receive commit (DSR-30 —
//! oplog, dedup and cursor cross one storage write), and it pages from
//! the committed cursor, so a reconnect never asks for anything it
//! already committed and never skips what it did not (DSR-28 opens each
//! page).
//!
//! The core stays network-free (DSR-11): the network is the
//! [`ChannelTransport`] seam, and the HTTP client that serves it lives
//! outside this crate.
//!
//! - **Bounded backoff.** A transient failure doubles the wait, capped
//!   at [`DriverConfig::max_backoff`], for at most
//!   [`DriverConfig::max_attempts`] consecutive attempts — then the run
//!   ends with [`StopReason::Exhausted`] instead of retrying forever.
//! - **Cancellation.** The flag is observed before every attempt and
//!   every wait, and waits sleep in small slices, so cancellation is
//!   answered promptly, not after the full backoff.
//! - **A missed notification is not data loss.** Receiving is
//!   pull-driven from the committed cursor, so the next cycle catches up
//!   whether or not a push notification ever arrived — notifications
//!   are hints, never authoritative.
//! - **A broken line loses nothing un-ACKed.** A send failure stops the
//!   cycle with the outbox untouched beyond what the relay confirmed;
//!   the next attempt re-sends byte-identical envelopes, and the relay's
//!   `(channel, messageId)` idempotency dedups any double commit.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use syncbond_relay_protocol::dto::{Envelope, EnvelopeAck, PullResponse};

use crate::crypto::KeyRing;
use crate::identity::DeviceIdentity;
use crate::outbox::{self, DrainFailure, OutboxStore};
use crate::receive::{apply_page, commit_receive, ReceiveError, ReceiveState, ReceivedPage};
use crate::replication::Replicator;
use crate::storage::SyncStorage;

/// The network seam of the driver. One implementation serves one
/// (server, channel, credential) binding; the driver tells it only the
/// variable part of each call.
pub trait ChannelTransport {
    /// Append a batch of sealed envelopes. The acks come back only for
    /// envelopes the relay committed durably.
    fn append(&self, envelopes: &[Envelope]) -> Result<Vec<EnvelopeAck>, TransportFailure>;
    /// Pull the entries after `after`, ascending and contiguous.
    fn pull(&self, after: u64, limit: u16) -> Result<PullResponse, TransportFailure>;
}

/// A transport outcome, classified by whether retrying can help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportFailure {
    /// Connection refused, timeout, a 5xx — the next attempt may work.
    Transient(String),
    /// Refused credentials, a broken contract — retrying cannot help.
    Fatal(String),
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportFailure::Transient(reason) => write!(f, "transient: {reason}"),
            TransportFailure::Fatal(reason) => write!(f, "fatal: {reason}"),
        }
    }
}

/// Typed failures of one sync cycle and of the run loop.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("send failed: {0}")]
    Send(TransportFailure),
    #[error("pull failed: {0}")]
    Pull(TransportFailure),
    #[error(transparent)]
    Receive(#[from] ReceiveError),
    #[error("outbox storage error: {0}")]
    Outbox(String),
}

impl DriverError {
    /// Fatal errors stop the run for good; the rest are worth a bounded
    /// retry. Receive and outbox storage errors are fatal: a page that
    /// cannot apply or a store that cannot commit will not fix itself.
    pub fn is_fatal(&self) -> bool {
        match self {
            DriverError::Send(TransportFailure::Fatal(_))
            | DriverError::Pull(TransportFailure::Fatal(_)) => true,
            DriverError::Send(TransportFailure::Transient(_))
            | DriverError::Pull(TransportFailure::Transient(_)) => false,
            DriverError::Receive(_) | DriverError::Outbox(_) => true,
        }
    }
}

/// The driver's knobs. Defaults suit a desktop embedder; tests shrink
/// the waits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverConfig {
    /// Entries asked for per pull page.
    pub page_limit: u16,
    /// Pages applied per cycle at most; the next cycle continues from
    /// the committed cursor.
    pub max_pages_per_cycle: usize,
    /// The first wait after a transient failure; doubled per failure.
    pub initial_backoff: Duration,
    /// The wait never exceeds this, however many failures stack up.
    pub max_backoff: Duration,
    /// Consecutive transient failures tolerated before the run ends.
    pub max_attempts: u32,
    /// The idle pause between cycles — the poll cadence when no
    /// notification nudges the driver.
    pub idle_interval: Duration,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            page_limit: 32,
            max_pages_per_cycle: 16,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            max_attempts: 5,
            idle_interval: Duration::from_secs(2),
        }
    }
}

/// What one cycle did, for the caller to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CycleReport {
    /// Batches the relay acked (and therefore confirmed in the outbox).
    pub sent_batches: usize,
    /// Envelopes those acks carried.
    pub sent_envelopes: usize,
    /// Pages applied and committed this cycle.
    pub pages_pulled: usize,
    /// Envelopes that decrypted and applied; own echoes and
    /// redeliveries are not counted here.
    pub applied: usize,
}

/// Why the run loop ended.
#[derive(Debug)]
pub enum StopReason {
    /// The cancellation flag was observed. Everything applied before
    /// this point is committed.
    Cancelled,
    /// `max_attempts` consecutive transient failures; the last error is
    /// carried for the caller to log.
    Exhausted(DriverError),
    /// An error retrying cannot fix; the last error is carried.
    Fatal(DriverError),
}

/// One device's session against one (server, channel): its replicator,
/// its receive state, its stores, its key material, and its transport.
/// Every field is the caller's own object — the driver holds nothing.
pub struct SyncDriver<'a> {
    pub replicator: &'a mut Replicator,
    pub receive: &'a mut ReceiveState,
    pub store: &'a (dyn SyncStorage + Send + Sync),
    pub keyring: &'a KeyRing,
    pub identity: &'a DeviceIdentity,
    pub group: &'a str,
    pub key_epoch: u64,
    pub outbox: &'a (dyn OutboxStore + Send + Sync),
    pub transport: &'a dyn ChannelTransport,
    pub server_id: &'a str,
    pub channel_id: &'a str,
    pub config: DriverConfig,
}

/// Waits sleep in slices of this size so a cancel flag is answered
/// promptly even mid-backoff.
const CANCEL_POLL: Duration = Duration::from_millis(25);

impl SyncDriver<'_> {
    /// One full cycle: send everything pending, then pull from the
    /// committed cursor until caught up (or the cycle's page budget
    /// ends). Each received page applies and commits as one blob before
    /// the next page is asked for, so a crash mid-cycle loses at most
    /// the un-committed page — never the cursor of pages before it.
    pub fn sync_once(&mut self) -> Result<CycleReport, DriverError> {
        let mut report = CycleReport::default();

        // Send. `drain` confirms only what the relay acked, so a failure
        // below leaves every un-acked envelope staged for the retry.
        let transport = self.transport;
        let mut delivered = 0usize;
        let sent = outbox::drain(self.outbox, |batch| {
            let acks = transport.append(&batch.envelopes)?;
            delivered += acks.len();
            Ok(acks)
        });
        match sent {
            Ok(batches) => {
                report.sent_batches = batches;
                report.sent_envelopes = delivered;
            }
            Err(DrainFailure::Storage(error)) => {
                return Err(DriverError::Outbox(error.to_string()));
            }
            Err(DrainFailure::Send(failure)) => return Err(DriverError::Send(failure)),
        }

        // Pull. The cursor is always the committed one: a restart, a
        // reconnect and a missed notification all resume from exactly
        // the same place.
        loop {
            if report.pages_pulled >= self.config.max_pages_per_cycle {
                break;
            }
            let after = self
                .receive
                .cursor_for(self.server_id, self.channel_id)
                .map_or(0, |cursor| cursor.server_seq);
            let response = self
                .transport
                .pull(after, self.config.page_limit)
                .map_err(DriverError::Pull)?;
            if response.entries.is_empty() {
                // Caught up: an empty page moves nothing, and no data
                // was skipped to get here.
                break;
            }
            let page = ReceivedPage {
                server_id: self.server_id,
                channel_id: self.channel_id,
                entries: &response.entries,
            };
            let applied = apply_page(self.replicator, self.receive, self.keyring, &page)?;
            commit_receive(
                self.store,
                &self
                    .replicator
                    .snapshot_state(self.identity, self.group, self.key_epoch),
                self.receive,
            )?;
            report.pages_pulled += 1;
            report.applied += applied.applied;
            if !response.has_more {
                break;
            }
        }

        Ok(report)
    }

    /// Cycle until cancelled, until `max_attempts` consecutive transient
    /// failures, or until a fatal error — whichever comes first. A
    /// successful cycle resets the failure count; the backoff doubles
    /// per failure and never passes [`DriverConfig::max_backoff`].
    pub fn run(&mut self, cancel: &AtomicBool) -> StopReason {
        let mut backoff = self.config.initial_backoff;
        let mut failures = 0u32;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return StopReason::Cancelled;
            }
            match self.sync_once() {
                Ok(_) => {
                    failures = 0;
                    backoff = self.config.initial_backoff;
                }
                Err(error) if error.is_fatal() => return StopReason::Fatal(error),
                Err(error) => {
                    failures += 1;
                    if failures >= self.config.max_attempts {
                        return StopReason::Exhausted(error);
                    }
                    if self.wait(cancel, backoff) {
                        return StopReason::Cancelled;
                    }
                    backoff = (backoff * 2).min(self.config.max_backoff);
                }
            }
            if self.wait(cancel, self.config.idle_interval) {
                return StopReason::Cancelled;
            }
        }
    }

    /// Sleep `total` in small slices; true when the cancel flag was
    /// observed during the wait.
    fn wait(&self, cancel: &AtomicBool, total: Duration) -> bool {
        let deadline = Instant::now() + total;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            std::thread::sleep(CANCEL_POLL.min(deadline - now));
        }
    }
}
