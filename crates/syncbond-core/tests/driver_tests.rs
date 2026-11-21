//! The sync driver (DSR-31): bounded backoff and cancellation, resume
//! from the committed cursor, catch-up without notifications, and no
//! un-ACKed data lost across a broken line.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use syncbond_core::conflict::LwwHlc;
use syncbond_core::crypto::KeyRing;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::outbox::{stage_operations, MemoryOutboxStore, OutboxStore};
use syncbond_core::receive::{load_receive, ReceiveState};
use syncbond_core::replication::Replicator;
use syncbond_core::storage::MemoryStorage;
use syncbond_core::sync_driver::{
    ChannelTransport, DriverConfig, DriverError, StopReason, SyncDriver, TransportFailure,
};
use syncbond_relay_protocol::dto::{Envelope, EnvelopeAck, PullEntry, PullResponse};

/// A relay stand-in: a committed log with per-entry sequences, pull
/// filtering by cursor, and injectable failures.
struct FakeRelay {
    entries: Mutex<Vec<(u64, Envelope)>>,
    next_seq: AtomicU64,
    append_failures: AtomicUsize,
    pull_failures: AtomicUsize,
    /// Every transport call attempted, failed or not.
    append_calls: AtomicUsize,
    /// Every `after` the driver asked for, in order.
    pull_requests: Mutex<Vec<u64>>,
    /// A permanent pull refusal, e.g. a credential the relay rejects.
    fatal_pull: AtomicBool,
    /// One-shot: the second append fails, as if the line dropped between
    /// batches.
    fail_second: AtomicBool,
    /// The whole line is down; everything is transient.
    down: AtomicBool,
}

impl FakeRelay {
    fn with_envelopes(envelopes: Vec<Envelope>) -> Self {
        let relay = Self {
            entries: Mutex::new(Vec::new()),
            next_seq: AtomicU64::new(1),
            append_failures: AtomicUsize::new(0),
            pull_failures: AtomicUsize::new(0),
            append_calls: AtomicUsize::new(0),
            pull_requests: Mutex::new(Vec::new()),
            fatal_pull: AtomicBool::new(false),
            fail_second: AtomicBool::new(false),
            down: AtomicBool::new(false),
        };
        relay.commit(envelopes);
        relay
    }

    /// Commit envelopes as if appended: per-channel sequence assigned.
    fn commit(&self, envelopes: Vec<Envelope>) {
        let mut entries = self.entries.lock().unwrap();
        for envelope in envelopes {
            let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
            entries.push((seq, envelope));
        }
    }
}

impl ChannelTransport for FakeRelay {
    fn append(&self, envelopes: &[Envelope]) -> Result<Vec<EnvelopeAck>, TransportFailure> {
        self.append_calls.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            return Err(TransportFailure::Transient("connection reset".into()));
        }
        if self.append_calls.load(Ordering::SeqCst) >= 2
            && self
                .fail_second
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Err(TransportFailure::Transient("connection reset".into()));
        }
        if self.append_failures.load(Ordering::SeqCst) > 0 {
            self.append_failures.fetch_sub(1, Ordering::SeqCst);
            return Err(TransportFailure::Transient("connection reset".into()));
        }
        let mut acks = Vec::new();
        let mut entries = self.entries.lock().unwrap();
        for envelope in envelopes {
            let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
            entries.push((seq, envelope.clone()));
            acks.push(EnvelopeAck {
                message_id: envelope.message_id.clone(),
                seq,
                duplicate: false,
            });
        }
        Ok(acks)
    }

    fn pull(&self, after: u64, limit: u16) -> Result<PullResponse, TransportFailure> {
        if self.down.load(Ordering::SeqCst) {
            return Err(TransportFailure::Transient("connection refused".into()));
        }
        if self.fatal_pull.load(Ordering::SeqCst) {
            return Err(TransportFailure::Fatal("credential refused".into()));
        }
        if self.pull_failures.load(Ordering::SeqCst) > 0 {
            self.pull_failures.fetch_sub(1, Ordering::SeqCst);
            return Err(TransportFailure::Transient("connection refused".into()));
        }
        self.pull_requests.lock().unwrap().push(after);
        let entries = self.entries.lock().unwrap();
        let fresh: Vec<&(u64, Envelope)> = entries.iter().filter(|(seq, _)| *seq > after).collect();
        let page: Vec<PullEntry> = fresh
            .iter()
            .take(limit as usize)
            .map(|(seq, envelope)| PullEntry {
                seq: *seq,
                envelope: envelope.clone(),
            })
            .collect();
        Ok(PullResponse {
            protocol_version: 1,
            request_id: "r-fake-00000001".into(),
            channel_id: "ch".into(),
            next_cursor: page.last().map_or(after, |entry| entry.seq),
            has_more: fresh.len() > page.len(),
            entries: page,
        })
    }
}

fn fast_config() -> DriverConfig {
    DriverConfig {
        page_limit: 2,
        max_pages_per_cycle: 8,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(4),
        max_attempts: 3,
        idle_interval: Duration::from_millis(1),
    }
}

/// Seal a peer's fresh writes. The peer replicator is the caller's own and
/// stays alive across batches, exactly like a device that persists its
/// cursor — a fresh one would restart its op ids and its ops would dedup
/// against itself.
fn peer_envelopes(
    peer: &mut Replicator,
    keyring: &KeyRing,
    prefix: &str,
    count: usize,
) -> Vec<Envelope> {
    let mut operations = Vec::new();
    for index in 0..count {
        operations.push(
            peer.put(
                format!("{prefix}/{index}"),
                format!("v{index}").into_bytes(),
            )
            .expect("peer write"),
        );
    }
    syncbond_core::batch::seal_operations(&operations, keyring, "peer")
        .expect("seals")
        .into_iter()
        .flatten()
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn driver<'a>(
    replicator: &'a mut Replicator,
    receive: &'a mut ReceiveState,
    store: &'a MemoryStorage,
    keyring: &'a KeyRing,
    identity: &'a DeviceIdentity,
    outbox: &'a MemoryOutboxStore,
    transport: &'a FakeRelay,
    config: DriverConfig,
) -> SyncDriver<'a> {
    SyncDriver {
        replicator,
        receive,
        store,
        keyring,
        identity,
        group: "group-1",
        key_epoch: 1,
        outbox,
        transport,
        server_id: "relay-1",
        channel_id: "ch-1",
        config,
    }
}

fn cursor_of(receive: &ReceiveState) -> u64 {
    receive
        .cursor_for("relay-1", "ch-1")
        .map_or(0, |cursor| cursor.server_seq)
}

#[test]
fn one_cycle_sends_the_outbox_and_pulls_every_page() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let mut peer = Replicator::new("peer");
    let relay = FakeRelay::with_envelopes(peer_envelopes(&mut peer, &keyring, "note", 5));

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();
    let own: Vec<_> = (0..3)
        .map(|index| {
            local
                .put(format!("mine/{index}"), format!("m{index}").into_bytes())
                .expect("local write")
        })
        .collect();
    stage_operations(&outbox, &own, &keyring, "local").expect("stage");

    let report = {
        let mut driver = driver(
            &mut local,
            &mut receive,
            &store,
            &keyring,
            &identity,
            &outbox,
            &relay,
            fast_config(),
        );
        driver.sync_once().expect("cycle")
    };

    // Both directions in one cycle: the outbox drained, every page
    // pulled (5 peer + 3 own echo, two entries per page → 4 pages).
    assert_eq!(report.sent_batches, 1);
    assert_eq!(report.sent_envelopes, 3);
    assert_eq!(report.pages_pulled, 4);
    assert_eq!(report.applied, 5, "own echoes are not counted as applied");
    assert_eq!(local.record_count(), 8, "5 peer notes + 3 own");
    assert_eq!(cursor_of(&receive), 8);

    // The cycle was durable: a fresh load sees cursor, ids and oplog.
    let (_, committed) = load_receive(&store).expect("load").expect("committed");
    assert_eq!(cursor_of(&committed), 8);
    assert_eq!(committed.seen_message_ids.len(), 8);
    // The outbox is empty: every envelope was acked.
    assert!(outbox.pending().expect("pending").is_empty());
}

#[test]
fn a_transient_send_failure_keeps_every_un_acked_envelope() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let relay = FakeRelay::with_envelopes(Vec::new());
    relay.append_failures.store(1, Ordering::SeqCst);

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();
    let own: Vec<_> = (0..3)
        .map(|index| {
            local
                .put(format!("mine/{index}"), format!("m{index}").into_bytes())
                .expect("local write")
        })
        .collect();
    stage_operations(&outbox, &own, &keyring, "local").expect("stage");

    let mut driver = driver(
        &mut local,
        &mut receive,
        &store,
        &keyring,
        &identity,
        &outbox,
        &relay,
        fast_config(),
    );
    let error = driver.sync_once().expect_err("the send failed");
    assert!(
        matches!(error, DriverError::Send(TransportFailure::Transient(_))),
        "got: {error:?}"
    );

    // Nothing was lost and nothing was committed: the batch is still
    // staged in full, the store still holds nothing.
    let pending = outbox.pending().expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].envelopes.len(), 3);
    assert!(load_receive(&store).expect("load").is_none());

    // The retry ships the same batch in full.
    let report = driver.sync_once().expect("retry");
    assert_eq!(report.sent_envelopes, 3);
    assert!(outbox.pending().expect("pending").is_empty());
}

#[test]
fn partial_send_progress_is_kept_across_a_mid_drain_failure() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let relay = FakeRelay::with_envelopes(Vec::new());
    // The first batch commits, the second one's send fails.
    relay.fail_second.store(true, Ordering::SeqCst);

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();
    // 17 envelopes force two batches (the batch cap is 16).
    let own: Vec<_> = (0..17)
        .map(|index| {
            local
                .put(format!("mine/{index}"), format!("m{index}").into_bytes())
                .expect("local write")
        })
        .collect();
    stage_operations(&outbox, &own, &keyring, "local").expect("stage");

    let mut driver = driver(
        &mut local,
        &mut receive,
        &store,
        &keyring,
        &identity,
        &outbox,
        &relay,
        fast_config(),
    );
    let error = driver.sync_once().expect_err("the second batch failed");
    assert!(matches!(
        error,
        DriverError::Send(TransportFailure::Transient(_))
    ));

    // The confirmed first batch stays confirmed; only the second is
    // still staged.
    let pending = outbox.pending().expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].envelopes.len(), 1);
    assert_eq!(relay.entries.lock().unwrap().len(), 16);

    // The retry ships the remainder; the relay ends with all 17.
    driver.sync_once().expect("retry");
    assert_eq!(relay.entries.lock().unwrap().len(), 17);
    assert!(outbox.pending().expect("pending").is_empty());
}

#[test]
fn run_backs_off_through_transient_failures_and_recovers() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let mut peer = Replicator::new("peer");
    let relay = FakeRelay::with_envelopes(peer_envelopes(&mut peer, &keyring, "note", 4));
    // Two failed cycles, then the line comes back.
    relay.append_failures.store(2, Ordering::SeqCst);

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();
    let own: Vec<_> = (0..2)
        .map(|index| {
            local
                .put(format!("mine/{index}"), format!("m{index}").into_bytes())
                .expect("local write")
        })
        .collect();
    stage_operations(&outbox, &own, &keyring, "local").expect("stage");

    let cancel = Arc::new(AtomicBool::new(false));
    let stop_flag = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        stop_flag.store(true, Ordering::SeqCst);
    });

    let reason = {
        let mut driver = driver(
            &mut local,
            &mut receive,
            &store,
            &keyring,
            &identity,
            &outbox,
            &relay,
            fast_config(),
        );
        driver.run(&cancel)
    };
    assert!(matches!(reason, StopReason::Cancelled), "got: {reason:?}");

    // Despite the two failed cycles, everything synced exactly once:
    // no data lost, no duplicate delivery.
    assert_eq!(relay.append_calls.load(Ordering::SeqCst), 3);
    assert_eq!(local.record_count(), 6);
    let (_, committed) = load_receive(&store).expect("load").expect("committed");
    assert_eq!(cursor_of(&committed), 6);
}

#[test]
fn run_stops_after_bounded_attempts_and_keeps_the_data() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let mut peer = Replicator::new("peer");
    let relay = FakeRelay::with_envelopes(peer_envelopes(&mut peer, &keyring, "note", 2));
    relay.down.store(true, Ordering::SeqCst);

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();
    let own: Vec<_> = (0..2)
        .map(|index| {
            local
                .put(format!("mine/{index}"), format!("m{index}").into_bytes())
                .expect("local write")
        })
        .collect();
    stage_operations(&outbox, &own, &keyring, "local").expect("stage");

    let config = DriverConfig {
        max_attempts: 2,
        ..fast_config()
    };
    let mut driver = driver(
        &mut local,
        &mut receive,
        &store,
        &keyring,
        &identity,
        &outbox,
        &relay,
        config,
    );
    let reason = driver.run(&AtomicBool::new(false));
    let StopReason::Exhausted(error) = reason else {
        panic!("expected exhaustion, got: {reason:?}");
    };
    assert!(matches!(
        error,
        DriverError::Send(TransportFailure::Transient(_))
    ));

    // Bounded: exactly max_attempts send attempts were made, and the
    // staged batch is intact for the next run.
    assert_eq!(relay.append_calls.load(Ordering::SeqCst), 2);
    assert_eq!(outbox.pending().expect("pending")[0].envelopes.len(), 2);
    assert!(load_receive(&store).expect("load").is_none());
}

#[test]
fn a_fatal_error_stops_the_run_without_retrying() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let mut peer = Replicator::new("peer");
    let relay = FakeRelay::with_envelopes(peer_envelopes(&mut peer, &keyring, "note", 2));
    relay.fatal_pull.store(true, Ordering::SeqCst);

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();
    // Something staged, so the send direction runs before the pull.
    let own: Vec<_> = (0..2)
        .map(|index| {
            local
                .put(format!("mine/{index}"), format!("m{index}").into_bytes())
                .expect("local write")
        })
        .collect();
    stage_operations(&outbox, &own, &keyring, "local").expect("stage");

    let mut driver = driver(
        &mut local,
        &mut receive,
        &store,
        &keyring,
        &identity,
        &outbox,
        &relay,
        fast_config(),
    );
    let reason = driver.run(&AtomicBool::new(false));
    let StopReason::Fatal(error) = reason else {
        panic!("expected a fatal stop, got: {reason:?}");
    };
    assert!(matches!(
        error,
        DriverError::Pull(TransportFailure::Fatal(_))
    ));
    // One cycle, no retries: the fatal outcome is not hammered.
    assert_eq!(relay.append_calls.load(Ordering::SeqCst), 1);
    // The send direction still committed (the relay acked it); only the
    // receive cursor stayed behind.
    assert!(outbox.pending().expect("pending").is_empty());
    assert_eq!(
        relay.entries.lock().unwrap().len(),
        4,
        "peer's 2 + local's 2"
    );
    assert!(load_receive(&store).expect("load").is_none());
}

#[test]
fn cancellation_is_observed_before_any_work() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let mut peer = Replicator::new("peer");
    let relay = FakeRelay::with_envelopes(peer_envelopes(&mut peer, &keyring, "note", 2));

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();

    let cancel = AtomicBool::new(true);
    let mut driver = driver(
        &mut local,
        &mut receive,
        &store,
        &keyring,
        &identity,
        &outbox,
        &relay,
        fast_config(),
    );
    let reason = driver.run(&cancel);
    assert!(matches!(reason, StopReason::Cancelled));
    assert_eq!(relay.append_calls.load(Ordering::SeqCst), 0, "no work ran");
    assert!(relay.pull_requests.lock().unwrap().is_empty());
}

#[test]
fn a_missed_notification_is_caught_up_from_the_committed_cursor() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let mut peer = Replicator::new("peer");
    let relay = FakeRelay::with_envelopes(peer_envelopes(&mut peer, &keyring, "note", 2));

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();

    {
        let mut first = driver(
            &mut local,
            &mut receive,
            &store,
            &keyring,
            &identity,
            &outbox,
            &relay,
            fast_config(),
        );
        first.sync_once().expect("first cycle");
    }
    assert_eq!(cursor_of(&receive), 2);

    // The peer sends three more while no notification ever fires. The
    // next cycle pulls from the committed cursor — not from zero — and
    // catches up in full.
    relay.commit(peer_envelopes(&mut peer, &keyring, "more", 3));
    {
        let mut second = driver(
            &mut local,
            &mut receive,
            &store,
            &keyring,
            &identity,
            &outbox,
            &relay,
            fast_config(),
        );
        second.sync_once().expect("catch-up cycle");
    }
    assert_eq!(local.record_count(), 5);
    assert_eq!(cursor_of(&receive), 5);
    let pulls = relay.pull_requests.lock().unwrap();
    assert_eq!(*pulls, vec![0, 2, 4], "resumed from the committed cursor");
}

#[test]
fn a_restart_resumes_from_the_committed_cursor() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let mut peer = Replicator::new("peer");
    let relay = FakeRelay::with_envelopes(peer_envelopes(&mut peer, &keyring, "note", 3));

    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();

    // First life: pulls the first three and commits cursor 3.
    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let mut first_driver = driver(
        &mut local,
        &mut receive,
        &store,
        &keyring,
        &identity,
        &outbox,
        &relay,
        fast_config(),
    );
    first_driver.sync_once().expect("first life");

    // The peer sends two more after the device went down.
    relay.commit(peer_envelopes(&mut peer, &keyring, "later", 2));

    // Second life: rebuilt from the committed snapshot alone.
    let (state, receive) = load_receive(&store).expect("load").expect("committed");
    let mut restarted = Replicator::from_state(&state, Arc::new(LwwHlc)).expect("replays");
    let mut restarted_receive = receive;
    let report = {
        let mut second_driver = driver(
            &mut restarted,
            &mut restarted_receive,
            &store,
            &keyring,
            &identity,
            &outbox,
            &relay,
            fast_config(),
        );
        second_driver.sync_once().expect("catch-up")
    };
    assert_eq!(
        report.applied, 2,
        "only the envelopes past the committed cursor"
    );
    assert_eq!(
        restarted.record_count(),
        5,
        "nothing re-applied, nothing skipped"
    );
    assert_eq!(cursor_of(&restarted_receive), 5);
    let pulls = relay.pull_requests.lock().unwrap();
    assert_eq!(
        *pulls,
        vec![0, 2, 3],
        "the restart asked for exactly what was missing"
    );
}

#[test]
fn an_empty_cycle_commits_nothing_and_asks_one_page() {
    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();
    let relay = FakeRelay::with_envelopes(Vec::new());

    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let outbox = MemoryOutboxStore::default();

    let mut driver = driver(
        &mut local,
        &mut receive,
        &store,
        &keyring,
        &identity,
        &outbox,
        &relay,
        fast_config(),
    );
    let report = driver.sync_once().expect("empty cycle");
    assert_eq!(report, syncbond_core::sync_driver::CycleReport::default());
    assert_eq!(*relay.pull_requests.lock().unwrap(), vec![0]);
    assert!(
        load_receive(&store).expect("load").is_none(),
        "nothing to commit"
    );
}
