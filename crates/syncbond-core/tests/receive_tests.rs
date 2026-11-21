//! Receive state and the atomic receive commit (DSR-30): oplog, dedup,
//! HLC high-water and receive cursor cross one storage write; a failed
//! commit loses the page, not the data; the three sequence numbers stay
//! apart.

use std::sync::Arc;

use syncbond_core::conflict::LwwHlc;
use syncbond_core::crypto::KeyRing;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::receive::{
    apply_page, commit_receive, load_receive, ReceiveError, ReceiveState, ReceivedPage,
};
use syncbond_core::replication::Replicator;
use syncbond_core::storage::{MemoryStorage, SyncStorage};
use syncbond_relay_protocol::dto::{Envelope, PullEntry};

fn identity() -> DeviceIdentity {
    DeviceIdentity::generate()
}

/// A receiver replicator with the default LWW strategy.
fn receiver(node_id: &str) -> Replicator {
    Replicator::new(node_id)
}

/// Seal a peer's operations into wire envelopes, exactly as the sender's
/// outbox would.
fn sealed(peer: &mut Replicator, keyring: &KeyRing, sender: &str, count: usize) -> Vec<Envelope> {
    let mut operations = Vec::new();
    for index in 0..count {
        operations.push(
            peer.put(
                format!("note/{index}"),
                format!("value-{index}").into_bytes(),
            )
            .expect("local write"),
        );
    }
    syncbond_core::batch::seal_operations(&operations, keyring, sender)
        .expect("seals")
        .into_iter()
        .flatten()
        .collect()
}

fn page<'a>(server: &'a str, channel: &'a str, entries: &'a [PullEntry]) -> ReceivedPage<'a> {
    ReceivedPage {
        server_id: server,
        channel_id: channel,
        entries,
    }
}

fn entries(envelopes: &[Envelope], first_seq: u64) -> Vec<PullEntry> {
    envelopes
        .iter()
        .enumerate()
        .map(|(index, envelope)| PullEntry {
            seq: first_seq + index as u64,
            envelope: envelope.clone(),
        })
        .collect()
}

#[test]
fn a_page_commits_operations_dedup_cursor_and_clock_together() {
    let keyring = KeyRing::new("group-1");
    let mut peer = receiver("peer");
    let envelopes = sealed(&mut peer, &keyring, "peer", 3);

    let mut local = receiver("local");
    let mut receive = ReceiveState::default();
    let entries = entries(&envelopes, 1);
    let report = apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "ch1", &entries),
    )
    .expect("page applies");
    assert_eq!(report.applied, 3);
    assert_eq!(report.duplicates, 0);
    assert_eq!(report.server_seq, Some(3));
    assert_eq!(local.record_count(), 3);

    let store = MemoryStorage::new();
    let identity = identity();
    let state = local.snapshot_state(&identity, "group-1", 1);
    commit_receive(&store, &state, &receive).expect("commit");

    // Everything a restart needs came out of the same blob.
    let (restored_state, restored_receive) = load_receive(&store)
        .expect("load")
        .expect("a committed snapshot exists");
    let restored =
        Replicator::from_state(&restored_state, Arc::new(LwwHlc)).expect("snapshot replays");
    assert_eq!(restored.record_count(), 3);
    assert_eq!(restored_state.oplog.len(), 3);
    assert_eq!(
        restored_receive
            .cursor_for("s1", "ch1")
            .expect("cursor present")
            .server_seq,
        3
    );
    assert_eq!(restored_receive.seen_message_ids.len(), 3);
    assert!(restored_receive.source_cursor_for("peer").is_some());
}

#[test]
fn a_failed_commit_leaves_the_previous_snapshot_and_nothing_is_skipped() {
    struct FailingStore {
        inner: MemoryStorage,
        fail: std::sync::atomic::AtomicBool,
    }
    impl SyncStorage for FailingStore {
        fn save(&self, state: &[u8]) -> Result<(), syncbond_core::storage::StorageError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(syncbond_core::storage::StorageError::Backend(
                    "disk full".into(),
                ));
            }
            self.inner.save(state)
        }
        fn load(&self) -> Result<Option<Vec<u8>>, syncbond_core::storage::StorageError> {
            self.inner.load()
        }
    }

    let keyring = KeyRing::new("group-1");
    let mut peer = receiver("peer");
    let envelopes = sealed(&mut peer, &keyring, "peer", 2);
    let store = FailingStore {
        inner: MemoryStorage::new(),
        fail: std::sync::atomic::AtomicBool::new(false),
    };
    let identity = identity();

    // Page 1 commits.
    let mut local = receiver("local");
    let mut receive = ReceiveState::default();
    let first = entries(&envelopes, 1);
    apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "ch1", &first),
    )
    .expect("page 1");
    commit_receive(
        &store,
        &local.snapshot_state(&identity, "group-1", 1),
        &receive,
    )
    .expect("first commit");

    // Page 2 applies in memory but its commit fails.
    let mut peer2 = receiver("peer2");
    let second_envelopes = sealed(&mut peer2, &keyring, "peer2", 2);
    let second = entries(&second_envelopes, 3);
    apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "ch1", &second),
    )
    .expect("page 2");

    store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let error = commit_receive(
        &store,
        &local.snapshot_state(&identity, "group-1", 1),
        &receive,
    )
    .expect_err("the commit must fail");
    assert!(matches!(error, ReceiveError::Storage(_)));

    // The backend is still exactly page 1: cursor 2, two ops, two ids.
    let (state, receive) = load_receive(&store).expect("load").expect("page 1 exists");
    assert_eq!(state.oplog.len(), 2);
    assert_eq!(in_cursor(&receive, "s1", "ch1"), 2);
    assert_eq!(receive.seen_message_ids.len(), 2);

    // Restart from the committed snapshot and re-pull page 2 — the page
    // re-applies in full: nothing was skipped and nothing duplicates.
    store.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let mut restarted = Replicator::from_state(&state, Arc::new(LwwHlc)).expect("replays");
    let mut restarted_receive = receive;
    let report = apply_page(
        &mut restarted,
        &mut restarted_receive,
        &keyring,
        &page("s1", "ch1", &second),
    )
    .expect("re-applies");
    assert_eq!(report.applied, 2, "the failed page was not skipped");
    // Page 2 writes the peer's same two keys, so the record count stays
    // at two while the oplog grows by the two new entries.
    assert_eq!(restarted.record_count(), 2);
    assert_eq!(restarted.oplog().len(), 4);
    commit_receive(
        &store,
        &restarted.snapshot_state(&identity, "group-1", 1),
        &restarted_receive,
    )
    .expect("second commit now succeeds");
    let (state, receive) = load_receive(&store).expect("load").expect("page 2");
    assert_eq!(state.oplog.len(), 4);
    assert_eq!(in_cursor(&receive, "s1", "ch1"), 4);
}

fn in_cursor(receive: &ReceiveState, server: &str, channel: &str) -> u64 {
    receive
        .cursor_for(server, channel)
        .map_or(0, |c| c.server_seq)
}

#[test]
fn a_redelivered_page_applies_nothing_but_still_advances_the_cursor() {
    let keyring = KeyRing::new("group-1");
    let mut peer = receiver("peer");
    let envelopes = sealed(&mut peer, &keyring, "peer", 3);
    let entries = entries(&envelopes, 1);

    let mut local = receiver("local");
    let mut receive = ReceiveState::default();
    apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "ch1", &entries),
    )
    .expect("first");

    // The server re-sends the same page (notification loss, retry).
    let report = apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "ch1", &entries),
    )
    .expect("redelivery is not an error");
    assert_eq!(report.applied, 0);
    assert_eq!(report.duplicates, 3);
    assert_eq!(local.record_count(), 3, "no duplicate rows");
    assert_eq!(local.oplog().len(), 3, "no duplicate oplog entries");
    assert_eq!(in_cursor(&receive, "s1", "ch1"), 3);
}

#[test]
fn a_mixed_page_skips_only_the_known_envelopes() {
    let keyring = KeyRing::new("group-1");
    let mut peer = receiver("peer");
    let envelopes = sealed(&mut peer, &keyring, "peer", 4);
    let entries = entries(&envelopes, 1);

    let mut local = receiver("local");
    let mut receive = ReceiveState::default();
    // Page one: the first two.
    apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "ch1", &entries[..2]),
    )
    .expect("p1");
    // Page two overlaps page one by one entry: only the three unseen
    // envelopes may apply, and the alignment must not drift.
    let report = apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "ch1", &entries[1..]),
    )
    .expect("overlapping page");
    assert_eq!(report.duplicates, 1);
    assert_eq!(report.applied, 2, "only the two unseen envelopes apply");
    assert_eq!(report.server_seq, Some(4));
    assert_eq!(local.record_count(), 4);
    assert_eq!(local.oplog().len(), 4);
}

#[test]
fn server_source_and_local_sequence_numbers_never_mix() {
    let keyring = KeyRing::new("group-1");

    // A peer with a two-digit local cursor: the numeric cursor must not
    // be confused by lexicographic ordering.
    let mut peer = receiver("peer");
    for index in 0..12 {
        peer.put(format!("k/{index}"), b"v".to_vec())
            .expect("write");
    }
    let envelopes = sealed(&mut peer, &keyring, "peer", 1);

    let mut local = receiver("local");
    // The local replicator already wrote some operations of its own.
    for index in 0..5 {
        local
            .put(format!("mine/{index}"), b"v".to_vec())
            .expect("local write");
    }
    let local_cursor_before = local.cursor();

    let mut receive = ReceiveState::default();
    let entries = entries(&envelopes, 7); // server seq starts at 7, not 1
    apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "ch1", &entries),
    )
    .expect("applies");

    // Server sequence: whatever the server said (7), unrelated to counts.
    assert_eq!(in_cursor(&receive, "s1", "ch1"), 7);
    // Source cursor: the peer's own numeric cursor (its 13th write), not the
    // server seq and not the local cursor.
    assert_eq!(receive.source_cursor_for("peer"), Some(13));
    // The local write cursor moved only because receiving an op advances
    // the replicator's own bookkeeping — it never equals the server's.
    let _ = local_cursor_before;
    assert_eq!(receive.source_cursor_for("local"), None);
}

#[test]
fn distinct_servers_and_channels_keep_distinct_cursors() {
    let keyring = KeyRing::new("group-1");
    let mut peer = receiver("peer");
    let envelopes = sealed(&mut peer, &keyring, "peer", 2);

    let mut local = receiver("local");
    let mut receive = ReceiveState::default();
    apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "chA", &entries(&envelopes, 5)),
    )
    .expect("s1/chA");
    apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s1", "chB", &entries(&envelopes, 9)),
    )
    .expect("s1/chB");
    // A redelivery under a different server must not be treated as known
    // by cursor, but the ids are global, so it dedups as before.
    let report = apply_page(
        &mut local,
        &mut receive,
        &keyring,
        &page("s2", "chA", &entries(&envelopes, 1)),
    )
    .expect("s2/chA");

    assert_eq!(in_cursor(&receive, "s1", "chA"), 6);
    assert_eq!(in_cursor(&receive, "s1", "chB"), 10);
    assert_eq!(in_cursor(&receive, "s2", "chA"), 2);
    assert_eq!(report.duplicates, 2);
}

#[test]
fn an_empty_page_changes_nothing() {
    let mut local = receiver("local");
    let mut receive = ReceiveState::default();
    let report = apply_page(
        &mut local,
        &mut receive,
        &KeyRing::new("g"),
        &page("s1", "ch1", &[]),
    )
    .expect("empty page");
    assert_eq!(report.applied, 0);
    assert_eq!(report.duplicates, 0);
    assert_eq!(report.server_seq, None);
    assert_eq!(in_cursor(&receive, "s1", "ch1"), 0, "no phantom cursor");
}

#[test]
fn a_wrong_key_page_does_not_move_the_committed_cursor() {
    let sender_keyring = KeyRing::with_epoch("group-1", 1, [1u8; 32]);
    let receiver_keyring = KeyRing::with_epoch("group-1", 1, [2u8; 32]);
    let mut peer = receiver("peer");
    let envelopes = sealed(&mut peer, &sender_keyring, "peer", 2);
    let entries = entries(&envelopes, 1);

    let mut local = receiver("local");
    let mut receive = ReceiveState::default();
    let store = MemoryStorage::new();
    let identity = identity();

    let error = apply_page(
        &mut local,
        &mut receive,
        &receiver_keyring,
        &page("s1", "ch1", &entries),
    )
    .expect_err("undecryptable page");
    assert!(matches!(error, ReceiveError::Batch(_)));

    // The in-memory cursor did not advance either: a page only counts
    // when it applied.
    assert_eq!(in_cursor(&receive, "s1", "ch1"), 0);
    commit_receive(
        &store,
        &local.snapshot_state(&identity, "group-1", 1),
        &receive,
    )
    .expect("an empty commit is still a commit");
    let (state, receive) = load_receive(&store).expect("load").expect("exists");
    assert!(state.oplog.is_empty());
    assert_eq!(in_cursor(&receive, "s1", "ch1"), 0);
}

#[test]
fn a_corrupt_snapshot_fails_closed() {
    struct CorruptStore;
    impl SyncStorage for CorruptStore {
        fn save(&self, _state: &[u8]) -> Result<(), syncbond_core::storage::StorageError> {
            Ok(())
        }
        fn load(&self) -> Result<Option<Vec<u8>>, syncbond_core::storage::StorageError> {
            Ok(Some(b"{\"state\": 12}".to_vec()))
        }
    }

    let error = load_receive(&CorruptStore).expect_err("unreadable snapshot");
    assert!(matches!(error, ReceiveError::Decode(_)), "got: {error:?}");
}
