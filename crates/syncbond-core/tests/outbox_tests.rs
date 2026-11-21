//! Persistent outbox and ACK confirmation (DSR-29): staged-before-sent,
//! byte-stable resends, and nothing removed until the server committed.
//! The fake server here mirrors the relay contract the server crate
//! already proves (DSR-13: same id same payload → original seq,
//! duplicate acks, append is transactional).

use std::collections::HashSet;

use syncbond_core::batch::open_operations;
use syncbond_core::crypto::KeyRing;
use syncbond_core::hlc::HlcStamp;
use syncbond_core::outbox::{
    drain, stage_operations, DrainFailure, MemoryOutboxStore, OutboxStore, StageError,
};
use syncbond_core::replication::Operation;
use syncbond_relay_protocol::dto::{Envelope, EnvelopeAck};

fn put(op_id: &str, key: &str, payload: &[u8]) -> Operation {
    Operation {
        op_id: op_id.to_owned(),
        key: key.to_owned(),
        payload: payload.to_vec(),
        deleted: false,
        stamp: HlcStamp {
            pt: 1_000,
            ct: 1,
            id: "device-a".into(),
        },
        witness: Default::default(),
    }
}

/// The relay's append contract, as proven server-side by DSR-13:
/// `(channel, message_id)` idempotency — a retried envelope appends
/// nothing and acks the original commit. Ack construction happens only
/// after the (simulated) commit.
#[derive(Default)]
struct FakeRelay {
    appended: Vec<Envelope>,
    seen_ids: HashSet<String>,
}

impl FakeRelay {
    /// Commit the batch, then decide whether the response survives.
    /// `lose_ack` drops the response after the commit — the crash window
    /// DSR-29 exists for.
    fn append(&mut self, batch: &[Envelope], lose_ack: bool) -> Result<Vec<EnvelopeAck>, String> {
        for envelope in batch {
            if self.seen_ids.insert(envelope.message_id.clone()) {
                self.appended.push(envelope.clone());
            }
        }
        if lose_ack {
            Err("response lost after commit".into())
        } else {
            // Seq values are decorative here; only message ids drive the
            // outbox. The relay contract (DSR-13/14) proves real seqs.
            Ok(batch
                .iter()
                .enumerate()
                .map(|(index, envelope)| EnvelopeAck {
                    message_id: envelope.message_id.clone(),
                    seq: index as u64 + 1,
                    duplicate: false,
                })
                .collect())
        }
    }
}

#[test]
fn staged_batches_are_recoverable_before_any_send() {
    let store = MemoryOutboxStore::default();
    let keyring = KeyRing::new("group-1");
    let operations: Vec<Operation> = (0..30)
        .map(|index| {
            put(
                &format!("device-a:{index}"),
                &format!("note/{index}"),
                b"payload",
            )
        })
        .collect();

    let staged =
        stage_operations(&store, &operations, &keyring, "device-a").expect("staging succeeds");
    assert!(
        staged > 1,
        "30 operations must exceed one 16-envelope batch"
    );

    // Nothing was sent — the "restart" finds everything pending and the
    // sealed envelopes still open into exactly the staged operations.
    let pending = store.pending().expect("pending readable");
    assert_eq!(pending.len(), staged);
    let envelopes: Vec<Envelope> = pending
        .iter()
        .flat_map(|b| b.envelopes.iter().cloned())
        .collect();
    assert_eq!(envelopes.len(), operations.len());
    let mut seen = HashSet::new();
    let reopened =
        open_operations(&envelopes, &keyring, &mut seen).expect("staged envelopes decrypt");
    assert_eq!(reopened, operations);
}

#[test]
fn a_lost_ack_leaves_everything_pending_and_the_resend_is_byte_identical() {
    let store = MemoryOutboxStore::default();
    let keyring = KeyRing::new("group-1");
    let operations: Vec<Operation> = (0..4)
        .map(|index| {
            put(
                &format!("device-a:{index}"),
                &format!("note/{index}"),
                b"payload",
            )
        })
        .collect();
    stage_operations(&store, &operations, &keyring, "device-a").expect("staged");

    let relay = std::cell::RefCell::new(FakeRelay::default());
    let mut sent_bytes: Vec<Vec<u8>> = Vec::new();
    let mut calls = 0;
    let mut send =
        |batch: &syncbond_core::outbox::OutboxBatch| -> Result<Vec<EnvelopeAck>, String> {
            calls += 1;
            sent_bytes.push(serde_json::to_vec(&batch.envelopes).expect("wire json"));
            relay.borrow_mut().append(&batch.envelopes, calls == 1)
        };
    let outcome = drain(&store, &mut send);
    match outcome {
        Err(DrainFailure::Send(message)) => assert_eq!(message, "response lost after commit"),
        other => panic!("expected Send failure, got: {other:?}"),
    }

    // The commit reached the relay, but the response did not reach us:
    // nothing may be confirmed.
    let pending = store.pending().expect("pending readable");
    assert_eq!(pending.len(), 1, "a lost ack must leave the batch pending");
    assert_eq!(
        relay.borrow().appended.len(),
        4,
        "the first attempt did commit"
    );

    // Retry: the exact same wire bytes go out — same message ids — so
    // the relay's idempotency recognizes every envelope.
    let outcome = drain(&store, &mut send);
    assert_eq!(outcome.expect("retry drains"), 1);
    assert_eq!(sent_bytes.len(), 2, "one attempt per send call");
    assert_eq!(
        sent_bytes[0], sent_bytes[1],
        "the retry must be byte-identical"
    );

    // The ack finally landed: the outbox empties.
    assert!(store.pending().expect("pending readable").is_empty());
}

#[test]
fn resend_after_a_lost_ack_appends_nothing_twice() {
    let store = MemoryOutboxStore::default();
    let keyring = KeyRing::new("group-1");
    let operations: Vec<Operation> = (0..4)
        .map(|index| {
            put(
                &format!("device-a:{index}"),
                &format!("note/{index}"),
                b"payload",
            )
        })
        .collect();
    stage_operations(&store, &operations, &keyring, "device-a").expect("staged");

    let mut relay = FakeRelay::default();
    let mut first = true;
    let mut send =
        |batch: &syncbond_core::outbox::OutboxBatch| -> Result<Vec<EnvelopeAck>, String> {
            let loss = std::mem::take(&mut first);
            relay.append(&batch.envelopes, loss)
        };
    assert!(matches!(
        drain(&store, &mut send),
        Err(DrainFailure::Send(_))
    ));
    let outcome = drain(&store, &mut send);
    assert_eq!(outcome.expect("retry drains"), 1);

    // Four operations, one append each — the lost-ack retry added zero.
    assert_eq!(relay.appended.len(), operations.len());
    let ids: HashSet<&str> = relay
        .appended
        .iter()
        .map(|e| e.message_id.as_str())
        .collect();
    assert_eq!(
        ids.len(),
        operations.len(),
        "no duplicate message ids stored"
    );
    assert!(store.pending().expect("pending readable").is_empty());
}

#[test]
fn nothing_is_confirmed_without_a_server_commit() {
    let store = MemoryOutboxStore::default();
    let keyring = KeyRing::new("group-1");
    let operations = vec![put("device-a:1", "note/1", b"payload")];
    stage_operations(&store, &operations, &keyring, "device-a").expect("staged");
    let before = store.pending().expect("pending readable");

    // The send fails before committing: the outbox must not lose a byte.
    let mut send =
        |_batch: &syncbond_core::outbox::OutboxBatch| -> Result<Vec<EnvelopeAck>, String> {
            Err("connection refused before the request was written".into())
        };
    assert!(matches!(
        drain(&store, &mut send),
        Err(DrainFailure::Send(_))
    ));
    assert_eq!(store.pending().expect("pending readable"), before);
}

#[test]
fn partial_progress_survives_a_later_batch_failure() {
    let store = MemoryOutboxStore::default();
    let keyring = KeyRing::new("group-1");
    let operations: Vec<Operation> = (0..20)
        .map(|index| {
            put(
                &format!("device-a:{index}"),
                &format!("note/{index}"),
                b"payload",
            )
        })
        .collect();
    let staged = stage_operations(&store, &operations, &keyring, "device-a").expect("staged");
    assert_eq!(staged, 2, "20 operations split into two batches");

    let mut relay = FakeRelay::default();
    let mut calls = 0;
    let mut send =
        |batch: &syncbond_core::outbox::OutboxBatch| -> Result<Vec<EnvelopeAck>, String> {
            calls += 1;
            relay.append(&batch.envelopes, calls == 2)
        };
    assert!(matches!(
        drain(&store, &mut send),
        Err(DrainFailure::Send(_))
    ));

    // Batch 1 was committed and acked — it stays gone. Batch 2 remains
    // pending and drains on the retry.
    let pending = store.pending().expect("pending readable");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].envelopes.len(), 4);
    let outcome = drain(&store, &mut send);
    assert_eq!(outcome.expect("retry drains the rest"), 1);
    assert!(store.pending().expect("pending readable").is_empty());
    assert_eq!(relay.appended.len(), 20);
}

#[test]
fn draining_an_empty_outbox_never_calls_the_sender() {
    let store = MemoryOutboxStore::default();
    let mut calls = 0;
    let mut send =
        |_batch: &syncbond_core::outbox::OutboxBatch| -> Result<Vec<EnvelopeAck>, String> {
            calls += 1;
            Ok(Vec::new())
        };
    let outcome = drain(&store, &mut send);
    assert_eq!(outcome.expect("empty drain"), 0);
    assert_eq!(calls, 0, "no pending batches, no send attempts");
}

#[test]
fn confirm_is_idempotent_and_ignores_unknown_ids() {
    let store = MemoryOutboxStore::default();
    let keyring = KeyRing::new("group-1");
    let operations = vec![
        put("device-a:1", "note/1", b"one"),
        put("device-a:2", "note/2", b"two"),
    ];
    stage_operations(&store, &operations, &keyring, "device-a").expect("staged");

    let pending = store.pending().expect("pending readable");
    let first_id = pending[0].envelopes[0].message_id.clone();
    let second_id = pending[0].envelopes[1].message_id.clone();

    // Both operations ride one batch: confirming the first ack leaves
    // the batch alive with only the second envelope.
    store
        .confirm(std::slice::from_ref(&first_id))
        .expect("confirm works");
    let pending = store.pending().expect("pending readable");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].envelopes.len(), 1);
    assert_eq!(pending[0].envelopes[0].message_id, second_id);

    // A retry's duplicate ack for the same envelope, plus an id the
    // store has never heard of: neither may error or change state.
    store
        .confirm(&[first_id, "never-seen-id".into()])
        .expect("re-confirm and unknown ids are no-ops");
    let pending = store.pending().expect("pending readable");
    assert_eq!(pending[0].envelopes.len(), 1, "no-ops change nothing");

    store.confirm(&[second_id]).expect("final confirm works");
    assert!(store.pending().expect("pending readable").is_empty());
}

#[test]
fn a_staging_storage_failure_sends_nothing() {
    struct RefusingStore;
    impl OutboxStore for RefusingStore {
        fn insert(
            &self,
            _batch: syncbond_core::outbox::OutboxBatch,
        ) -> Result<(), syncbond_core::outbox::OutboxError> {
            Err(syncbond_core::outbox::OutboxError::Storage(
                "disk full".into(),
            ))
        }
        fn pending(
            &self,
        ) -> Result<Vec<syncbond_core::outbox::OutboxBatch>, syncbond_core::outbox::OutboxError>
        {
            Ok(Vec::new())
        }
        fn confirm(
            &self,
            _message_ids: &[String],
        ) -> Result<(), syncbond_core::outbox::OutboxError> {
            Ok(())
        }
    }

    let store = RefusingStore;
    let keyring = KeyRing::new("group-1");
    let operations = vec![put("device-a:1", "note/1", b"payload")];
    let error = stage_operations(&store, &operations, &keyring, "device-a")
        .expect_err("insert failure surfaces");
    match error {
        StageError::Storage(syncbond_core::outbox::OutboxError::Storage(message)) => {
            assert_eq!(message, "disk full");
        }
        other => panic!("expected Storage failure, got: {other:?}"),
    }
}
