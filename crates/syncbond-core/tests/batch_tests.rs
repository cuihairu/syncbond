//! Bounded operation batches (DSR-28): round trips, wire limits, and the
//! failure surfaces — nothing plaintext leaves, oversize logs split, an
//! oversize operation is a typed error, and every crypto verdict surfaces
//! with its own variant.

use std::collections::HashSet;

use syncbond_core::batch::{open_operations, seal_operations, BatchError};
use syncbond_core::crypto::{b64url_encode, CryptoError, KeyRing};
use syncbond_core::hlc::HlcStamp;
use syncbond_core::replication::Operation;
use syncbond_relay_protocol::dto::Envelope;
use syncbond_relay_protocol::limits::check_batch;

/// A put operation with an explicit payload (no replicator needed — the
/// batch codec works on the plain struct).
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

fn delete(op_id: &str, key: &str) -> Operation {
    Operation {
        deleted: true,
        payload: Vec::new(),
        ..put(op_id, key, &[])
    }
}

fn open_all(batches: &[Vec<Envelope>], keyring: &KeyRing) -> Result<Vec<Operation>, BatchError> {
    let mut seen = HashSet::new();
    let mut operations = Vec::new();
    for batch in batches {
        operations.extend(open_operations(batch, keyring, &mut seen)?);
    }
    Ok(operations)
}

#[test]
fn round_trip_preserves_every_operation_field() {
    let keyring = KeyRing::new("group-1");
    let operations = vec![
        put("device-a:1", "note/1", b"hello"),
        delete("device-a:2", "note/1"),
        put("device-a:3", "empty/1", &[]),
        put("device-a:4", "binary/1", &[0u8, 255, 7, 128, 42, 0, 0, 13]),
    ];
    let batches = seal_operations(&operations, &keyring, "device-a").expect("small log seals");

    // Every operation is its own envelope, in order.
    let envelope_count: usize = batches.iter().map(Vec::len).sum();
    assert_eq!(envelope_count, operations.len());
    for batch in &batches {
        check_batch(batch).expect("every produced batch meets the contract");
    }

    let opened = open_all(&batches, &keyring).expect("round trip opens");
    assert_eq!(opened, operations);
    // Exact struct equality already covers op_id/key/payload/deleted/
    // stamp/witness; the assertion above is the whole check.
}

#[test]
fn only_ciphertext_leaves_the_wire() {
    let keyring = KeyRing::new("group-1");
    let operations = vec![put("device-a:1", "secret/1", b"the plaintext payload")];
    let batches = seal_operations(&operations, &keyring, "device-a").expect("seals");

    let wire = serde_json::to_string(&batches).expect("wire json serializes");
    assert!(
        !wire.contains("the plaintext payload"),
        "payload leaked: {wire}"
    );
    assert!(!wire.contains("secret/1"), "record key leaked: {wire}");
    assert!(!wire.contains("device-a:1"), "op id leaked: {wire}");

    // One fresh nonce and message id per operation: identical plaintexts
    // under the same key must still produce distinct envelopes.
    let twin = vec![put("device-a:2", "secret/1", b"the plaintext payload")];
    let more = seal_operations(&twin, &keyring, "device-a").expect("seals");
    let all: Vec<&Envelope> = batches.iter().chain(more.iter()).flatten().collect();
    let mut nonces: Vec<&str> = all.iter().map(|e| e.nonce.as_str()).collect();
    nonces.sort_unstable();
    nonces.dedup();
    assert_eq!(nonces.len(), all.len(), "nonce reused across envelopes");
}

#[test]
fn large_log_splits_across_batches() {
    let keyring = KeyRing::new("group-1");
    let payload = vec![0xABu8; 600 * 1024];
    let operations: Vec<Operation> = (0..25)
        .map(|index| {
            put(
                &format!("device-a:{index}"),
                &format!("blob/{index}"),
                &payload,
            )
        })
        .collect();
    let batches = seal_operations(&operations, &keyring, "device-a").expect("large log seals");

    // One operation per envelope, in order; the log cannot ride one
    // batch.
    let envelope_count: usize = batches.iter().map(Vec::len).sum();
    assert_eq!(envelope_count, operations.len());
    assert!(batches.len() > 1, "a 25-op log must split, got one batch");
    for batch in &batches {
        check_batch(batch).expect("every produced batch meets the contract");
    }

    let opened = open_all(&batches, &keyring).expect("all batches open");
    assert_eq!(opened.len(), operations.len());
    for (opened_op, original) in opened.iter().zip(&operations) {
        assert_eq!(opened_op.op_id, original.op_id);
        assert_eq!(opened_op.payload, original.payload);
    }
}

#[test]
fn an_operation_that_cannot_fit_one_envelope_is_a_typed_error() {
    let keyring = KeyRing::new("group-1");
    let huge = vec![0xCDu8; 2 * 1024 * 1024];
    let operations = vec![
        put("device-a:1", "small/1", b"tiny"),
        put("device-a:2", "huge/1", &huge),
    ];
    let error = seal_operations(&operations, &keyring, "device-a")
        .expect_err("an oversize operation is refused");

    match error {
        BatchError::OperationTooLarge {
            index,
            payload_len,
            wire_len,
            wire_cap,
        } => {
            assert_eq!(index, 1, "the error names the oversized operation");
            assert_eq!(payload_len, huge.len());
            assert!(wire_len > wire_cap);
        }
        other => panic!("expected OperationTooLarge, got: {other:?}"),
    }
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let keyring = KeyRing::new("group-1");
    let operations = vec![put("device-a:1", "note/1", b"payload")];
    let batches = seal_operations(&operations, &keyring, "device-a").expect("seals");

    // Flip one ciphertext byte on the wire envelope.
    let mut tampered: Vec<Envelope> = batches[0].clone();
    let mut cipher = syncbond_core::crypto::b64url_decode(&tampered[0].ciphertext).expect("b64");
    cipher[0] ^= 0xFF;
    tampered[0].ciphertext = b64url_encode(&cipher);

    let mut seen = HashSet::new();
    let error = open_operations(&tampered, &keyring, &mut seen)
        .expect_err("a tampered envelope must not open");
    match error {
        BatchError::Crypto(CryptoError::AuthenticationFailed) => {}
        other => panic!("expected AuthenticationFailed, got: {other:?}"),
    }
}

#[test]
fn envelopes_from_another_group_are_refused() {
    let key = [7u8; 32];
    let sender = KeyRing::with_epoch("group-a", 1, key);
    let receiver = KeyRing::with_epoch("group-b", 1, key);

    let batches = seal_operations(
        &[put("device-a:1", "note/1", b"payload")],
        &sender,
        "device-a",
    )
    .expect("seals");
    let mut seen = HashSet::new();
    let error = open_operations(&batches[0], &receiver, &mut seen)
        .expect_err("another group's envelope must not open");
    match error {
        BatchError::Crypto(CryptoError::CrossGroup { got, expected }) => {
            assert_eq!(got, "group-a");
            assert_eq!(expected, "group-b");
        }
        other => panic!("expected CrossGroup, got: {other:?}"),
    }
}

#[test]
fn an_unknown_key_epoch_is_refused_without_guessing() {
    let key = [9u8; 32];
    let sender = KeyRing::with_epoch("group-1", 2, key);
    let receiver_stale = KeyRing::with_epoch("group-1", 1, key);

    let batches = seal_operations(
        &[put("device-a:1", "note/1", b"payload")],
        &sender,
        "device-a",
    )
    .expect("seals at epoch 2");
    assert_eq!(batches[0][0].key_epoch, 2);

    let mut seen = HashSet::new();
    let error = open_operations(&batches[0], &receiver_stale, &mut seen)
        .expect_err("an epoch this keyring lacks must not open");
    assert_eq!(error, BatchError::MissingKeyEpoch(2));
}

#[test]
fn redelivery_of_the_same_envelope_is_a_replay() {
    let keyring = KeyRing::new("group-1");
    let batches = seal_operations(
        &[put("device-a:1", "note/1", b"payload")],
        &keyring,
        "device-a",
    )
    .expect("seals");

    let mut seen = HashSet::new();
    open_operations(&batches[0], &keyring, &mut seen).expect("first delivery opens");
    let error = open_operations(&batches[0], &keyring, &mut seen)
        .expect_err("the same envelope delivered twice is a replay");
    match error {
        BatchError::Crypto(CryptoError::Replay(_)) => {}
        other => panic!("expected Replay, got: {other:?}"),
    }
}

#[test]
fn an_empty_log_ships_no_batches() {
    let keyring = KeyRing::new("group-1");
    let batches = seal_operations(&[], &keyring, "device-a").expect("empty input is fine");
    assert!(
        batches.is_empty(),
        "the relay rejects empty batches, so none ship"
    );
}

#[test]
fn rotation_keeps_old_envelopes_openable_and_new_ones_epoch_checked() {
    let key1 = [3u8; 32];
    let mut sender = KeyRing::with_epoch("group-1", 1, key1);
    let old_batches = seal_operations(&[put("device-a:1", "note/1", b"old")], &sender, "device-a")
        .expect("seals at epoch 1");

    // The sender rotates: the same keyring now holds epochs 1 and 2, and
    // new envelopes carry the new epoch.
    let (new_epoch, _new_key) = sender.rotate();
    assert_eq!(new_epoch, 2);
    let new_batches = seal_operations(&[put("device-a:2", "note/2", b"new")], &sender, "device-a")
        .expect("seals at epoch 2");
    assert_eq!(new_batches[0][0].key_epoch, 2);

    // The rotating device still opens its own epoch-1 history.
    let mut seen = HashSet::new();
    let reopened = open_operations(&old_batches[0], &sender, &mut seen).expect("old epoch opens");
    assert_eq!(reopened[0].payload, b"old");

    // A peer that missed the rotation opens the old envelope but gets a
    // typed refusal for the new one — never a guessed-key failure.
    let stale = KeyRing::with_epoch("group-1", 1, key1);
    let mut stale_seen = HashSet::new();
    let opened = open_operations(&old_batches[0], &stale, &mut stale_seen)
        .expect("the stale peer still holds epoch 1");
    assert_eq!(opened[0].payload, b"old");
    let error = open_operations(&new_batches[0], &stale, &mut stale_seen)
        .expect_err("the stale peer lacks epoch 2");
    assert_eq!(error, BatchError::MissingKeyEpoch(2));
}
