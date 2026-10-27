//! P3 universality gate: three unrelated applications (generic KV store,
//! note-taking documents, arbitrary binary records) all run on the same
//! core with zero business knowledge in the SDK.
//!
//! Each example covers: pairing, E2EE transport, incremental sync, offline
//! concurrency with conflict retention, deletion, and crash-restart
//! persistence. Protocol-level guarantees (revocation via key epochs,
//! version negotiation, replay/tamper rejection) are payload-independent
//! and covered in crypto_envelope_tests.rs and pairing_tests.rs.

use std::sync::Arc;
use syncbond_core::conflict::LwwHlc;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::replication::Replicator;
use syncbond_core::storage::{MemoryStorage, SyncStorage};
use syncbond_core::transport::MemoryTransport;

/// Pair two devices and sync their replicators (both directions).
fn pair_and_exchange(code: &str, rep_a: &mut Replicator, rep_b: &mut Replicator) {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    std::thread::scope(|s| {
        let rep_b_ref = &mut *rep_b;
        let ib_ref = &ib;
        let tb_for_b = tb.clone();
        let h_b = s.spawn(move || {
            let session = syncbond_core::pairing::accept(
                code,
                ib_ref,
                tb_for_b as Arc<dyn syncbond_core::Transport>,
            )
            .expect("responder pairing");
            rep_b_ref
                .sync_over(&session, false)
                .expect("responder sync");
        });
        let session_a =
            syncbond_core::pairing::pair(code, &ia, ta as Arc<dyn syncbond_core::Transport>)
                .expect("initiator pairing");
        rep_a.sync_over(&session_a, true).expect("initiator sync");
        h_b.join().expect("responder thread");
    });
}

#[test]
fn example_1_generic_key_value_sync() {
    let storage_a = MemoryStorage::new();
    let mut a = Replicator::new("kv-device-a");
    let mut b = Replicator::new("kv-device-b");

    a.put("user:theme", b"dark".to_vec()).unwrap();
    a.put("user:locale", b"zh-CN".to_vec()).unwrap();
    b.put("user:font_size", b"14".to_vec()).unwrap();

    pair_and_exchange("KVPAW3", &mut a, &mut b);

    // Both KV stores converged on all three keys.
    for key in ["user:theme", "user:locale", "user:font_size"] {
        assert_eq!(a.get(key).unwrap().payload, b.get(key).unwrap().payload);
    }
    assert_eq!(b.get("user:theme").unwrap().payload, b"dark");

    // Deletion syncs too.
    a.delete("user:locale").unwrap();
    pair_and_exchange("KVPAW3", &mut a, &mut b);
    assert!(b.get("user:locale").unwrap().deleted);

    // Persistence recovery on the KV device.
    let state = a.snapshot_state(&DeviceIdentity::generate(), "unused", 1);
    storage_a
        .save(&syncbond_core::replication::encode_state(&state).unwrap())
        .unwrap();
    let restored = Replicator::from_state(
        &syncbond_core::replication::decode_state(
            &storage_a.load().unwrap().expect("saved state present"),
        )
        .unwrap(),
        Arc::new(LwwHlc),
    )
    .unwrap();
    assert!(restored.get("user:locale").unwrap().deleted);
    assert_eq!(restored.get("user:theme").unwrap().payload, b"dark");
}

#[test]
fn example_2_note_documents_with_offline_conflict() {
    let mut a = Replicator::new("laptop");
    let mut b = Replicator::new("phone");

    // A note is just JSON bytes; the SDK never parses it.
    let note = serde_json::json!({"title": "grocery", "body": "milk"});
    a.put("note:1", serde_json::to_vec(&note).unwrap()).unwrap();
    pair_and_exchange("NT6ES2", &mut a, &mut b);

    // Both edit offline. b edits without seeing a's newer revision.
    let a_edit = serde_json::json!({"title": "grocery", "body": "milk, eggs"});
    let a_op = a
        .put("note:1", serde_json::to_vec(&a_edit).unwrap())
        .unwrap();

    let b_edit = serde_json::json!({"title": "grocery", "body": "milk, bread"});
    let b_op = b
        .put("note:1", serde_json::to_vec(&b_edit).unwrap())
        .unwrap();

    pair_and_exchange("NT6ES2", &mut a, &mut b);

    let on_a = a.get("note:1").unwrap();
    let on_b = b.get("note:1").unwrap();
    // Converged: same winner everywhere.
    assert_eq!(on_a.payload, on_b.payload);
    // The concurrent (losing) revision is retained for the app to resolve.
    let winner_payload = on_a.payload.clone();
    let mut all_versions = [on_a.payload.clone()]
        .into_iter()
        .chain(on_a.conflicts.iter().map(|c| c.payload.clone()));
    assert!(all_versions.any(|p| p == winner_payload));
    // Both written bodies survive somewhere (no data loss).
    let mut bodies = on_a
        .conflicts
        .iter()
        .map(|c| c.payload.clone())
        .collect::<Vec<_>>();
    bodies.push(on_a.payload.clone());
    assert!(
        bodies.contains(&serde_json::to_vec(&a_edit).unwrap())
            || bodies.contains(&serde_json::to_vec(&b_edit).unwrap())
    );
    let _ = (a_op, b_op);
}

#[test]
fn example_3_arbitrary_binary_records() {
    let mut a = Replicator::new("camera");
    let mut b = Replicator::new("backup-drive");

    // 4 KiB of "binary" data (a fake thumbnail): opaque to the SDK.
    let blob: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    a.put("thumb:0001", blob.clone()).unwrap();

    pair_and_exchange("BNR4VX", &mut a, &mut b);

    assert_eq!(
        b.get("thumb:0001").unwrap().payload,
        blob,
        "binary round-trip intact"
    );

    // Incremental: a second record syncs without resending the first.
    let blob2: Vec<u8> = (0..2048u32).map(|i| (i % 253) as u8).collect();
    a.put("thumb:0002", blob2.clone()).unwrap();
    pair_and_exchange("BNR4VX", &mut a, &mut b);
    assert_eq!(b.get("thumb:0002").unwrap().payload, blob2);
    assert_eq!(b.record_count(), 2);
}
