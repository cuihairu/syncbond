//! Tombstone GC: collection needs both the time threshold and causal
//! dominance, the compaction keeps the causal barrier (so a pre-delete write
//! redelivered after GC cannot resurrect the delete), the compacted state
//! survives a restart, and a compacted peer converges with an uncompacted one.

use std::sync::Arc;
use syncbond_core::conflict::LwwHlc;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::replication::{decode_state, encode_state, Operation, Replicator};

fn node(id: &str) -> Replicator {
    Replicator::with_fixed_clock(id, 1_000)
}

/// Exchange oplogs in both directions (the unencrypted sync half).
fn exchange(a: &mut Replicator, b: &mut Replicator) {
    let a_ops = a.oplog().to_vec();
    let b_ops = b.oplog().to_vec();
    for op in &a_ops {
        let _ = b.apply_remote(op);
    }
    for op in &b_ops {
        let _ = a.apply_remote(op);
    }
}

/// a creates k, b edits offline, a deletes, then b catches up and reports
/// back — the point where a has evidence for every known replica.
fn tombstoned_with_evidence() -> (Replicator, Replicator, Operation) {
    let mut a = node("node-a");
    let mut b = node("node-b");
    let created = a.put("k", b"value".to_vec());
    let stale = b.put("k", b"offline edit".to_vec());
    a.apply_remote(&stale);
    let tombstone = a.delete("k");
    b.apply_remote(&created);
    b.apply_remote(&tombstone);
    let echo = b.put("hb", b"echo".to_vec());
    a.apply_remote(&echo);
    (a, b, stale)
}

#[test]
fn gc_collects_tombstones_after_the_threshold_when_every_replica_saw_the_delete() {
    let (mut a, _b, _stale) = tombstoned_with_evidence();

    let report = a.gc_tombstones(1_000, 0);
    assert_eq!(report.scanned, 1);
    assert_eq!(report.collected, vec!["k".to_string()]);
    assert_eq!(
        report.oplog_entries_removed, 2,
        "pre-delete history collapses to one op"
    );
    assert!(
        a.get("k").is_none(),
        "the tombstone record itself is dropped"
    );
    assert!(
        a.gc_barriers().contains_key("k"),
        "the causal barrier must survive the collection"
    );
    assert_eq!(a.live_keys(), vec!["hb".to_string()]);
}

#[test]
fn gc_refuses_to_collect_without_dominance_evidence() {
    let mut a = node("node-a");
    let mut b = node("node-b");
    let created = a.put("k", b"value".to_vec());
    let stale = b.put("k", b"offline".to_vec());
    a.apply_remote(&stale);
    a.delete("k");
    b.apply_remote(&created); // b knows the write, not the delete

    let report = a.gc_tombstones(1_000, 0);
    assert_eq!(report.scanned, 1);
    assert!(
        report.collected.is_empty(),
        "b has not been seen past the delete, so collection must wait"
    );
    assert!(a.get("k").unwrap().deleted);
    assert!(a.gc_barriers().is_empty());
}

#[test]
fn gc_refuses_before_the_time_threshold() {
    let (mut a, _b, _stale) = tombstoned_with_evidence();

    let report = a.gc_tombstones(1_000, 1);
    assert_eq!(report.scanned, 1);
    assert!(
        report.collected.is_empty(),
        "the tombstone is not old enough"
    );
    assert!(a.get("k").unwrap().deleted);
}

#[test]
fn stale_put_cannot_resurrect_a_collected_delete() {
    let (mut a, _b, stale) = tombstoned_with_evidence();
    a.gc_tombstones(1_000, 0);

    assert!(
        !a.apply_remote(&stale),
        "the pre-delete write must be rejected"
    );
    assert!(a.get("k").is_none(), "no resurrection");
    // Redelivery is rejected the same way, not lost in a confusing state.
    assert!(!a.apply_remote(&stale));
    assert!(a.get("k").is_none());
    assert!(a.gc_barriers().contains_key("k"));
}

#[test]
fn gc_compacts_the_oplog_and_survives_a_restart() {
    let (mut a, _b, stale) = tombstoned_with_evidence();
    a.gc_tombstones(1_000, 0);
    let entries = a.oplog().iter().filter(|op| op.key == "k").count();
    assert_eq!(entries, 1, "the key keeps only its tombstone op");

    let identity = DeviceIdentity::generate();
    let state = a.snapshot_state(&identity, "group-1", 1);
    let loaded = decode_state(&encode_state(&state).unwrap()).unwrap();

    let mut restored = Replicator::from_state(&loaded, Arc::new(LwwHlc));
    assert!(
        restored.gc_barriers().contains_key("k"),
        "barrier survives reload"
    );
    assert!(restored.get("k").is_none());
    assert!(!restored.apply_remote(&stale));
    assert!(restored.get("k").is_none());
}

#[test]
fn compacted_peer_converges_with_an_uncompacted_peer() {
    let (mut a, mut b, _stale) = tombstoned_with_evidence();
    a.gc_tombstones(1_000, 0);

    // b still holds the full history (payload-bearing tombstone); a only the
    // compacted barrier. Live keys unrelated to k must keep flowing.
    b.put("keep", b"still here".to_vec());
    exchange(&mut a, &mut b);

    assert!(
        a.get("k").is_none(),
        "a must not resurrect k from b's history"
    );
    assert!(
        b.get("k").unwrap().deleted,
        "b must learn about the collected delete"
    );
    assert_eq!(a.get("keep").unwrap().payload, b"still here");
    assert_eq!(a.live_keys(), vec!["hb".to_string(), "keep".to_string()]);
    assert_eq!(b.live_keys(), vec!["hb".to_string(), "keep".to_string()]);
}

#[test]
fn recreate_after_gc_propagates_everywhere() {
    let (mut a, mut b, _stale) = tombstoned_with_evidence();
    a.gc_tombstones(1_000, 0);

    // The application deletes and then recreates the key.
    a.put("k", b"recreated".to_vec());
    exchange(&mut a, &mut b);

    assert_eq!(a.get("k").unwrap().payload, b"recreated");
    assert_eq!(b.get("k").unwrap().payload, b"recreated");
}

#[test]
fn gc_is_idempotent() {
    let (mut a, _b, _stale) = tombstoned_with_evidence();
    assert_eq!(a.gc_tombstones(1_000, 0).collected.len(), 1);
    assert_eq!(a.gc_tombstones(1_000, 0).collected.len(), 0);
}
