//! Data-integrity regressions for the default-server P0 blockers
//! (todo.md, DSR-01..DSR-06): persisted remote writes, forwarding with
//! original op ids, receive-path HLC advancement, persisted clock high-water,
//! order-independent LWW merge, and clock-skew policy.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use syncbond_core::conflict::{LwwHlc, MergeContext, MergeStrategy, Record};
use syncbond_core::hlc::{compare_stamps, HlcStamp};
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::replication::{decode_state, encode_state, Operation, Replicator};

fn stamp(pt: u64, ct: u64, id: &str) -> HlcStamp {
    HlcStamp {
        pt,
        ct,
        id: id.to_string(),
    }
}

fn wire_op(
    op_id: &str,
    key: &str,
    payload: &[u8],
    deleted: bool,
    own: HlcStamp,
    witness: HashMap<String, HlcStamp>,
) -> Operation {
    Operation {
        op_id: op_id.to_string(),
        key: key.to_string(),
        payload: payload.to_vec(),
        deleted,
        stamp: own,
        witness,
    }
}

/// A one-entry witness: the writer's own stamp (a writer always carries its
/// latest stamp).
fn own_witness(own: &HlcStamp) -> HashMap<String, HlcStamp> {
    HashMap::from([(own.id.clone(), own.clone())])
}

fn lww() -> Arc<LwwHlc> {
    Arc::new(LwwHlc)
}

// DSR-01: received remote put/delete operations must be persisted — they
// survive a snapshot/restore, tombstones included, and the restored dedup set
// still absorbs a replay of the same ops.
#[test]
fn remote_writes_and_dedup_survive_snapshot_and_restore() {
    let mut a = Replicator::with_fixed_clock("node-a", lww(), 1_000);
    let mut b = Replicator::with_fixed_clock("node-b", lww(), 1_000);

    let keep = a.put("keep", b"kept value".to_vec()).unwrap();
    let doc_put = a.put("doc", b"draft".to_vec()).unwrap();
    let doc_delete = a.delete("doc").unwrap();

    for op in [&keep, &doc_put, &doc_delete] {
        assert!(b.apply_remote(op).unwrap(), "the remote op must be applied");
    }
    assert_eq!(b.get("keep").unwrap().payload, b"kept value");
    assert!(
        b.get("doc").unwrap().deleted,
        "the received tombstone applies"
    );

    // Crash: snapshot, round-trip through storage, restore.
    let state = b.snapshot_state(&DeviceIdentity::generate(), "group-1", 1);
    let reloaded = decode_state(&encode_state(&state).unwrap()).unwrap();
    let mut restored =
        Replicator::from_state_with_clock(&reloaded, lww(), Arc::new(|| 1_000)).unwrap();

    assert_eq!(
        restored.get("keep").unwrap().payload,
        b"kept value",
        "the received value must survive the restart"
    );
    assert!(
        restored.get("doc").unwrap().deleted,
        "the received tombstone must survive the restart"
    );
    assert_eq!(restored.oplog().len(), 3, "every received op was persisted");
    // Dedup results survive with it: a replay of the same ops is a no-op.
    for op in [&keep, &doc_put, &doc_delete] {
        assert!(
            !restored.apply_remote(op).unwrap(),
            "re-applying a persisted remote op must be a no-op"
        );
    }
}

// DSR-02: forwarded ops keep the original op id (A -> B -> C), duplicate
// forwarding is idempotent, and B still forwards after a restart.
#[test]
fn forwarding_preserves_op_ids_and_survives_restart() {
    let mut a = Replicator::with_fixed_clock("node-a", lww(), 1_000);
    let mut b = Replicator::with_fixed_clock("node-b", lww(), 1_000);
    let mut c = Replicator::with_fixed_clock("node-c", lww(), 1_000);

    let origin = a.put("doc", b"from-a".to_vec()).unwrap();
    assert!(b.apply_remote(&origin).unwrap());

    // B forwards the op exactly as received: same op id, same stamp.
    let forwarded = b.oplog()[0].clone();
    assert_eq!(forwarded.op_id, origin.op_id, "the original op id is kept");
    assert_eq!(forwarded.stamp, origin.stamp, "the op is not re-stamped");

    assert!(c.apply_remote(&forwarded).unwrap());
    assert_eq!(c.get("doc").unwrap().payload, b"from-a");
    assert!(
        !c.apply_remote(&forwarded).unwrap(),
        "duplicate forwarding is idempotent"
    );

    // B restarts; the forwarded op is still in its oplog, still forwardable.
    let state = b.snapshot_state(&DeviceIdentity::generate(), "group-1", 1);
    let reloaded = decode_state(&encode_state(&state).unwrap()).unwrap();
    let b_restarted =
        Replicator::from_state_with_clock(&reloaded, lww(), Arc::new(|| 1_000)).unwrap();
    let after_restart = b_restarted.oplog()[0].clone();
    assert_eq!(after_restart.op_id, origin.op_id);

    let mut fresh = Replicator::with_fixed_clock("node-fresh", lww(), 1_000);
    assert!(fresh.apply_remote(&after_restart).unwrap());
    assert_eq!(fresh.get("doc").unwrap().payload, b"from-a");
    // C, which already saw the op, absorbs B's re-forward idempotently.
    assert!(!c.apply_remote(&after_restart).unwrap());
}

// DSR-03: receiving a legal remote stamp makes later local writes strict
// causal successors; a stamp beyond the skew bound is refused and leaves the
// local clock untouched.
#[test]
fn receive_path_advances_the_clock_within_skew_only() {
    let mut r = Replicator::with_fixed_clock("node-r", lww(), 1_000);
    let first = r.put("k", b"v1".to_vec()).unwrap();

    // A remote stamp within the skew bound is legal: the local clock adopts
    // it, so the next local write is a strict causal successor.
    let remote = wire_op(
        "node-s:1",
        "remote",
        b"seen",
        false,
        stamp(2_000, 0, "node-s"),
        own_witness(&stamp(2_000, 0, "node-s")),
    );
    assert!(r.apply_remote(&remote).unwrap());
    let successor = r.put("k", b"v2".to_vec()).unwrap();
    assert_eq!(
        compare_stamps(&successor.stamp, &remote.stamp),
        Ordering::Greater,
        "the next local write must causally follow the received stamp"
    );
    assert_eq!(
        compare_stamps(&successor.stamp, &first.stamp),
        Ordering::Greater
    );

    // A stamp an hour ahead (skew bound: 5 min) must not pollute the clock.
    let future = stamp(1_000 + 3_600_000, 5, "node-f");
    let future_op = wire_op(
        "node-f:1",
        "future",
        b"from the future",
        false,
        future.clone(),
        own_witness(&future),
    );
    assert!(r.apply_remote(&future_op).unwrap());
    let after_future = r.put("k", b"v3".to_vec()).unwrap();
    assert!(
        after_future.stamp.pt < future.pt,
        "a refused future stamp must not drag the local physical time, got {}",
        after_future.stamp.pt
    );
    assert_eq!(
        compare_stamps(&after_future.stamp, &successor.stamp),
        Ordering::Greater
    );
    // The future write itself was still applied and stays reachable.
    assert_eq!(r.get("future").unwrap().payload, b"from the future");
}

// DSR-04: restarting within the same wall-clock millisecond (a fixed clock
// makes every stamp "same-ms") never repeats a stamp.
#[test]
fn same_millisecond_restart_never_repeats_a_stamp() {
    let mut node = Replicator::with_fixed_clock("device-r", lww(), 10_000);
    let before = node.put("k", b"v1".to_vec()).unwrap();

    let state = node.snapshot_state(&DeviceIdentity::generate(), "group-1", 1);
    let reloaded = decode_state(&encode_state(&state).unwrap()).unwrap();
    let mut restarted =
        Replicator::from_state_with_clock(&reloaded, lww(), Arc::new(|| 10_000)).unwrap();
    let after = restarted.put("k", b"v2".to_vec()).unwrap();

    assert_ne!(after.stamp, before.stamp, "stamps must not repeat");
    assert_eq!(
        compare_stamps(&after.stamp, &before.stamp),
        Ordering::Greater,
        "the post-restart write stays a causal successor"
    );
    assert_eq!(restarted.get("k").unwrap().payload, b"v2");
}

// DSR-04: a wall-clock rollback after the snapshot cannot repeat a stamp —
// the restored high-water clamps the physical time.
#[test]
fn wall_clock_rollback_cannot_repeat_a_stamp() {
    let clock = Arc::new(AtomicU64::new(10_000));
    let mut node = Replicator::with_wall_clock(
        "device-rollback",
        lww(),
        Arc::new({
            let clock = Arc::clone(&clock);
            move || clock.load(AtomicOrdering::SeqCst)
        }),
    );
    let before = node.put("k", b"v1".to_vec()).unwrap();

    // The wall clock rolls back to 5_000 after the snapshot was taken at
    // 10_000 (NTP step, VM migration, dead CMOS battery).
    let state = node.snapshot_state(&DeviceIdentity::generate(), "group-1", 1);
    clock.store(5_000, AtomicOrdering::SeqCst);
    let reloaded = decode_state(&encode_state(&state).unwrap()).unwrap();
    let mut restarted = Replicator::from_state_with_clock(
        &reloaded,
        lww(),
        Arc::new({
            let clock = Arc::clone(&clock);
            move || clock.load(AtomicOrdering::SeqCst)
        }),
    )
    .unwrap();
    let after = restarted.put("k", b"v2".to_vec()).unwrap();

    assert_eq!(
        after.stamp.pt, before.stamp.pt,
        "the high-water holds the physical time above the rolled-back wall"
    );
    assert_eq!(
        compare_stamps(&after.stamp, &before.stamp),
        Ordering::Greater,
        "the counter advances past the pre-restart stamp"
    );
    assert_eq!(restarted.get("k").unwrap().payload, b"v2");
}

// DSR-04: a snapshot from an older build (no `clock` field) still restores —
// the high-water is re-derived from the persisted oplog.
#[test]
fn snapshots_without_the_clock_field_still_restore() {
    let mut node = Replicator::with_fixed_clock("device-legacy", lww(), 1_000);
    let before = node.put("k", b"v1".to_vec()).unwrap();
    assert_eq!((before.stamp.pt, before.stamp.ct), (1_000, 0));

    let state = node.snapshot_state(&DeviceIdentity::generate(), "group-1", 1);
    // Strip the clock field, as an older snapshot would have persisted it.
    // The value form decodes back through the same wire format.
    let mut json = serde_json::to_value(&state).unwrap();
    let round_trip = decode_state(&serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(
        round_trip.oplog, state.oplog,
        "oplog survives the value form"
    );
    assert_eq!(
        round_trip.clock, state.clock,
        "clock survives the value form"
    );
    json.as_object_mut().unwrap().remove("clock");
    let legacy = serde_json::to_vec(&json).unwrap();
    let stripped = decode_state(&legacy).unwrap();
    assert!(stripped.clock.is_none(), "the legacy snapshot has no clock");

    let mut restored =
        Replicator::from_state_with_clock(&stripped, lww(), Arc::new(|| 1_000)).unwrap();
    assert_eq!(restored.get("k").unwrap().payload, b"v1");
    let after = restored.put("k", b"v2".to_vec()).unwrap();
    assert_eq!(
        compare_stamps(&after.stamp, &before.stamp),
        Ordering::Greater,
        "the oplog-derived high-water keeps post-restore writes unique"
    );
}

// DSR-05: A writes at pt 1000, B at pt 900 having already observed A, and C
// writes independently at pt 950. Every delivery order of the three writes
// must converge to the same primary and the same normalized conflict set.
#[test]
fn independent_writes_converge_under_every_delivery_order() {
    let a = stamp(1_000, 0, "a");
    let b = stamp(900, 0, "b");
    let c = stamp(950, 0, "c");
    let op_a = wire_op("a:1", "k", b"A", false, a.clone(), own_witness(&a));
    let op_b = wire_op(
        "b:1",
        "k",
        b"B",
        false,
        b.clone(),
        HashMap::from([("b".to_string(), b.clone()), ("a".to_string(), a.clone())]),
    );
    let op_c = wire_op("c:1", "k", b"C", false, c.clone(), own_witness(&c));

    let orders = [
        [&op_a, &op_b, &op_c],
        [&op_a, &op_c, &op_b],
        [&op_b, &op_a, &op_c],
        [&op_b, &op_c, &op_a],
        [&op_c, &op_a, &op_b],
        [&op_c, &op_b, &op_a],
    ];
    for (i, order) in orders.iter().enumerate() {
        let mut replica = Replicator::with_fixed_clock(format!("probe-{i}"), lww(), 1_000);
        for op in order {
            replica.apply_remote(op).unwrap();
        }
        let record = replica.get("k").unwrap();
        assert_eq!(
            record.payload, b"C",
            "order {i}: the highest-stamp non-dominated survivor wins the primary"
        );
        assert_eq!(record.stamp, c, "order {i}: the primary stamp is canonical");
        assert_eq!(
            record.conflicts.len(),
            1,
            "order {i}: one normalized conflict: {record:?}"
        );
        assert_eq!(
            record.conflicts[0].stamp, b,
            "order {i}: the conflict set is the B write (A is dominated by B's witness)"
        );
        assert_eq!(record.conflicts[0].payload, b"B");
    }
}

// DSR-05, property face: deterministic LCG-generated multi-node writes on one
// key; every delivery permutation (plus one common trailing write) converges
// to the same primary and normalized conflict set.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 16
    }
}

fn absorb(witness: &mut HashMap<String, HlcStamp>, seen: &HlcStamp) {
    let newer = witness
        .get(&seen.id)
        .is_none_or(|held| compare_stamps(held, seen) != Ordering::Greater);
    if newer {
        witness.insert(seen.id.clone(), seen.clone());
    }
}

fn generated_writes(seed: u64, count: usize) -> Vec<Operation> {
    let mut rng = Lcg(seed);
    let nodes = ["n0", "n1", "n2", "n3", "n4"];
    let mut ops: Vec<Operation> = Vec::new();
    for i in 0..count {
        let node = nodes[(rng.next() % nodes.len() as u64) as usize];
        let own = stamp(900 + rng.next() % 400, i as u64, node);
        let mut witness = own_witness(&own);
        // Causal shape: the writer saw an arbitrary subset of earlier writes
        // (and, transitively, everything they saw).
        for earlier in &ops {
            if rng.next().is_multiple_of(3) {
                absorb(&mut witness, &earlier.stamp);
                for seen in earlier.witness.values() {
                    absorb(&mut witness, seen);
                }
            }
        }
        ops.push(wire_op(
            &format!("prop-{i}"),
            "k",
            &format!("op-{i}").into_bytes(),
            false,
            own,
            witness,
        ));
    }
    ops
}

/// All permutations of `items` (Heap's algorithm, `n!` results).
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    let mut current = items.to_vec();
    let mut out = vec![current.clone()];
    let n = current.len();
    let mut c = vec![0usize; n];
    let mut i = 0;
    while i < n {
        if c[i] < i {
            if i % 2 == 0 {
                current.swap(0, i);
            } else {
                current.swap(c[i], i);
            }
            out.push(current.clone());
            c[i] += 1;
            i = 0;
        } else {
            c[i] = 0;
            i += 1;
        }
    }
    out
}

#[test]
fn multi_node_permutation_convergence_property() {
    for seed in [0x00d5_0001u64, 0x00d5_0002, 0x00d5_0003] {
        let ops = generated_writes(seed, 7);
        let (shuffled, verifier) = ops.split_at(6);

        let mut expected: Option<(HlcStamp, Vec<u8>, Vec<HlcStamp>)> = None;
        for (n, order) in permutations(shuffled).into_iter().enumerate() {
            let mut replica =
                Replicator::with_fixed_clock(format!("probe-{seed}-{n}"), lww(), 1_000);
            for op in &order {
                replica.apply_remote(op).unwrap();
            }
            // A common trailing write exercises the merged record's witness
            // across differently-ordered merge histories.
            for op in verifier {
                replica.apply_remote(op).unwrap();
            }
            let record = replica.get("k").unwrap();
            let conflicts: Vec<HlcStamp> =
                record.conflicts.iter().map(|c| c.stamp.clone()).collect();
            let summary = (record.stamp.clone(), record.payload.clone(), conflicts);
            match &expected {
                None => expected = Some(summary),
                Some(expected) => {
                    assert_eq!(&summary, expected, "seed {seed}: permutation {n} diverged")
                }
            }
        }
        assert!(expected.is_some());
    }
}

// DSR-06: an anomalous future write leads to the same outcome whether it
// arrives before or after the normal write: the normal write stays primary,
// the future write stays retained and trackable, never silently overwriting.
#[test]
fn future_write_outcome_is_order_independent_and_trackable() {
    let normal_stamp = stamp(1_000, 0, "normal");
    let future_stamp = stamp(1_000 + 3_600_000, 0, "fast");
    let normal = wire_op(
        "normal:1",
        "k",
        b"normal",
        false,
        normal_stamp.clone(),
        own_witness(&normal_stamp),
    );
    let future = wire_op(
        "fast:1",
        "k",
        b"from the future",
        false,
        future_stamp.clone(),
        own_witness(&future_stamp),
    );

    let orders = [[&normal, &future], [&future, &normal]];
    for (i, order) in orders.iter().enumerate() {
        let mut replica = Replicator::with_fixed_clock(format!("probe-{i}"), lww(), 1_000);
        for op in order {
            replica.apply_remote(op).unwrap();
        }
        let record = replica.get("k").unwrap();
        assert_eq!(
            record.payload, b"normal",
            "order {i}: a run-ahead clock must not silently win"
        );
        assert_eq!(record.stamp, normal_stamp, "order {i}: same primary");
        assert_eq!(
            record.conflicts.len(),
            1,
            "order {i}: the future write stays retained: {record:?}"
        );
        assert_eq!(record.conflicts[0].stamp, future_stamp);
        assert_eq!(record.conflicts[0].payload, b"from the future");
    }
}

// DSR-06: the empty-record path runs the same skew policy — a future write
// is adopted (it is the only version) but flagged, not silently accepted as
// a normal write.
#[test]
fn empty_record_path_flags_a_future_write() {
    let ctx = MergeContext {
        now_ms: 1_000,
        max_skew_ms: 300_000,
    };
    let future_stamp = stamp(1_000 + 3_600_000, 0, "fast");
    let future = Record::new(
        "k",
        b"from the future".to_vec(),
        false,
        future_stamp.clone(),
        own_witness(&future_stamp),
    );
    let outcome = LwwHlc.merge(None, &future, &ctx).unwrap();
    assert!(
        outcome.skew_detected,
        "the empty-record path must flag an anomalous future stamp"
    );
    assert_eq!(outcome.record.payload, b"from the future");
    assert!(!outcome.concurrent);

    let normal_stamp = stamp(1_000, 0, "normal");
    let normal = Record::new(
        "k",
        b"normal".to_vec(),
        false,
        normal_stamp.clone(),
        own_witness(&normal_stamp),
    );
    let outcome = LwwHlc.merge(None, &normal, &ctx).unwrap();
    assert!(!outcome.skew_detected, "a legal stamp is not flagged");
}
