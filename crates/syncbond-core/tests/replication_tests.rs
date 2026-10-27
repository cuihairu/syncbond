//! Replication correctness: convergence under out-of-order and duplicate
//! delivery, causality (deletes never resurrect), clock-skew safety,
//! pluggable strategies (OR-Set, PN-Counter), and crash-restart persistence.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use syncbond_core::conflict::{LwwHlc, OrSetDoc, OrSetStrategy, PnCounterDoc, PnCounterStrategy};
use syncbond_core::hlc::HlcStamp;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::relay::{apply_pull_response, MemoryRelayStore, PullRequest, RelayStore};
use syncbond_core::replication::{decode_state, encode_state, Operation, Replicator};
use syncbond_core::storage::{MemoryStorage, SyncStorage};

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[test]
fn causally_newer_write_wins_on_both_replicas() {
    let mut a = Replicator::new("node-a");
    let mut b = Replicator::new("node-b");

    let op1 = a.put("k", b"v1".to_vec()).unwrap();
    b.apply_remote(&op1).unwrap(); // b sees v1, then edits on top of it

    let op2 = b.put("k", b"v2".to_vec()).unwrap();
    a.apply_remote(&op2).unwrap(); // v2 causally follows v1: it wins everywhere

    assert_eq!(a.get("k").unwrap().payload, b"v2");
    assert_eq!(b.get("k").unwrap().payload, b"v2");
}

#[test]
fn out_of_order_and_duplicate_delivery_converge() {
    let mut a = Replicator::new("node-a");
    let mut b = Replicator::new("node-b");
    let ops: Vec<_> = (0..5)
        .map(|i| {
            a.put(format!("k{i}"), format!("v{i}").into_bytes())
                .unwrap()
        })
        .collect();

    // Deliver shuffled, with duplicates; duplicates are no-ops.
    let shuffled = [3usize, 0, 4, 0, 2, 1, 3, 2, 4, 1];
    for &i in &shuffled {
        let _ = b.apply_remote(&ops[i]).unwrap();
    }
    let snapshot: Vec<Vec<u8>> = (0..5)
        .map(|i| b.get(&format!("k{i}")).unwrap().payload.clone())
        .collect();
    assert_eq!(
        snapshot,
        (0..5)
            .map(|i| format!("v{i}").into_bytes())
            .collect::<Vec<_>>()
    );

    // A full second replay is a no-op everywhere.
    let applied: Vec<bool> = ops.iter().map(|op| b.apply_remote(op).unwrap()).collect();
    assert!(
        applied.iter().all(|applied| !applied),
        "duplicates must be no-ops"
    );
    let snapshot2: Vec<Vec<u8>> = (0..5)
        .map(|i| b.get(&format!("k{i}")).unwrap().payload.clone())
        .collect();
    assert_eq!(snapshot, snapshot2);
}

#[test]
fn old_device_reconnect_cannot_resurrect_a_delete() {
    let mut a = Replicator::with_fixed_clock("device-a", Arc::new(LwwHlc), 1_000);
    let mut stale = Replicator::with_fixed_clock("device-stale", Arc::new(LwwHlc), 1_000);

    let created = a.put("doc", b"v1".to_vec()).unwrap();
    stale.apply_remote(&created).unwrap();

    // a deletes; the stale device misses the tombstone and edits offline.
    let tombstone = a.delete("doc").unwrap();
    let offline_edit = stale.put("doc", b"stale edit".to_vec()).unwrap();

    // Tombstone and offline edit are concurrent: the edit is retained for
    // the application, but on the stale side the tombstone is causally
    // newer and must win once delivered.
    a.apply_remote(&offline_edit).unwrap();
    let after_merge = a.get("doc").unwrap();
    assert!(
        after_merge.deleted || after_merge.conflicts.iter().any(|c| c.deleted),
        "the delete must be retained (primary or in conflicts), got: {after_merge:?}",
    );

    stale.apply_remote(&tombstone).unwrap();
    assert!(
        stale.get("doc").unwrap().deleted,
        "old device must not resurrect the deleted record",
    );
    // Re-delivering everything (idempotent) keeps it deleted.
    stale.apply_remote(&offline_edit).unwrap();
    assert!(stale.get("doc").unwrap().deleted);
}

#[test]
fn large_clock_skew_does_not_silently_overwrite() {
    let mut normal = Replicator::new("node-normal");
    let seed = normal.put("k", b"seed".to_vec()).unwrap();
    let local = normal.put("k", b"local-value".to_vec()).unwrap();
    assert!(
        local.stamp.pt > seed.stamp.pt || local.stamp.ct == seed.stamp.ct + 1,
        "the HLC must advance monotonically, seed={seed:?}, local={local:?}"
    );

    // A device with a run-ahead clock (+1h) writes concurrently.
    let op = Operation {
        op_id: "node-fast:1".to_string(),
        key: "k".to_string(),
        payload: b"from-fast-clock".to_vec(),
        deleted: false,
        stamp: HlcStamp {
            pt: wall_ms() + 3_600_000,
            ct: 1,
            id: "node-fast".to_string(),
        },
        witness: HashMap::from([(
            "node-fast".to_string(),
            HlcStamp {
                pt: wall_ms() + 3_600_000,
                ct: 1,
                id: "node-fast".to_string(),
            },
        )]),
    };
    assert!(normal.apply_remote(&op).unwrap());

    let record = normal.get("k").unwrap();
    assert_eq!(
        record.payload, b"local-value",
        "run-ahead write must not silently win"
    );
    assert!(
        record
            .conflicts
            .iter()
            .any(|c| c.payload == b"from-fast-clock"),
        "the skewed write must be retained for the application"
    );
}

#[test]
fn or_set_concurrent_add_wins_over_remove() {
    let strategy = Arc::new(OrSetStrategy);
    let mut a = Replicator::with_strategy("node-a", strategy.clone());
    let mut b = Replicator::with_strategy("node-b", strategy);

    let doc = OrSetDoc {
        adds: HashMap::from([("fav:42".to_string(), vec!["node-a:0".to_string()])]),
        rems: vec![],
    };
    a.put("favorites", OrSetStrategy::encode(&doc)).unwrap();

    // a removes (observing tag node-a:0); b concurrently re-adds with a tag
    // the remover never observed.
    let removed = OrSetDoc {
        adds: doc.adds.clone(),
        rems: vec!["node-a:0".to_string()],
    };
    let op_remove = a.put("favorites", OrSetStrategy::encode(&removed)).unwrap();
    let added = OrSetDoc {
        adds: HashMap::from([("fav:42".to_string(), vec!["node-b:0".to_string()])]),
        rems: vec![],
    };
    let op_add = b.put("favorites", OrSetStrategy::encode(&added)).unwrap();

    a.apply_remote(&op_add).unwrap();
    b.apply_remote(&op_remove).unwrap();

    let merged_a = OrSetStrategy::decode(&a.get("favorites").unwrap().payload).unwrap();
    let merged_b = OrSetStrategy::decode(&b.get("favorites").unwrap().payload).unwrap();
    assert!(
        OrSetStrategy::live(&merged_a).contains(&"fav:42".to_string()),
        "concurrent add must win over the observed-remove"
    );
    assert_eq!(
        a.get("favorites").unwrap().payload,
        b.get("favorites").unwrap().payload,
        "both replicas must hold the same canonical bytes"
    );
    assert_eq!(
        OrSetStrategy::live(&merged_a),
        OrSetStrategy::live(&merged_b),
        "both replicas converge on the same live set, in the same order"
    );
}

#[test]
fn pn_counter_merges_by_per_node_max() {
    let strategy = Arc::new(PnCounterStrategy);
    let mut a = Replicator::with_strategy("node-a", strategy.clone());
    let mut b = Replicator::with_strategy("node-b", strategy);

    let mut doc_a = PnCounterDoc::default();
    doc_a.p.insert("node-a".into(), 3);
    a.put("counter", PnCounterStrategy::encode(&doc_a)).unwrap();

    let mut doc_b = PnCounterDoc::default();
    doc_b.n.insert("node-b".into(), 1);
    let op_b = b.put("counter", PnCounterStrategy::encode(&doc_b)).unwrap();

    let op_a = a.put("counter", PnCounterStrategy::encode(&doc_a)).unwrap();
    a.apply_remote(&op_b).unwrap();
    b.apply_remote(&op_a).unwrap();

    let merged_a = PnCounterStrategy::decode(&a.get("counter").unwrap().payload).unwrap();
    let merged_b = PnCounterStrategy::decode(&b.get("counter").unwrap().payload).unwrap();
    assert_eq!(PnCounterStrategy::value(&merged_a), 2);
    assert_eq!(PnCounterStrategy::value(&merged_b), 2);
    assert_eq!(
        a.get("counter").unwrap().payload,
        b.get("counter").unwrap().payload,
        "both replicas must hold the same canonical bytes"
    );
}

#[test]
fn crash_restart_restores_identity_cursor_and_oplog() {
    let storage = MemoryStorage::new();
    let identity = DeviceIdentity::generate();

    let mut node = Replicator::new("device-x");
    node.put("k1", b"v1".to_vec()).unwrap();
    node.put("k2", b"v2".to_vec()).unwrap();
    node.delete("k1").unwrap();
    let cursor_before = node.cursor();

    let state = node.snapshot_state(&identity, "group-1", 1);
    storage.save(&encode_state(&state).unwrap()).unwrap();

    // "Crash": rebuild everything from storage.
    let loaded = decode_state(&storage.load().unwrap().unwrap()).unwrap();
    assert_eq!(loaded.identity.device_id, identity.device_id);
    assert_eq!(loaded.identity.public_key, identity.public_key);
    assert_eq!(loaded.group_id, "group-1");
    assert_eq!(loaded.key_epoch, 1);

    let mut restored =
        Replicator::from_state(&loaded, Arc::new(syncbond_core::conflict::LwwHlc)).unwrap();
    assert_eq!(restored.cursor(), cursor_before, "cursor survives");
    assert_eq!(restored.oplog().len(), 3, "oplog survives");
    assert!(restored.get("k1").unwrap().deleted, "tombstone survives");
    assert_eq!(restored.get("k2").unwrap().payload, b"v2");

    // New writes continue the cursor without collision.

    let op = restored.put("k3", b"v3".to_vec()).unwrap();
    assert_eq!(op.op_id, format!("device-x:{}", cursor_before + 1));
}

#[test]
fn reconnecting_relay_client_resumes_after_cursor_without_duplicates() {
    let relay = MemoryRelayStore::new();
    let mut writer = Replicator::new("writer");
    let mut reconnecting = Replicator::new("reconnecting");

    let online_op = writer.put("online", b"one".to_vec()).unwrap();
    relay.append("channel", &online_op).unwrap();

    let response = relay.pull_after("channel", 0).unwrap();
    assert_eq!(
        apply_pull_response(&mut reconnecting, &response).unwrap(),
        1
    );
    assert_eq!(reconnecting.get("online").unwrap().payload, b"one");
    assert_eq!(reconnecting.cursor(), 0);

    // The endpoint goes offline, persists the relay cursor separately, and
    // returns after more writes.
    let relay_cursor = response.after;
    let state = reconnecting.snapshot_state(&DeviceIdentity::generate(), "group", 1);
    let mut restored = Replicator::from_state(
        &decode_state(&encode_state(&state).unwrap()).unwrap(),
        Arc::new(syncbond_core::conflict::LwwHlc),
    )
    .unwrap();

    let offline_ops = [
        writer.put("offline-1", b"two".to_vec()).unwrap(),
        writer.delete("online").unwrap(),
        writer.put("offline-2", b"three".to_vec()).unwrap(),
    ];
    for operation in &offline_ops {
        relay.append("channel", operation).unwrap();
    }

    let request = PullRequest {
        channel: "channel".to_string(),
        after: relay_cursor,
    };
    let response = relay.pull_after(&request.channel, request.after).unwrap();
    assert_eq!(response.ops.len(), 3);
    assert_eq!(apply_pull_response(&mut restored, &response).unwrap(), 3);

    assert!(restored.get("online").unwrap().deleted);
    assert_eq!(restored.get("offline-1").unwrap().payload, b"two");
    assert_eq!(restored.get("offline-2").unwrap().payload, b"three");

    // Relay redelivery must remain idempotent.
    let replay = relay.pull_after(&request.channel, response.after).unwrap();
    assert_eq!(apply_pull_response(&mut restored, &replay).unwrap(), 0);
    assert_eq!(restored.record_count(), 3);
}

#[test]
fn malformed_strategy_payloads_error_instead_of_panicking() {
    // A malformed OR-Set payload must surface as an explicit merge error (the
    // binding maps it to a stable error code) rather than panicking inside the
    // strategy decode, so cross-language behavior stays uniform.
    let mut or_set = Replicator::with_strategy("or-set", Arc::new(OrSetStrategy));
    let err = or_set.put("k", b"not-json".to_vec());
    assert!(
        err.is_err(),
        "malformed OR-Set payload must be rejected, not panic"
    );
    assert_eq!(
        or_set.record_count(),
        0,
        "rejected write must not be stored"
    );

    let mut pn = Replicator::with_strategy("pn-counter", Arc::new(PnCounterStrategy));
    let err = pn.put("k", b"{} garbage".to_vec());
    assert!(
        err.is_err(),
        "malformed PN-Counter payload must be rejected, not panic"
    );
    assert_eq!(pn.record_count(), 0, "rejected write must not be stored");

    // A malformed remote payload arriving over apply_remote is rejected the
    // same way: explicit error, no panic, no partial local state.
    let mut receiver = Replicator::with_strategy("receiver", Arc::new(OrSetStrategy));
    let mut sender = Replicator::with_strategy("sender", Arc::new(OrSetStrategy));
    let valid = OrSetDoc {
        adds: HashMap::from([("x".to_string(), vec!["sender:0".to_string()])]),
        rems: Vec::new(),
    };
    sender.put("k", OrSetStrategy::encode(&valid)).unwrap();
    let remote_op = sender.oplog()[0].clone();
    assert!(receiver.apply_remote(&remote_op).is_ok());
    let malformed = Operation {
        op_id: "sender:99".to_string(),
        key: "k".to_string(),
        payload: b"not-json".to_vec(),
        deleted: false,
        stamp: remote_op.stamp.clone(),
        witness: remote_op.witness.clone(),
    };
    assert!(
        receiver.apply_remote(&malformed).is_err(),
        "malformed remote payload must return an explicit error"
    );
    assert_eq!(
        receiver.record_count(),
        1,
        "valid write survives the rejected op"
    );
}
