//! State snapshot tests (todo.md DSR-35): the replicator's committed state
//! and the receive cursors round-trip as one versioned blob, a wrong version
//! or a malformed blob is refused before any handle is touched, and a restore
//! loses no remote data that was already committed.

use syncbond_ffi::error::{
    SB_ERR_INPUT, SB_ERR_VERSION_MISMATCH, SB_STATE_SNAPSHOT_VERSION, SB_STRATEGY_LWW_HLC,
};
use syncbond_ffi::handles::{import_snapshot, Identity, ReceiveState, Replicator};

const GROUP: &str = "group-9";

fn receive_with(server: &str, channel: &str, seq: u64, seen: &[&str]) -> ReceiveState {
    let mut state = ReceiveState::new();
    state.set_server_cursor(server, channel, seq).unwrap();
    for id in seen {
        state.mark_seen(id).unwrap();
    }
    state
}

#[test]
fn a_snapshot_round_trips_the_committed_state_and_cursors() {
    let identity = Identity::generate();
    let mut replicator = Replicator::new_clock("node-a", SB_STRATEGY_LWW_HLC, 1000).unwrap();
    replicator.put("note/1", b"hello").unwrap();
    replicator.put("note/2", b"world").unwrap();
    replicator.delete("note/1").unwrap(); // a tombstone survives the trip too

    let mut receive = receive_with("relay-1", "channel-a", 17, &["msg-1", "msg-2"]);
    receive
        .set_server_cursor("relay-1", "channel-b", 4)
        .unwrap();
    receive.set_source_cursor("node-b", 11).unwrap();
    receive.mark_seen("msg-3").unwrap();

    let blob = replicator
        .export_snapshot(&identity, GROUP, 3, &receive)
        .unwrap();
    assert!(!blob.is_empty());

    let (restored, restored_receive) = import_snapshot(&blob, SB_STRATEGY_LWW_HLC).unwrap();
    assert_eq!(restored.node_id(), "node-a");
    assert_eq!(restored.record_count(), replicator.record_count());
    assert_eq!(restored.oplog_len(), replicator.oplog_len());
    assert_eq!(restored.records_json(), replicator.records_json());
    assert_eq!(restored.gc_barriers_json(), replicator.gc_barriers_json());
    assert_eq!(restored.get("note/1"), None, "the tombstone stays dead");
    assert_eq!(restored.get("note/2"), Some(b"world".to_vec()));

    // The receive position is byte-identical, so a restart asks for exactly
    // the same pull positions.
    assert_eq!(restored_receive.json(), receive.json());
    assert_eq!(
        restored_receive.server_seq("relay-1", "channel-a"),
        Some(17)
    );
    assert_eq!(restored_receive.server_seq("relay-1", "channel-b"), Some(4));
    assert_eq!(restored_receive.server_seq("relay-1", "channel-c"), None);
    assert!(restored_receive.seen("msg-1") && restored_receive.seen("msg-3"));
}

#[test]
fn a_restore_loses_no_remote_data_it_already_committed() {
    let identity = Identity::generate();
    let mut local = Replicator::new_clock("node-a", SB_STRATEGY_LWW_HLC, 1000).unwrap();
    let mut remote = Replicator::new_clock("node-b", SB_STRATEGY_LWW_HLC, 2000).unwrap();
    remote.put("note/1", b"from b").unwrap();
    remote.put("note/2", b"also b").unwrap();
    for index in 0..2 {
        let op = remote.op_json(index).unwrap();
        assert!(local.apply_remote_json(&op).unwrap(), "{op}");
    }

    let receive = receive_with("relay-1", "channel-a", 2, &["msg-1"]);
    let blob = local
        .export_snapshot(&identity, GROUP, 1, &receive)
        .unwrap();
    let (mut restored, restored_receive) = import_snapshot(&blob, SB_STRATEGY_LWW_HLC).unwrap();

    // Both remote records survived the restart...
    assert_eq!(restored.record_count(), 2);
    assert_eq!(restored.get("note/1"), Some(b"from b".to_vec()));
    assert_eq!(restored.get("note/2"), Some(b"also b".to_vec()));
    // ...the pull position still points past what was committed...
    assert_eq!(restored_receive.server_seq("relay-1", "channel-a"), Some(2));
    // ...so a redelivery of an already-seen op stays a no-op, and nothing is
    // re-requested or re-applied.
    assert!(
        !restored
            .apply_remote_json(&remote.op_json(0).unwrap())
            .unwrap(),
        "the seen op is still deduplicated"
    );
    assert_eq!(restored_receive.server_seq("relay-1", "channel-a"), Some(2));
}

#[test]
fn a_snapshot_carries_the_group_facts_the_restored_device_needs() {
    let identity = Identity::generate();
    let replicator = Replicator::new_clock("node-a", SB_STRATEGY_LWW_HLC, 1000).unwrap();
    let blob = replicator
        .export_snapshot(&identity, GROUP, 7, &ReceiveState::new())
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&blob).unwrap();
    assert_eq!(parsed["version"], SB_STATE_SNAPSHOT_VERSION);
    assert_eq!(parsed["state"]["node_id"], "node-a");
    assert_eq!(parsed["state"]["group_id"], GROUP);
    assert_eq!(parsed["state"]["key_epoch"], 7);
}

#[test]
fn the_snapshot_embeds_the_identity_secret_so_it_is_private_material() {
    let identity = Identity::generate();
    let replicator = Replicator::new_clock("node-a", SB_STRATEGY_LWW_HLC, 1000).unwrap();
    let blob = replicator
        .export_snapshot(&identity, GROUP, 1, &ReceiveState::new())
        .unwrap();
    // The warning in the header is not decorative: the blob really does carry
    // the device's signing secret in a recoverable form.
    let parsed: serde_json::Value = serde_json::from_slice(&blob).unwrap();
    let secret_hex = parsed["state"]["identity"]["secret_key"]
        .as_str()
        .expect("secret key serialized as a hex string");
    let secret = hex_decode(secret_hex);
    assert_eq!(secret, identity.secret_key().to_vec());
}

#[test]
fn a_snapshot_from_another_version_is_refused() {
    let blob = format!(
        r#"{{"version": {}, "state": {{}}, "receive": {{}}}}"#,
        SB_STATE_SNAPSHOT_VERSION + 1
    );
    let error = import_snapshot(blob.as_bytes(), SB_STRATEGY_LWW_HLC)
        .err()
        .unwrap();
    assert_eq!(error.code, SB_ERR_VERSION_MISMATCH);
}

#[test]
fn a_malformed_snapshot_fails_closed() {
    let cases: &[&[u8]] = &[
        b"",
        b"not json",
        b"{}",
        b"{\"version\":1}",
        b"{\"version\":1,\"receive\":{}}",
        b"{\"version\":1,\"state\":{}}",
        b"{\"version\":\"one\",\"state\":{},\"receive\":{}}",
    ];
    for case in cases {
        let error = import_snapshot(case, SB_STRATEGY_LWW_HLC).err().unwrap();
        assert_eq!(error.code, SB_ERR_INPUT, "case {case:?}");
    }
}

#[test]
fn construction_and_argument_validation() {
    let identity = Identity::generate();
    let mut receive = ReceiveState::new();
    let error = receive.set_server_cursor("", "channel-a", 1).err().unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);
    let error = receive.set_server_cursor("server", "", 1).err().unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);
    let error = receive.set_source_cursor("", 1).err().unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);
    let error = receive.mark_seen("").err().unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);

    // A fresh replicator and an empty position make a valid, empty snapshot.
    let replicator = Replicator::new_clock("node-a", SB_STRATEGY_LWW_HLC, 1000).unwrap();
    let blob = replicator
        .export_snapshot(&identity, GROUP, 0, &ReceiveState::new())
        .unwrap();
    let (restored, restored_receive) = import_snapshot(&blob, SB_STRATEGY_LWW_HLC).unwrap();
    assert_eq!(restored.record_count(), 0);
    assert_eq!(restored_receive.json(), ReceiveState::new().json());
}

fn hex_decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("hex digit");
            let lo = (pair[1] as char).to_digit(16).expect("hex digit");
            (hi * 16 + lo) as u8
        })
        .collect()
}
