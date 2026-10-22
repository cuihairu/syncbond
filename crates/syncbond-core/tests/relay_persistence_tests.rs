use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use syncbond_core::relay::{apply_pull_response, FileRelayStore, PullRequest, RelayStore};
use syncbond_core::replication::Replicator;

fn temporary_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!(
        "syncbond-relay-{}-{unique}.json",
        std::process::id()
    ))
}

#[test]
fn durable_relay_resumes_across_server_restart_without_duplicates() {
    let path = temporary_path();
    let mut writer = Replicator::new("writer");

    let store = FileRelayStore::open(&path).unwrap();
    let first = writer.put("key", b"first".to_vec());
    store.append("channel", &first).unwrap();
    let first_pull = store.pull_after("channel", 0).unwrap();
    drop(store);

    let second = writer.put("key", b"second".to_vec());
    let restarted = FileRelayStore::open(&path).unwrap();
    restarted.append("channel", &first).unwrap();
    restarted.append("channel", &second).unwrap();

    let request = PullRequest {
        channel: "channel".to_string(),
        after: first_pull.after,
    };
    let pull = restarted
        .pull_after(&request.channel, request.after)
        .unwrap();
    assert_eq!(pull.ops.len(), 1);
    assert_eq!(pull.ops[0].op_id, second.op_id);

    let mut replica = Replicator::new("replica");
    let all = restarted.pull_after("channel", 0).unwrap();
    assert_eq!(apply_pull_response(&mut replica, &all).unwrap(), 2);
    assert_eq!(apply_pull_response(&mut replica, &pull).unwrap(), 0);
    assert_eq!(replica.get("key").unwrap().payload, b"second");

    fs::remove_file(path).unwrap();
}
