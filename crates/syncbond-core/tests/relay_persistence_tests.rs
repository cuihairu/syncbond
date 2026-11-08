use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use syncbond_core::relay::{apply_pull_response, FileRelayStore, PullRequest, RelayStore};
use syncbond_core::replication::Replicator;

/// Serializes tests that mutate the process-global current directory. CWD is
/// shared by every test binary's threads, so any test that chdirs must hold
/// this lock for the duration of the CWD change, and other CWD-dependent
/// tests must take it too.
static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Restores the process CWD on drop, even if the guarded body panics.
struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    fn enter(dir: &std::path::Path) -> Self {
        let original = env::current_dir().expect("read current dir");
        env::set_current_dir(dir).expect("chdir into temp dir");
        CwdGuard { original }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        env::set_current_dir(&self.original).expect("restore current dir");
    }
}

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
    let first = writer.put("key", b"first".to_vec()).unwrap();
    store.append("channel", &first).unwrap();
    let first_pull = store.pull_after("channel", 0).unwrap();
    drop(store);

    let second = writer.put("key", b"second".to_vec()).unwrap();
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

#[test]
fn durable_relay_accepts_bare_relative_path() {
    // Regression test for parent() == Some("") on a bare relative path.
    let _guard = CWD_LOCK.lock().unwrap();
    let unique_suffix = format!(
        "syncbond-relay-bare-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp = env::temp_dir().join(&unique_suffix);
    fs::create_dir_all(&temp).unwrap();
    let _cwd = CwdGuard::enter(&temp);

    let result = std::panic::catch_unwind(|| {
        let mut writer = Replicator::new("writer");
        let store = FileRelayStore::open("state.json").unwrap();
        let operation = writer.put("key", b"first".to_vec()).unwrap();
        store.append("channel", &operation).unwrap();
    });
    fs::remove_file(temp.join("state.json")).unwrap();
    fs::remove_dir(temp).unwrap();
    result.unwrap();
}

#[test]
fn open_on_a_directory_is_an_error() {
    let dir = env::temp_dir().join(format!("syncbond-relay-dir-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    assert!(
        FileRelayStore::open(&dir).is_err(),
        "a directory is not a relay log"
    );
}

#[test]
fn persist_reports_error_when_a_parent_component_is_a_file() {
    let root = env::temp_dir().join(format!("syncbond-relay-block-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let mut writer = Replicator::new("writer");
    // Open is fine: the log file simply does not exist yet.
    let store = FileRelayStore::open(root.join("sub").join("relay.json")).unwrap();
    // Now plant a regular file where persist would create its directory.
    fs::write(root.join("sub"), b"blocker").unwrap();
    let operation = writer.put("key", b"v".to_vec()).unwrap();
    assert!(
        store.append("channel", &operation).is_err(),
        "persist must report the unwritable directory"
    );
}
