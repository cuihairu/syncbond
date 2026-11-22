//! Acceptance (todo.md DSR-45): the recovery story pinned over the real network.
//!
//! DSR-33 proved the happy path as real processes. This suite pins the
//! fault paths the unit tests already cover — page dedup, LWW conflicts,
//! durable cursors, server restart — over the same shape as production:
//! a relay booted from a directory, `demo-client` processes with their own
//! identities and storage, and the real `RelayClient` + `apply_page` stack
//! doing the pulls.
//!
//! Scenarios (the acceptance list, one test each):
//!   1. bidirectional offline writes incl. one same-key LWW conflict — the
//!      two devices converge to the same value and the same count;
//!   2. duplicate and out-of-order page delivery over the real relay — an
//!      older-stamp write for a key delivered after the newer one loses the
//!      LWW merge, then the page re-delivered; exactly-once effects, the
//!      cursor only ever advances with forward pulls;
//!   3. both devices and the server restart — a relay rebooted twice over
//!      the same durable directory resumes its channel log; both devices
//!      catch up from their committed cursors;
//!   4. ACK loss — the client re-appends the byte-identical envelope; the
//!      relay answers `duplicate` with the original seq and the log does
//!      not grow;
//!   5. page boundary — more envelopes than one page holds, pulled in a
//!      loop with a tiny limit; an empty page preserves the cursor;
//!   6. commit failure — a mixed page skips what the durable state knows,
//!      and a page applied but not committed is re-pulled by the restored
//!      device without moving the durable cursor;
//!   7. cleanup — the harness kills stragglers and the relays release
//!      their ports; the durable-dir relay keeps its database, the
//!      throwaway one deletes it.
//!
//! Everything here is deterministic: the relay never lies, the client
//! never invents, and every failure arrives typed. A failed assertion is
//! a test panic — a non-zero exit or a hung budget, never a silent skip.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead as _, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::time::{Duration, Instant};

use syncbond_core::conflict::LwwHlc;
use syncbond_core::hlc::HlcStamp;
use syncbond_core::replication::{Operation, Replicator};
use syncbond_core::storage::MemoryStorage;
use syncbond_core::{
    apply_page, commit_receive, load_receive, seal_operations, ApplyReport, DeviceIdentity,
    KeyRing, ReceiveState, ReceivedPage,
};
use syncbond_relay_client::{RelayClient, TlsPolicy};
use syncbond_relay_protocol::dto::{AppendAck, CredentialScope, Envelope, PullResponse};
use syncbond_server::test_support::{boot_relay, boot_relay_in, TestRelay};
use syncbond_transport_ws::{create_invite, Invite, WsPairingOptions};

/// The pull position `demo-client` reports: every process names the same
/// server, so a committed cursor survives restarts and moves with the
/// channel, not the relay's port.
const SERVER_ID: &str = "relay-1";
/// The demo's replication group; both paired devices join it.
const GROUP_ID: &str = "recovery-group";
/// The shared replication key every device carries through its pairing
/// session (the relay never sees it). Constant here because the in-process
/// devices bypass pairing and must agree with each other.
const GROUP_KEY: [u8; 32] = [7u8; 32];
/// A page small enough to force a boundary in every multi-page scenario.
const TINY_LIMIT: u16 = 2;

// ===========================================================================
// The harness: owns the temp root and any spawned children, so a panicking
// test never leaks a demo process or a stale directory. Relays are plain
// locals — a panic unwinds them and their Drop releases the port.
// ===========================================================================

/// One test's world: a temp root and the children spawned during it.
/// Dropping it kills every child still running and removes the root.
struct Harness {
    root: PathBuf,
    children: Vec<Child>,
}

impl Harness {
    fn new() -> Self {
        // Distinct root per test so parallel tests never collide.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "syncbond-recovery-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create the recovery root");
        Self {
            root,
            children: Vec::new(),
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Track a child so a panic cannot leave it running; returns its
    /// slot. [`Harness::release_child`] takes it back once it is done.
    fn track(&mut self, child: Child) -> usize {
        let index = self.children.len();
        self.children.push(child);
        index
    }

    fn release_child(&mut self, index: usize) -> Child {
        self.children.swap_remove(index)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for mut child in std::mem::take(&mut self.children) {
            let _ = child.kill();
            let _ = child.wait();
        }
        std::fs::remove_dir_all(&self.root).ok();
    }
}

/// Wait for a child to end, with a budget: a hung client fails the test
/// instead of hanging CI.
fn wait_with_budget(child: Child, budget: Duration) -> Output {
    let (output_tx, output_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let output = child.wait_with_output().expect("child io ends");
        let _ = output_tx.send(output);
    });
    output_rx
        .recv_timeout(budget)
        .expect("the client ends within the budget")
}

/// Read the host's stdout line by line until the code appears, keeping the
/// remaining lines available on the same channel. On timeout the host's
/// stderr file is read, so a failed pairing says why.
fn read_code_line(
    stdout: std::process::ChildStdout,
    host_stderr: &Path,
) -> (String, std::sync::mpsc::Receiver<String>) {
    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    loop {
        let line = match line_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => line,
            Err(_) => {
                let stderr = std::fs::read_to_string(host_stderr)
                    .unwrap_or_else(|error| format!("(no stderr file: {error})"));
                panic!("the host never printed the code; stderr: {stderr}");
            }
        };
        if let Some(code) = line.strip_prefix("code ") {
            return (code.to_owned(), line_rx);
        }
    }
}

/// Pull one `key value` line out of the demo-client protocol output.
fn field(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(key).map(|value| value.trim().to_owned()))
        .unwrap_or_else(|| panic!("demo-client printed no {key} line in: {stdout:?}"))
}

/// Run one demo-client invocation as its own process, asserting success.
fn run_demo(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_demo-client"))
        .args(args)
        .output()
        .expect("demo-client starts");
    assert!(
        output.status.success(),
        "demo-client {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is utf-8")
}

/// One demo write, and the record count it reports.
fn demo_write(dir: &Path, key: &str, value: &str, expected: usize) {
    let stdout = run_demo(&["write", dir.to_str().unwrap(), key, value]);
    assert_eq!(
        field(&stdout, "records"),
        expected.to_string(),
        "writing {key} left the wrong record count"
    );
}

/// One demo sync, and the record count it reports.
fn demo_sync(dir: &Path, relay_url: &str, channel_id: &str, token: &str, expected: usize) {
    let stdout = run_demo(&["sync", dir.to_str().unwrap(), relay_url, channel_id, token]);
    assert_eq!(
        field(&stdout, "records"),
        expected.to_string(),
        "syncing left the wrong record count"
    );
}

/// One demo count, and the record count it reports (no network).
fn demo_count(dir: &Path, expected: usize) {
    let stdout = run_demo(&["count", dir.to_str().unwrap()]);
    assert_eq!(
        field(&stdout, "records"),
        expected.to_string(),
        "the offline count drifted"
    );
}

/// One demo read, and the value it reports.
fn demo_get(dir: &Path, key: &str) -> String {
    field(&run_demo(&["get", dir.to_str().unwrap(), key]), "value")
}

/// Pair two demo-client processes through the relay's pairing room. Both
/// children are tracked before anything can panic, so a failed pairing
/// never leaks a process.
fn pair_demo_devices(
    harness: &mut Harness,
    dir_a: &Path,
    dir_b: &Path,
    relay_url: &str,
    invite: &Invite,
    host_stderr: &Path,
    joiner_stderr: &Path,
) {
    let mut host = Command::new(env!("CARGO_BIN_EXE_demo-client"))
        .args([
            "pair-host",
            dir_a.to_str().expect("dir path is utf-8"),
            relay_url,
            &invite.room_id,
            &invite.capability,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            File::create(host_stderr).expect("host stderr file"),
        ))
        .spawn()
        .expect("host process starts");
    let stdout = host.stdout.take().expect("host stdout is piped");
    let host_index = harness.track(host);

    let (code, host_lines_rx) = read_code_line(stdout, host_stderr);

    let joiner = Command::new(env!("CARGO_BIN_EXE_demo-client"))
        .args([
            "pair-joiner",
            dir_b.to_str().expect("dir path is utf-8"),
            relay_url,
            &invite.room_id,
            &invite.capability,
            &code,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            File::create(joiner_stderr).expect("joiner stderr file"),
        ))
        .spawn()
        .expect("joiner process starts");
    let joiner_index = harness.track(joiner);

    let joiner = harness.release_child(joiner_index);
    let joiner_output = wait_with_budget(joiner, Duration::from_secs(60));
    let host = harness.release_child(host_index);
    let host_output = wait_with_budget(host, Duration::from_secs(60));

    let joiner_err = std::fs::read_to_string(joiner_stderr).unwrap_or_default();
    assert!(
        joiner_output.status.success(),
        "joiner stderr: {joiner_err}"
    );
    let host_err = std::fs::read_to_string(host_stderr).unwrap_or_default();
    assert!(host_output.status.success(), "host stderr: {host_err}");

    // Drain the host's remaining lines (the code line reader kept them).
    let mut host_lines = vec![format!("code {code}")];
    loop {
        match host_lines_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(line) => host_lines.push(line),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => break,
        }
    }
    let host_paired = field(&host_lines.join("\n"), "paired");
    let joiner_paired = field(
        &String::from_utf8(joiner_output.stdout).expect("stdout is utf-8"),
        "paired",
    );
    assert!(!host_paired.is_empty(), "the host never paired");
    assert!(!joiner_paired.is_empty(), "the joiner never paired");
}

/// A pairing room plus the two demo directories, through real processes.
/// Returns nothing: the devices are on disk, every later step is a fresh
/// process recovering from there.
fn pair_demo_devices_over(
    harness: &mut Harness,
    relay_url: &str,
    runtime: &tokio::runtime::Runtime,
) -> (PathBuf, PathBuf) {
    let options = WsPairingOptions {
        relay_url: relay_url.to_owned(),
        ..Default::default()
    };
    let invite = runtime
        .block_on(create_invite(&options))
        .expect("room created");
    let dir_a = harness.dir("a");
    let dir_b = harness.dir("b");
    let host_stderr = harness.dir("host.stderr");
    let joiner_stderr = harness.dir("joiner.stderr");
    pair_demo_devices(
        harness,
        &dir_a,
        &dir_b,
        relay_url,
        &invite,
        &host_stderr,
        &joiner_stderr,
    );
    (dir_a, dir_b)
}

// ===========================================================================
// The real stack: a relay client over a booted relay, plus an in-process
// device — its own identity, keyring, replicator, receive state, and a
// storage it commits snapshots into — driving the real pull/apply path.
// ===========================================================================

/// The shared group keyring every device in the group carries. Deterministic
/// because the in-process devices bypass pairing and must agree with each
/// other; the demo processes mint the same key in their pairing session.
fn group_keyring() -> KeyRing {
    KeyRing::with_epoch(GROUP_ID, 1, GROUP_KEY)
}

/// An operation with an explicit stamp, bypassing `Replicator::put`'s
/// monotonic clock: the out-of-order scenario needs an older stamp
/// appended AFTER a newer one, which no single writer's clock can produce.
/// The stamps sit far in the past so no HLC skew bound is ever at play.
fn op_with_stamp(node: &str, op_id: &str, key: &str, payload: &[u8], pt: u64) -> Operation {
    Operation {
        op_id: op_id.to_owned(),
        key: key.to_owned(),
        payload: payload.to_vec(),
        deleted: false,
        stamp: HlcStamp {
            pt,
            ct: 0,
            id: node.to_owned(),
        },
        witness: HashMap::new(),
    }
}

/// One in-process device over the real relay.
struct InProcessDevice {
    replicator: Replicator,
    receive: ReceiveState,
    keyring: KeyRing,
    identity: DeviceIdentity,
    store: Arc<MemoryStorage>,
}

impl InProcessDevice {
    fn fresh() -> Self {
        let identity = DeviceIdentity::generate();
        Self {
            replicator: Replicator::new(identity.device_id.clone()),
            receive: ReceiveState::default(),
            keyring: group_keyring(),
            identity,
            store: Arc::new(MemoryStorage::new()),
        }
    }

    /// A fresh device over the same durable store: identity, replicator,
    /// and receive state come from the committed snapshot — the exact
    /// rebuild a restart performs.
    fn restored(store: Arc<MemoryStorage>) -> Self {
        let (state, receive) = load_receive(&*store)
            .expect("load the committed snapshot")
            .expect("the snapshot was committed");
        let identity = state.identity.clone();
        let replicator =
            Replicator::from_state(&state, Arc::new(LwwHlc)).expect("replay the snapshot");
        Self {
            replicator,
            receive,
            keyring: group_keyring(),
            identity,
            store,
        }
    }

    /// Persist the current snapshot (oplog, cursor, receive state). The
    /// commit point for the receive cursor.
    fn commit(&self) {
        let state =
            self.replicator
                .snapshot_state(&self.identity, GROUP_ID, self.keyring.current_epoch());
        commit_receive(&*self.store, &state, &self.receive).expect("commit the snapshot");
    }

    /// The pull position a restarting device would resume from: decoded
    /// from the committed snapshot, not the in-memory state.
    fn durable_cursor(&self, channel_id: &str) -> u64 {
        load_receive(&*self.store)
            .expect("load the committed snapshot")
            .expect("the snapshot was committed")
            .1
            .cursor_for(SERVER_ID, channel_id)
            .map(|cursor| cursor.server_seq)
            .unwrap_or(0)
    }

    /// Seal and append locally generated ops, returning the relay's acks.
    fn append(
        &self,
        runtime: &tokio::runtime::Runtime,
        client: &RelayClient,
        token: &str,
        channel_id: &str,
        ops: Vec<Operation>,
        request_id: &str,
    ) -> AppendAck {
        let envelopes = self.seal_ops(&ops);
        runtime
            .block_on(client.append(token, channel_id, &envelopes, request_id))
            .expect("append")
    }

    /// Seal operations into wire envelopes under this device's keyring.
    fn seal_ops(&self, ops: &[Operation]) -> Vec<Envelope> {
        seal_operations(ops, &self.keyring, &self.identity.device_id)
            .expect("seal")
            .into_iter()
            .flatten()
            .collect()
    }

    /// Pull one page and apply it in memory — no commit, the cursor is
    /// not durable until [`InProcessDevice::commit`].
    ///
    /// Each argument names a different thing the scenario varies, so the
    /// wide signature is deliberate in a test helper.
    #[allow(clippy::too_many_arguments)]
    fn pull_apply(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        client: &RelayClient,
        token: &str,
        channel_id: &str,
        after: u64,
        limit: Option<u16>,
        request_id: &str,
    ) -> (ApplyReport, PullResponse) {
        let page = runtime
            .block_on(client.pull(token, channel_id, after, limit, None, request_id))
            .expect("pull");
        let report = apply_page(
            &mut self.replicator,
            &mut self.receive,
            &self.keyring,
            &ReceivedPage {
                server_id: SERVER_ID,
                channel_id,
                entries: &page.entries,
            },
        )
        .expect("apply the page");
        (report, page)
    }

    /// [`InProcessDevice::pull_apply`] followed by the commit that makes
    /// the cursor durable.
    ///
    /// Each argument names a different thing the scenario varies, so the
    /// wide signature is deliberate in a test helper.
    #[allow(clippy::too_many_arguments)]
    fn pull_apply_commit(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        client: &RelayClient,
        token: &str,
        channel_id: &str,
        after: u64,
        limit: Option<u16>,
        request_id: &str,
    ) -> (ApplyReport, PullResponse) {
        let result = self.pull_apply(runtime, client, token, channel_id, after, limit, request_id);
        self.commit();
        result
    }

    /// The committed cursor this device's receive state holds.
    fn cursor(&self, channel_id: &str) -> u64 {
        self.receive
            .cursor_for(SERVER_ID, channel_id)
            .map(|cursor| cursor.server_seq)
            .unwrap_or(0)
    }
}

/// A fresh relay client over the test relay.
fn relay_client(relay: &TestRelay) -> RelayClient {
    let relay_url = format!("http://{}", relay.address);
    RelayClient::new(&relay_url, TlsPolicy::Validate, Duration::from_secs(10))
        .expect("a loopback location parses")
}

/// One channel and one Append+Pull credential, issued through the relay's
/// admin API exactly as a provisioner would.
fn provision(
    runtime: &tokio::runtime::Runtime,
    client: &RelayClient,
    admin: &str,
    counter: u64,
) -> (String, String) {
    let channel = runtime
        .block_on(client.create_channel(admin, &format!("recovery-create-{counter:08}")))
        .expect("channel creation");
    let token = issue_token(runtime, client, admin, &channel.channel_id, counter + 1000);
    (channel.channel_id, token)
}

/// One Append+Pull credential on an existing channel. Every device in a
/// scenario gets its own credential on the one shared channel — a credential
/// issued for a different channel is forbidden, never a silent no-op.
fn issue_token(
    runtime: &tokio::runtime::Runtime,
    client: &RelayClient,
    admin: &str,
    channel_id: &str,
    counter: u64,
) -> String {
    runtime
        .block_on(client.issue_credential(
            admin,
            channel_id,
            &[CredentialScope::Append, CredentialScope::Pull],
            Some("recovery"),
            &format!("recovery-issue-{counter:08}"),
        ))
        .expect("credential issuance")
        .token
}

/// Drop the relay, then wait until its port is gone. The serve task's
/// listener closes only when its future drops, so a released port means
/// the store was released too and another relay can reopen the database.
fn release(relay: TestRelay, budget: Duration) {
    let address = relay.address.clone();
    drop(relay);
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if TcpStream::connect(&address).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("relay port {address} was not released within the budget");
}

// ===========================================================================
// Scenarios
// ===========================================================================

#[test]
fn bidirectional_offline_writes_and_a_same_key_conflict_converge() {
    let mut harness = Harness::new();
    let relay = boot_relay();
    let relay_url = format!("http://{}", relay.address);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let client = relay_client(&relay);
    let (channel_id, token_a) = provision(&runtime, &client, &relay.admin, 1);
    let token_b = issue_token(&runtime, &client, &relay.admin, &channel_id, 2);

    let (dir_a, dir_b) = pair_demo_devices_over(&mut harness, &relay_url, &runtime);

    // Offline writes on both devices. `shared/key` is written by both —
    // the same-key LWW conflict the convergence claim rests on.
    demo_write(&dir_a, "only/a1", "va1", 1);
    demo_write(&dir_b, "only/b1", "vb1", 1);
    demo_write(&dir_a, "shared/key", "from-a", 2);
    demo_write(&dir_b, "shared/key", "from-b", 2);

    // First sync: each pushes its offline writes. A pulls nothing yet (its
    // writes are the only ones on the relay); B pulls A's two.
    demo_sync(&dir_a, &relay_url, &channel_id, &token_a, 2);
    demo_sync(&dir_b, &relay_url, &channel_id, &token_b, 3);
    // A catches up on B's two, resolving the conflict on both ends.
    demo_sync(&dir_a, &relay_url, &channel_id, &token_a, 3);

    // The conflict converged: one winner, the same on both devices, and
    // the disjoint keys cross-matched.
    let value_a = demo_get(&dir_a, "shared/key");
    let value_b = demo_get(&dir_b, "shared/key");
    assert_eq!(value_a, value_b, "the same-key conflict did not converge");
    assert!(
        value_a == "from-a" || value_a == "from-b",
        "the conflict resolved to a foreign value: {value_a}"
    );
    assert_eq!(demo_get(&dir_a, "only/a1"), "va1");
    assert_eq!(demo_get(&dir_b, "only/b1"), "vb1");
    assert_eq!(demo_get(&dir_a, "only/b1"), "vb1");
    assert_eq!(demo_get(&dir_b, "only/a1"), "va1");

    // Convergence, confirmed by plain count with no network at all.
    demo_count(&dir_a, 3);
    demo_count(&dir_b, 3);
}

#[test]
fn duplicate_and_out_of_order_pages_apply_exactly_once() {
    let relay = boot_relay();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let client = relay_client(&relay);
    let (channel_id, token) = provision(&runtime, &client, &relay.admin, 3);

    let writer = InProcessDevice::fresh();
    let mut applier = InProcessDevice::fresh();
    // The out-of-order case, delivered by the relay in seq order: the LATER
    // stamp for `shared/a` is appended FIRST (seqs 1,2), the EARLIER one
    // second (seqs 3,4). A forward pull hands the applier the newer write
    // before the older one — the same-key LWW resolution an out-of-order
    // delivery exercises, with no stale cursor needed.
    let ops = vec![
        op_with_stamp("node-a", "op-a-new", "shared/a", b"a1", 200),
        op_with_stamp("node-a", "op-c-1", "shared/c", b"c0", 300),
    ];
    writer.append(&runtime, &client, &token, &channel_id, ops, "dup-1");
    let ops = vec![
        op_with_stamp("node-a", "op-a-old", "shared/a", b"a0", 100),
        op_with_stamp("node-a", "op-b-1", "shared/b", b"b0", 400),
    ];
    writer.append(&runtime, &client, &token, &channel_id, ops, "dup-2");

    // The first page (seqs 1,2): both fresh, both apply.
    let (report, page) =
        applier.pull_apply_commit(&runtime, &client, &token, &channel_id, 0, Some(2), "dup-3");
    assert_eq!(
        report.applied, 2,
        "the first page applies on a fresh device"
    );
    let seqs: Vec<u64> = page.entries.iter().map(|entry| entry.seq).collect();
    assert_eq!(seqs, vec![1, 2]);
    assert_eq!(applier.cursor(&channel_id), 2);
    assert_eq!(applier.durable_cursor(&channel_id), 2);
    assert_eq!(applier.replicator.record_count(), 2);

    // The second page (seqs 3,4) carries the OLDER stamp for `shared/a`.
    // Its entries are new to this device, so both are ingested — but a0
    // loses the LWW merge (kept only as a concurrent version) and must not
    // clobber the a1 already applied. b0 is fresh and becomes a record.
    let (report, _) =
        applier.pull_apply_commit(&runtime, &client, &token, &channel_id, 2, Some(2), "dup-4");
    assert_eq!(report.applied, 2, "both new entries are ingested");
    assert_eq!(applier.cursor(&channel_id), 4);
    assert_eq!(applier.replicator.record_count(), 3);
    // The newer stamp still wins over the out-of-order delivery.
    assert_eq!(
        applier.replicator.get("shared/a").unwrap().payload,
        b"a1".to_vec(),
        "an out-of-order older write must not clobber the newer value"
    );

    // Re-delivery: pull the same page again. Every entry is a duplicate;
    // nothing is applied twice, and the cursor does not move.
    let (report, page) =
        applier.pull_apply_commit(&runtime, &client, &token, &channel_id, 2, Some(2), "dup-5");
    assert_eq!(report.applied, 0, "redelivered pages apply nothing new");
    assert_eq!(
        report.duplicates, 2,
        "every redelivered entry is a duplicate"
    );
    assert_eq!(
        page.next_cursor, 4,
        "the redelivered page's cursor is stable"
    );
    assert_eq!(applier.cursor(&channel_id), 4);
    assert_eq!(
        applier.replicator.record_count(),
        3,
        "exactly once: no growth"
    );
}

#[test]
fn server_restart_resumes_the_durable_channel_log() {
    let mut harness = Harness::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    // Boot 1: provision, pair, and sync the first offline writes.
    let data_dir = harness.dir("restart-relay");
    let relay = boot_relay_in(&data_dir);
    let relay_url = format!("http://{}", relay.address);
    let client = relay_client(&relay);
    let (channel_id, token_a) = provision(&runtime, &client, &relay.admin, 4);
    let token_b = issue_token(&runtime, &client, &relay.admin, &channel_id, 5);
    let (dir_a, dir_b) = pair_demo_devices_over(&mut harness, &relay_url, &runtime);

    demo_write(&dir_a, "k/a1", "va1", 1);
    demo_write(&dir_b, "k/b1", "vb1", 1);
    // A pushes its write and pulls it back — its own op, so nothing new.
    demo_sync(&dir_a, &relay_url, &channel_id, &token_a, 1);
    // B pushes its write, then pulls both: A's is fresh.
    demo_sync(&dir_b, &relay_url, &channel_id, &token_b, 2);
    // A catches up on B's.
    demo_sync(&dir_a, &relay_url, &channel_id, &token_a, 2);
    demo_count(&dir_a, 2);
    demo_count(&dir_b, 2);

    // Restart 1: the same durable directory, a new port.
    release(relay, Duration::from_secs(5));
    let relay = boot_relay_in(&data_dir);
    let relay_url = format!("http://{}", relay.address);

    // Offline writes continue over the restarted relay; each device
    // catches the other up from its committed cursor.
    demo_write(&dir_a, "k/a2", "va2", 3);
    demo_sync(&dir_a, &relay_url, &channel_id, &token_a, 3);
    demo_sync(&dir_b, &relay_url, &channel_id, &token_b, 3);

    // Restart 2: the log survives a second reboot, and both devices
    // converge against the third boot.
    release(relay, Duration::from_secs(5));
    let relay = boot_relay_in(&data_dir);
    let relay_url = format!("http://{}", relay.address);
    demo_sync(&dir_a, &relay_url, &channel_id, &token_a, 3);
    demo_sync(&dir_b, &relay_url, &channel_id, &token_b, 3);

    demo_count(&dir_a, 3);
    demo_count(&dir_b, 3);
    assert_eq!(demo_get(&dir_a, "k/a2"), "va2");
    assert_eq!(demo_get(&dir_b, "k/a2"), "va2");
    drop(relay);
}

#[test]
fn ack_loss_reappending_the_identical_envelope_is_idempotent() {
    let relay = boot_relay();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let client = relay_client(&relay);
    let (channel_id, token) = provision(&runtime, &client, &relay.admin, 6);

    let mut writer = InProcessDevice::fresh();
    // The append the client never heard back about: the SAME envelope —
    // sealed once, so every byte including the message id matches — goes
    // up twice.
    let ops = vec![writer.replicator.put("k/loss", b"v1".to_vec()).unwrap()];
    let envelopes = writer.seal_ops(&ops);
    let first = runtime
        .block_on(client.append(&token, &channel_id, &envelopes, "ack-1"))
        .expect("first append");
    assert_eq!(first.acks.len(), 1);
    assert_eq!(first.acks[0].seq, 1);
    assert!(
        !first.acks[0].duplicate,
        "the first append is not a duplicate"
    );

    let resend = runtime
        .block_on(client.append(&token, &channel_id, &envelopes, "ack-2"))
        .expect("the resend");
    assert_eq!(resend.acks.len(), 1);
    assert!(
        resend.acks[0].duplicate,
        "the resend hit the idempotency record"
    );
    assert_eq!(resend.acks[0].seq, 1, "the original seq is preserved");
    assert_eq!(resend.acks[0].message_id, first.acks[0].message_id);

    // The log did not grow: one entry, one page, no more.
    let page = runtime
        .block_on(client.pull(&token, &channel_id, 0, None, None, "ack-pull"))
        .expect("pull");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].seq, 1);
    assert!(!page.has_more);
}

#[test]
fn page_boundary_pulls_with_a_tiny_limit() {
    let relay = boot_relay();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let client = relay_client(&relay);
    let (channel_id, token) = provision(&runtime, &client, &relay.admin, 7);

    let mut writer = InProcessDevice::fresh();
    let mut applier = InProcessDevice::fresh();
    let ops = (0..5)
        .map(|i| {
            writer
                .replicator
                .put(format!("k/page{i}"), format!("v{i}").into_bytes())
                .unwrap()
        })
        .collect::<Vec<_>>();
    writer.append(&runtime, &client, &token, &channel_id, ops, "page-append");

    // Pull in a loop with the tiny limit, following nextCursor/hasMore.
    let mut cursor = 0u64;
    let mut pulled = 0usize;
    let mut pages = 0usize;
    loop {
        let (report, page) = applier.pull_apply_commit(
            &runtime,
            &client,
            &token,
            &channel_id,
            cursor,
            Some(TINY_LIMIT),
            &format!("page-pull-{pages}"),
        );
        assert_eq!(
            report.applied,
            page.entries.len(),
            "every pulled entry applies"
        );
        pulled += page.entries.len();
        cursor = page.next_cursor;
        pages += 1;
        if !page.has_more {
            break;
        }
        assert!(pages < 50, "the pull loop did not terminate");
    }
    assert_eq!(pulled, 5, "exactly five entries across the pages");
    assert_eq!(applier.replicator.record_count(), 5);
    assert_eq!(applier.cursor(&channel_id), cursor);

    // An empty page at the end preserves the cursor.
    let (report, page) = applier.pull_apply_commit(
        &runtime,
        &client,
        &token,
        &channel_id,
        cursor,
        Some(TINY_LIMIT),
        "page-empty",
    );
    assert_eq!(report.applied, 0, "the empty page applies nothing");
    assert_eq!(page.entries.len(), 0);
    assert_eq!(
        page.next_cursor, cursor,
        "an empty page preserves the cursor"
    );
    assert_eq!(applier.cursor(&channel_id), cursor);
    assert_eq!(applier.durable_cursor(&channel_id), cursor);
}

#[test]
fn a_failed_commit_leaves_the_cursor_unmoved_and_reapplies_idempotently() {
    let relay = boot_relay();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let client = relay_client(&relay);
    let (channel_id, token) = provision(&runtime, &client, &relay.admin, 8);

    let mut writer = InProcessDevice::fresh();
    let mut applier = InProcessDevice::fresh();
    let ops = vec![writer.replicator.put("k/commit/a", b"a".to_vec()).unwrap()];
    writer.append(&runtime, &client, &token, &channel_id, ops, "commit-1");
    let ops = vec![
        writer.replicator.put("k/commit/b", b"b".to_vec()).unwrap(),
        writer.replicator.put("k/commit/c", b"c".to_vec()).unwrap(),
    ];
    writer.append(&runtime, &client, &token, &channel_id, ops, "commit-2");

    // The first page (seqs 1,2) applies and commits; the durable cursor
    // is 2 and the durable dedup set holds a and b.
    let (report, _) = applier.pull_apply_commit(
        &runtime,
        &client,
        &token,
        &channel_id,
        0,
        Some(2),
        "commit-3",
    );
    assert_eq!(report.applied, 2);
    assert_eq!(applier.durable_cursor(&channel_id), 2);

    // A stale-cursor retry delivers the mixed page [2,3]: b is already in
    // the durable set (skipped), c is fresh (applied).
    let (report, _) = applier.pull_apply_commit(
        &runtime,
        &client,
        &token,
        &channel_id,
        1,
        Some(2),
        "commit-4",
    );
    assert_eq!(report.duplicates, 1, "the known entry is skipped");
    assert_eq!(report.applied, 1, "the fresh entry applies");
    assert_eq!(applier.replicator.record_count(), 3);
    assert_eq!(applier.durable_cursor(&channel_id), 3);

    // The commit failure: page [4] applies in memory but is never
    // committed. The in-memory cursor moves to 4; the durable one stays.
    let ops = vec![writer.replicator.put("k/commit/d", b"d".to_vec()).unwrap()];
    writer.append(&runtime, &client, &token, &channel_id, ops, "commit-5");
    let (report, _) = applier.pull_apply(
        &runtime,
        &client,
        &token,
        &channel_id,
        3,
        Some(2),
        "commit-6",
    );
    assert_eq!(report.applied, 1);
    assert_eq!(applier.cursor(&channel_id), 4, "the in-memory cursor moved");
    assert_eq!(
        applier.durable_cursor(&channel_id),
        3,
        "the failed commit left it"
    );

    // The restored device rebuilds from the durable snapshot and re-pulls
    // from the durable cursor: d applies exactly once.
    let mut restored = InProcessDevice::restored(applier.store.clone());
    assert_eq!(restored.cursor(&channel_id), 3);
    assert_eq!(restored.replicator.record_count(), 3);
    let (report, _) = restored.pull_apply_commit(
        &runtime,
        &client,
        &token,
        &channel_id,
        3,
        Some(2),
        "commit-7",
    );
    assert_eq!(report.applied, 1, "the uncommitted page re-applies once");
    assert_eq!(report.duplicates, 0, "the durable set never saw it");
    assert_eq!(restored.replicator.record_count(), 4);
    assert_eq!(restored.durable_cursor(&channel_id), 4);
    assert_eq!(
        restored.replicator.get("k/commit/d").unwrap().payload,
        b"d".to_vec()
    );
}

#[test]
fn dropping_the_harness_kills_stragglers_and_releases_the_ports() {
    let mut harness = Harness::new();
    let root = harness.root.clone();

    // A straggler child that would outlive the test without the harness.
    let straggler = Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("sleep starts");
    let pid = straggler.id();
    harness.track(straggler);

    // The throwaway relay: port released, database removed on drop.
    let relay = boot_relay();
    let db = relay.db_path().to_owned();
    assert!(db.exists(), "the throwaway relay created its database");
    release(relay, Duration::from_secs(5));
    assert!(!db.exists(), "the throwaway relay removed its database");

    // The durable-dir relay: port released, database kept for the next
    // boot to resume from.
    let data_dir = harness.dir("durable");
    let relay = boot_relay_in(&data_dir);
    let db = relay.db_path().to_owned();
    assert!(db.exists(), "the durable relay created its database");
    release(relay, Duration::from_secs(5));
    assert!(db.exists(), "the durable relay kept its database");

    // The harness killed the straggler and removed the root.
    drop(harness);
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the harness killed the straggler process"
    );
    assert!(!root.exists(), "the harness removed its temp root");
}
