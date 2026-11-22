//! Acceptance (todo.md DSR-47): the server's ciphertext boundary over real
//! data and a real rotation.
//!
//! Three surfaces, one server, one scan. The relay runs as its own process
//! — the deliverable binary, a real config, a real data directory — so its
//! database files, its log stream, and every application-layer byte between
//! clients and server are observable. A tee proxy in front of it copies the
//! traffic both ways without interpreting a byte.
//!
//! The traffic driven through it is the whole story:
//!   - a real pairing room — the short code is issued and consumed, and the
//!     group key crosses the room's socket inside one end-to-end encrypted
//!     session message;
//!   - real channel data — append + pull, every payload a distinctive
//!     marker string, sealed under the epoch-1 key;
//!   - a real member rotation — `rotate_for_removal` delivers the epoch-2
//!     key only to survivors, and a post-rotation envelope (sealed under it)
//!     is appended to the channel.
//!
//! The claim, one assertion per surface: none of the three secrets — the
//! pairing short code, the payload markers, the epoch-1 or epoch-2 group
//! key — appears in the database files, the log stream, or the traffic.
//! The scan is not vacuous: the ciphertext and the envelope message ids
//! DO appear in the database and the traffic, which is the point of the
//! boundary — the relay stores and forwards exactly the ciphertext.
//!
//! Everything here is deterministic and typed: a failed assertion is a test
//! panic, never a silent skip.

use std::collections::BTreeSet;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use syncbond_core::member_crypto::MemberKeyRing;
use syncbond_core::member_distribution::{deliver_rotation, MemberChannel, MemberChannelError};
use syncbond_core::replication::Replicator;
use syncbond_core::{seal_operations, DeviceIdentity, KeyRing};
use syncbond_relay_client::{RelayClient, TlsPolicy};
use syncbond_relay_protocol::dto::{CredentialScope, Envelope};
use syncbond_transport_ws::{create_invite, pair_as_host, pair_as_joiner, WsPairingOptions};

/// The replication group every in-process device shares (the demo group id;
/// the relay never sees it).
const GROUP_ID: &str = "boundary-group";
/// The known epoch-1 group key. The host seals it over the pairing session
/// (so it rides the room socket inside ciphertext), and every pre-rotation
/// envelope is sealed under it.
const KEY_EPOCH_1: [u8; 32] = [0x11; 32];
/// A distinctive plaintext payload marker: must never appear in the clear
/// on any server surface.
const MARKER_PRE: &str = "BOUNDARY-MARKER-PLAINTEXT-PRE-ROTATION";
/// The second marker, on the post-rotation envelope.
const MARKER_POST: &str = "BOUNDARY-MARKER-PLAINTEXT-POST-ROTATION";

// ===========================================================================
// The real server process
// ===========================================================================

/// Pick an ephemeral loopback port. The relay binds it right after, so the
/// small reuse race is a test-level concern only (the test owns the port).
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
    listener.local_addr().expect("probe address").port()
}

/// The deliverable relay binary, as its own process: a real config on disk,
/// a real data directory, piped logs. Dropping without `stop` aborts it.
struct ServerProcess {
    child: Option<Child>,
    address: String,
    data_dir: PathBuf,
    /// The bootstrap admin credential (read from the file the store wrote).
    admin: String,
}

impl ServerProcess {
    fn start(root: &Path) -> Self {
        // `free_port()` returns a number whose probe socket is already
        // dropped, and a sibling suite probing at the same moment can be
        // handed that same number. Our child then loses the bind and exits,
        // so the listener that answers is a *foreign* relay holding a
        // different admin credential — the first admin call comes back 401
        // "admin credential required". A live child is the only proof the
        // port is ours, so a fresh port fixes every collision.
        for _ in 0..8 {
            if let Some(server) = Self::start_once(root) {
                return server;
            }
        }
        panic!("no free relay port: every candidate was claimed by another server");
    }

    fn start_once(root: &Path) -> Option<Self> {
        let data_dir = root.join("server-data");
        std::fs::create_dir_all(&data_dir).expect("create the data directory");
        let port = free_port();
        let config_path = root.join("config.json");
        // The closed config shape the binary validates at startup. The
        // shutdown budget is a few seconds so a stop is quick and the drain
        // still checkpoints the WAL.
        let config = serde_json::json!({
            "listen": format!("127.0.0.1:{port}"),
            "dataDir": data_dir.to_str().expect("utf-8 data dir"),
            "shutdownTimeoutSeconds": 5,
        });
        std::fs::write(&config_path, config.to_string()).expect("write the config");
        let mut child = Command::new(env!("CARGO_BIN_EXE_syncbond-server"))
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the relay binary starts");
        // Readiness is the listener accepting plus the bootstrap admin
        // credential on disk — never before both. The store writes the
        // credential before it binds, so a listening socket plus a
        // credential is not yet proof that either came from *this* child:
        // hold the port a moment and require the child to still be alive.
        let admin_path = syncbond_server::sqlite::admin_credential_path(&data_dir.join("relay.db"));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let listening = TcpStream::connect(("127.0.0.1", port)).is_ok();
            let admin_ready = admin_path.exists();
            if listening && admin_ready {
                for _ in 0..5 {
                    if child.try_wait().is_ok_and(|status| status.is_some()) {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                let admin =
                    std::fs::read_to_string(&admin_path).expect("admin credential readable");
                return Some(Self {
                    child: Some(child),
                    address: format!("127.0.0.1:{port}"),
                    data_dir,
                    admin: admin.trim().to_owned(),
                });
            }
            if child.try_wait().is_ok_and(|status| status.is_some()) {
                return None;
            }
            assert!(Instant::now() < deadline, "the relay never became ready");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// SIGTERM (the container-runtime stop), wait for the drain, and return
    /// everything the process emitted. The drain checkpoints the WAL, so the
    /// database files on disk are the final consistent state.
    fn stop(mut self) -> Output {
        let child = self.child.take().expect("the server is still running");
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let (tx, rx) = std::sync::mpsc::channel::<Output>();
        std::thread::spawn(move || {
            let output = child.wait_with_output().expect("relay io ends");
            let _ = tx.send(output);
        });
        match rx.recv_timeout(Duration::from_secs(25)) {
            Ok(output) => output,
            Err(_) => panic!("the relay did not stop within the budget"),
        }
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ===========================================================================
// The tee proxy: copies every byte between clients and the relay into a
// shared capture, without interpreting any of it.
// ===========================================================================

/// All application-layer bytes seen on either side of every connection,
/// in arrival order.
#[derive(Default)]
struct Traffic {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Traffic {
    fn snapshot(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

struct TeeProxy {
    address: String,
    traffic: Traffic,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl TeeProxy {
    /// Listen on an ephemeral loopback port and forward every accepted
    /// connection to `backend`, teeing both directions.
    async fn start(backend: String) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the proxy binds");
        let address = listener.local_addr().unwrap().to_string();
        let traffic = Traffic::default();
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let task_sink = tasks.clone();
        let bytes = traffic.bytes.clone();
        let accept = tokio::spawn(async move {
            loop {
                let accepted = listener.accept().await;
                let (client, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => break,
                };
                let backend = match tokio::net::TcpStream::connect(&backend).await {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                let bytes = bytes.clone();
                let handle = tokio::spawn(async move {
                    let _ = tee(client, backend, &bytes).await;
                });
                task_sink
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(handle);
            }
        });
        tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(accept);
        Self {
            address,
            traffic,
            tasks,
        }
    }
}

impl Drop for TeeProxy {
    fn drop(&mut self) {
        let tasks = std::mem::take(
            &mut *self
                .tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for task in tasks {
            task.abort();
        }
    }
}

/// Relay one duplex connection, teeing both directions into `capture`.
async fn tee(
    mut client: tokio::net::TcpStream,
    mut backend: tokio::net::TcpStream,
    capture: &Arc<Mutex<Vec<u8>>>,
) {
    let (mut client_read, mut client_write) = client.split();
    let (mut backend_read, mut backend_write) = backend.split();
    // The two directions on one task, so the borrowed halves are safe.
    let _ = tokio::join!(
        copy_tee(&mut client_read, &mut backend_write, capture.clone()),
        copy_tee(&mut backend_read, &mut client_write, capture.clone()),
    );
}

async fn copy_tee<R, W>(reader: &mut R, writer: &mut W, capture: Arc<Mutex<Vec<u8>>>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;
    let mut buffer = [0u8; 8192];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        capture
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(&buffer[..read]);
        if writer.write_all(&buffer[..read]).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

// ===========================================================================
// Scan helpers
// ===========================================================================

fn windows_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Assert `needle` (named `what`) never appears in `haystack` (named
/// `surface`), for a scan that must prove an absence.
fn assert_absent(surface: &str, haystack: &[u8], what: &str, needle: &[u8]) {
    assert!(
        !windows_contain(haystack, needle),
        "{surface} ({hay} bytes) contains {what} ({needle_len} bytes)",
        hay = haystack.len(),
        needle_len = needle.len(),
    );
}

/// The byte shapes a key could leak in: raw, lower/upper hex, standard and
/// url-safe base64. A leak in a binary file, a log line, or a JSON field
/// lands in at least one of them.
fn key_needles(key: &[u8; 32]) -> Vec<Vec<u8>> {
    let hex_lower: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    let hex_upper: String = key.iter().map(|byte| format!("{byte:02X}")).collect();
    use base64::Engine as _;
    vec![
        key.to_vec(),
        hex_lower.into_bytes(),
        hex_upper.into_bytes(),
        base64::engine::general_purpose::STANDARD
            .encode(key)
            .into_bytes(),
        base64::engine::general_purpose::URL_SAFE
            .encode(key)
            .into_bytes(),
    ]
}

/// Concatenate every file in `dir` (flat: the relay keeps its database and
/// WAL and the admin credential there).
fn dir_bytes(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read the data directory") {
        let entry = entry.expect("a directory entry");
        if !entry.file_type().expect("entry type").is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).expect("read a data file");
        all.extend_from_slice(&bytes);
    }
    all
}

/// The log stream: everything the process wrote to stdout or stderr.
fn logs(output: &Output) -> Vec<u8> {
    let mut all = Vec::new();
    all.extend_from_slice(&output.stdout);
    all.extend_from_slice(&output.stderr);
    all
}

// ===========================================================================
// The member-ring setup (a rotation, over the real channel)
// ===========================================================================

fn member_ring(device: &DeviceIdentity, members: &[&DeviceIdentity]) -> MemberKeyRing {
    MemberKeyRing::with_epoch(
        GROUP_ID,
        &device.device_id,
        members.iter().map(|member| member.device_id.clone()),
        members
            .iter()
            .map(|member| (member.device_id.clone(), member.public_key)),
        1,
        KEY_EPOCH_1,
    )
    .expect("shared group state")
}

/// Per-device pairwise channels, bound to the survivors only — the guard
/// that keeps a rotation record off a channel the removed member can read.
struct SurvivorChannels {
    bound: BTreeSet<String>,
}

impl SurvivorChannels {
    fn for_devices(devices: &[&str]) -> Self {
        Self {
            bound: devices.iter().map(|device| (*device).to_owned()).collect(),
        }
    }
}

impl MemberChannel for SurvivorChannels {
    fn deliver(&self, device_id: &str, _bytes: &[u8]) -> Result<(), MemberChannelError> {
        if !self.bound.contains(device_id) {
            return Err(MemberChannelError::NotRecipient {
                bound: "no pairwise channel".into(),
                asked: device_id.to_owned(),
            });
        }
        Ok(())
    }
}

/// Seal operations under `keyring` into wire envelopes.
fn seal_ops(keyring: &KeyRing, device_id: &str, key: &str, payload: &[u8]) -> Vec<Envelope> {
    let mut replicator = Replicator::new(device_id.to_owned());
    let op = replicator
        .put(key.to_owned(), payload.to_vec())
        .expect("put");
    seal_operations(&[op], keyring, device_id)
        .expect("seal")
        .into_iter()
        .flatten()
        .collect()
}

// ===========================================================================
// The scenario
// ===========================================================================

#[test]
fn real_data_and_a_rotation_leave_no_secret_in_the_server_artifacts() {
    let root = std::env::temp_dir().join(format!(
        "syncbond-boundary-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("create the boundary root");
    let server = ServerProcess::start(&root);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    // The tee proxy in front of the real relay: every byte the clients and
    // the server exchange passes through here.
    let proxy = runtime.block_on(TeeProxy::start(server.address.clone()));
    let proxy_url = format!("http://{}", proxy.address);
    let client = RelayClient::new(&proxy_url, TlsPolicy::Validate, Duration::from_secs(10))
        .expect("the proxy location parses");

    // --- a real pairing room: the short code is issued, the group key
    // --- crosses the room socket inside one encrypted session message.
    let options = WsPairingOptions {
        relay_url: proxy_url.clone(),
        ..Default::default()
    };
    let invite = runtime
        .block_on(create_invite(&options))
        .expect("room created");
    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    let host_options = options.clone();
    let host_invite = invite.clone();
    let key_over_session = KEY_EPOCH_1.to_vec();
    let host_key = key_over_session.clone();
    let host = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("host runtime");
        let identity = DeviceIdentity::generate();
        let session = rt
            .block_on(pair_as_host(
                &host_options,
                &identity,
                &host_invite,
                |code| {
                    code_tx
                        .send(code.to_owned())
                        .expect("the code channel is open");
                },
            ))
            .expect("host pairing completes");
        // The group key rides the room socket inside the session's cipher.
        session
            .seal_and_send(&host_key)
            .expect("the session seals the key");
        // The bridge's pump is driven by the runtime's other threads, but a
        // beat flushes the frame before the socket closes.
        rt.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    });
    let code = code_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the host issued the short code");
    let joiner_options = options.clone();
    let joiner_invite = invite.clone();
    let joiner_code = code.clone();
    let joiner = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("joiner runtime");
        let identity = DeviceIdentity::generate();
        let session = rt
            .block_on(pair_as_joiner(
                &joiner_options,
                &identity,
                &joiner_code,
                &joiner_invite,
            ))
            .expect("joiner pairing completes");
        session
            .recv_and_open()
            .expect("the joiner opens the session key")
    });
    host.join().expect("the host thread ends");
    let opened = joiner.join().expect("the joiner thread ends");
    assert_eq!(
        opened, key_over_session,
        "the group key crossed the room socket and opened on the other side"
    );

    // --- real channel data: append + pull, every payload a marker.
    let channel = runtime
        .block_on(client.create_channel(&server.admin, "boundary-create-00000001"))
        .expect("channel creation");
    let channel_id = channel.channel_id;
    let token = runtime
        .block_on(client.issue_credential(
            &server.admin,
            &channel_id,
            &[CredentialScope::Append, CredentialScope::Pull],
            Some("boundary"),
            "boundary-issue-00000002",
        ))
        .expect("credential issuance")
        .token;
    let writer_id = "boundary-writer";
    let epoch1 = KeyRing::with_epoch(GROUP_ID, 1, KEY_EPOCH_1);
    let pre = seal_ops(&epoch1, writer_id, "boundary/pre", MARKER_PRE.as_bytes());
    runtime
        .block_on(client.append(&token, &channel_id, &pre, "boundary-append-00000003"))
        .expect("append the pre-rotation op");
    let page = runtime
        .block_on(client.pull(&token, &channel_id, 0, None, None, "boundary-pull-00000004"))
        .expect("pull the pre-rotation op back");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].envelope.message_id, pre[0].message_id);
    assert_eq!(
        page.entries[0].envelope.ciphertext, pre[0].ciphertext,
        "the relay returns exactly the ciphertext it was given"
    );

    // --- a real member rotation: the epoch-2 key reaches survivors only,
    // --- then a post-rotation envelope is sealed under it and appended.
    let identities = [
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
    ];
    let members = [&identities[0], &identities[1], &identities[2]];
    let mut a = member_ring(&identities[0], &members);
    let mut b = member_ring(&identities[1], &members);
    let c = member_ring(&identities[2], &members);
    let rotation = a
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .expect("rotate");
    assert_eq!(rotation.epoch, 2);
    let router =
        SurvivorChannels::for_devices(&[&identities[0].device_id, &identities[1].device_id]);
    let delivered = deliver_rotation(&router, &rotation).expect("the survivors are delivered");
    assert_eq!(delivered, rotation.member_ids);
    b.apply_rotation(&rotation.distribution)
        .expect("B installs");
    assert_eq!(c.current_epoch(), 1, "the removed device never advanced");
    let key_epoch_2 = rotation.key;
    let epoch2 = KeyRing::with_epoch(GROUP_ID, 2, key_epoch_2);
    let post = seal_ops(&epoch2, writer_id, "boundary/post", MARKER_POST.as_bytes());
    runtime
        .block_on(client.append(&token, &channel_id, &post, "boundary-append-00000005"))
        .expect("append the post-rotation op");
    let page = runtime
        .block_on(client.pull(&token, &channel_id, 0, None, None, "boundary-pull-00000006"))
        .expect("pull the post-rotation op back");
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[1].envelope.ciphertext, post[0].ciphertext);

    // --- stop the relay cleanly: the drain checkpoints the WAL.
    let data_dir = server.data_dir.clone();
    let output = server.stop();
    assert!(
        output.status.success(),
        "the relay exited non-zero on SIGTERM: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // A beat lets the proxy's tee tasks observe the final EOF.
    std::thread::sleep(Duration::from_millis(300));

    // --- the three surfaces.
    let db = dir_bytes(&data_dir);
    let log = logs(&output);
    let traffic = proxy.traffic.snapshot();
    // The scan is not vacuous: the ciphertext and the message ids the relay
    // stores DO appear in the database and the traffic — the server is a
    // ciphertext boundary, not a black hole.
    assert!(
        windows_contain(&traffic, pre[0].ciphertext.as_bytes()),
        "the traffic must carry the ciphertext"
    );
    assert!(
        windows_contain(&db, pre[0].message_id.as_bytes()),
        "the database must hold the envelope message ids"
    );
    assert!(
        windows_contain(&traffic, pre[0].message_id.as_bytes()),
        "the traffic must carry the envelope message ids"
    );

    // The three secrets, each in every shape it could leak in, on every
    // surface.
    let code_needle = code.as_bytes();
    let pre_marker = MARKER_PRE.as_bytes();
    let post_marker = MARKER_POST.as_bytes();
    for (surface_name, surface) in [
        ("database", db.as_slice()),
        ("log stream", log.as_slice()),
        ("traffic", traffic.as_slice()),
    ] {
        assert_absent(surface_name, surface, "the pairing short code", code_needle);
        assert_absent(surface_name, surface, "the pre-rotation marker", pre_marker);
        assert_absent(
            surface_name,
            surface,
            "the post-rotation marker",
            post_marker,
        );
        for key_needle in key_needles(&KEY_EPOCH_1) {
            assert_absent(surface_name, surface, "the epoch-1 group key", &key_needle);
        }
        for key_needle in key_needles(&key_epoch_2) {
            assert_absent(surface_name, surface, "the epoch-2 group key", &key_needle);
        }
    }

    std::fs::remove_dir_all(&root).ok();
}
