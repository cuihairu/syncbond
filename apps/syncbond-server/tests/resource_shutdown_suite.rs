//! Acceptance (todo.md DSR-48): the server's resource and shutdown bounds,
//! over the real binary.
//!
//! DSR-23 and DSR-24 proved each bound as handler-level tests with injected
//! budgets. This suite pins the same bounds over the deliverable process —
//! the real binary, a real config per scenario, real sockets — so each
//! condition is reproducible end to end:
//!
//!   - 巨帧: an append body past the frozen 16 MiB request-body cap is
//!     refused with a bounded 413 (the route never runs), and a WebSocket
//!     message past the socket cap ends that socket without hanging the
//!     server;
//!   - 慢客户端: a client that trickles its request headers is cut within
//!     the configured header budget;
//!   - 队列饱和: a pairing peer that floods faster than its roommate
//!     drains saturates the frozen outbound queue budget; the slow end,
//!     once it drains, is closed with 1013 (a declared failure), the
//!     flooding end then sees 1001, and the server keeps serving;
//!   - 配额耗尽: past the configured channel byte budget, appends are
//!     refused with 507 `quota_exceeded` while reads and the admin face
//!     keep working;
//!   - 中途关闭: a SIGTERM under a live events subscription closes it with
//!     1001, refuses new connections, exits 0 within the budget, and every
//!     ACKed envelope survives a restart on the same data directory.
//!
//! Every budget here has a deadline: a hung condition fails the test, it
//! never blocks CI.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use futures_util::SinkExt as _;
use futures_util::StreamExt as _;
use syncbond_core::replication::Replicator;
use syncbond_core::{seal_operations, KeyRing};
use syncbond_relay_client::{RelayClient, RelayClientError, TlsPolicy};
use syncbond_relay_protocol::dto::{CredentialScope, Envelope};
use syncbond_relay_protocol::error::RelayErrorCode;
use syncbond_relay_protocol::limits::PAIRING_FRAME_MAX_BYTES;
use syncbond_transport_ws::{create_invite, WsPairingOptions};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// The replication group for the suites' sealed envelopes (the relay never
/// sees it; the envelopes are opaque bytes to every limit here).
const GROUP_ID: &str = "resource-shutdown-group";
/// The epoch-1 key the sealed envelopes ride under.
const KEY: [u8; 32] = [0x43; 32];

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

// ===========================================================================
// The real server process, one tailored config per scenario
// ===========================================================================

/// Pick an ephemeral loopback port (the test owns it; the relay binds it
/// right after).
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
    listener.local_addr().expect("probe address").port()
}

/// The deliverable relay binary as its own process over `data_dir`, with a
/// fresh config tuned per scenario. A restart on the same `data_dir` reuses
/// the database and the bootstrap admin credential.
struct ServerProcess {
    child: Option<Child>,
    address: String,
    /// The bootstrap admin credential (read from the file the store wrote).
    admin: String,
}

impl ServerProcess {
    fn boot(data_dir: &Path, tune: impl Fn(&mut serde_json::Value)) -> Self {
        // `free_port()` returns a number whose probe socket is already
        // dropped, and a sibling suite probing at the same moment can be
        // handed that same number. Our child then loses the bind and exits,
        // so the listener that answers is a *foreign* relay holding a
        // different admin credential — the first admin call comes back 401
        // "admin credential required". A live child is the only proof the
        // port is ours, so a fresh port fixes every collision.
        for _ in 0..8 {
            if let Some(server) = Self::boot_once(data_dir, &tune) {
                return server;
            }
        }
        panic!("no free relay port: every candidate was claimed by another server");
    }

    fn boot_once(data_dir: &Path, tune: &impl Fn(&mut serde_json::Value)) -> Option<Self> {
        std::fs::create_dir_all(data_dir).expect("the data directory exists");
        let port = free_port();
        // The same closed config shape the binary validates; the shutdown
        // budget is small because every scenario's drain is trivial.
        let mut config = serde_json::json!({
            "listen": format!("127.0.0.1:{port}"),
            "dataDir": data_dir.to_str().expect("a utf-8 data dir"),
            "shutdownTimeoutSeconds": 2,
        });
        tune(&mut config);
        let config_path = data_dir.join(format!("config-{port}.json"));
        std::fs::write(&config_path, config.to_string()).expect("the config writes");
        let mut child = Command::new(env!("CARGO_BIN_EXE_syncbond-server"))
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the relay binary starts");
        // Readiness is the listener accepting plus the admin credential on
        // disk — never before both. The store writes the credential before
        // it binds, so a listening socket plus a credential is not yet proof
        // that either came from *this* child: hold the port a moment and
        // require the child to still be alive to claim it.
        let admin_path = syncbond_server::sqlite::admin_credential_path(&data_dir.join("relay.db"));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let listening = TcpStream::connect(("127.0.0.1", port)).is_ok();
            if listening && admin_path.exists() {
                for _ in 0..5 {
                    if child.try_wait().is_ok_and(|status| status.is_some()) {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                let admin =
                    std::fs::read_to_string(&admin_path).expect("the admin credential reads");
                return Some(Self {
                    child: Some(child),
                    address: format!("127.0.0.1:{port}"),
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

    /// SIGTERM (the container-runtime stop), wait for the bounded drain,
    /// and return everything the process emitted.
    fn stop(mut self) -> Output {
        let child = self.child.take().expect("the server is still running");
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let (tx, rx) = std::sync::mpsc::channel::<Output>();
        std::thread::spawn(move || {
            let output = child.wait_with_output().expect("the relay io ends");
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
// Shared drivers
// ===========================================================================

/// A multi-thread runtime: the shutdown scenario blocks its calling thread
/// inside `block_on` while the sockets still need polling.
fn new_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("the test runtime")
}

/// A client over the plain loopback relay.
fn relay_client(address: &str) -> RelayClient {
    RelayClient::new(
        &format!("http://{address}"),
        TlsPolicy::Validate,
        Duration::from_secs(10),
    )
    .expect("a loopback location parses")
}

/// One channel and one Append+Pull credential through the admin API.
fn provision(
    runtime: &tokio::runtime::Runtime,
    client: &RelayClient,
    admin: &str,
    counter: u64,
) -> (String, String) {
    let channel = runtime
        .block_on(client.create_channel(admin, &format!("res-create-{counter:08}")))
        .expect("channel creation");
    let issued = runtime
        .block_on(client.issue_credential(
            admin,
            &channel.channel_id,
            &[CredentialScope::Append, CredentialScope::Pull],
            Some("resource-shutdown"),
            &format!("res-issue-{counter:08}"),
        ))
        .expect("credential issuance");
    (channel.channel_id, issued.token)
}

/// One small real envelope (a sealed op), for liveness checks.
fn small_envelope(device_id: &str, key: &str) -> Vec<Envelope> {
    let mut replicator = Replicator::new(device_id.to_owned());
    let op = replicator.put(key.to_owned(), b"v".to_vec()).expect("put");
    seal_operations(&[op], &KeyRing::with_epoch(GROUP_ID, 1, KEY), device_id)
        .expect("seal")
        .into_iter()
        .flatten()
        .collect()
}

/// A scratch root per test, cleaned up by the test's last line.
fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "syncbond-res-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("the scratch root exists");
    root
}

// ===========================================================================
// Raw socket and WebSocket helpers (the surfaces the client crate does not
// drive)
// ===========================================================================

/// Subscribe to `/v1/channels/{channel}/events` (or a pairing room) with a
/// bearer credential, over a real socket.
async fn ws_connect(address: &str, path: &str, token: &str) -> WsStream {
    let mut request = format!("ws://{address}{path}")
        .into_client_request()
        .expect("the url builds a request");
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("a token is header-safe"),
    );
    let (socket, _response) = connect_async(request).await.expect("the upgrade completes");
    socket
}

/// The next server text frame as JSON, with a budget.
async fn next_text(socket: &mut WsStream) -> serde_json::Value {
    let frame = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .unwrap_or_else(|_| panic!("the stream went silent"));
    match frame {
        Some(Ok(WsMessage::Text(text))) => serde_json::from_str(text.as_str()).expect("json"),
        other => panic!("expected a text message, got {other:?}"),
    }
}

/// Drain a socket until it ends and report the close code (0 when the
/// socket died without one). Every read carries a budget; a silent socket
/// fails the test instead of hanging it.
async fn drain_until_close(socket: &mut WsStream) -> (u16, usize) {
    let started = Instant::now();
    let mut frames = 0;
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the socket never ended: {frames} frames in {:?}",
            started.elapsed()
        );
        let frame = tokio::time::timeout(Duration::from_secs(10), socket.next()).await;
        match frame {
            Ok(Some(Ok(WsMessage::Close(Some(frame))))) => return (u16::from(frame.code), frames),
            Ok(Some(Ok(WsMessage::Close(None)))) => return (0, frames),
            Ok(Some(Ok(_))) => frames += 1,
            Ok(Some(Err(_))) | Ok(None) => return (0, frames),
            Err(_) => panic!("the stream went silent after {frames} frames"),
        }
    }
}

// ===========================================================================
// 巨帧: a body past the frozen request cap is a bounded 413
// ===========================================================================

#[test]
fn a_giant_request_body_is_refused_bounded_and_the_server_survives() {
    let root = scratch("body-cap");
    let server = ServerProcess::boot(&root.join("data"), |_| {});
    let runtime = new_runtime();
    let client = relay_client(&server.address);
    let (channel, token) = provision(&runtime, &client, &server.admin, 1);

    // Push 16 MiB + 1 of body through a raw socket: the transport-layer cap
    // answers 413 without the route ever running. The server may cut the
    // connection mid-write, so a broken write is the refusal arriving, not
    // a failure.
    let mut stream = TcpStream::connect(&server.address).expect("the socket connects");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("a write budget");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read budget");
    let body_len = 16 * 1024 * 1024 + 1;
    let head = format!(
        "POST /v1/channels/{channel}/append HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n",
        server.address
    );
    stream.write_all(head.as_bytes()).expect("the head writes");
    let chunk = vec![b'x'; 1024 * 1024];
    let mut sent = 0usize;
    while sent < body_len {
        let take = (body_len - sent).min(chunk.len());
        if stream.write_all(&chunk[..take]).is_err() {
            break;
        }
        sent += take;
    }
    drop(chunk);
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status = response.lines().next().unwrap_or_default();
    assert!(
        status.contains("413"),
        "a body past the frozen cap must be a bounded 413, got {status:?} ({response:?})"
    );

    // The refusal did not wound the server: a normal append still lands.
    let envelopes = small_envelope("giant-liveness", "giant/alive");
    let ack = runtime
        .block_on(client.append(&token, &channel, &envelopes, "giant-1"))
        .expect("a normal append still works");
    assert_eq!(ack.acks.len(), 1);

    drop(server);
    std::fs::remove_dir_all(&root).ok();
}

// ===========================================================================
// 巨帧 (socket side): a WebSocket message past the socket cap is a bounded
// end, not a hang
// ===========================================================================

#[test]
fn an_oversized_websocket_frame_ends_the_socket_without_hanging_the_server() {
    let root = scratch("ws-cap");
    let server = ServerProcess::boot(&root.join("data"), |_| {});
    let runtime = new_runtime();
    let client = relay_client(&server.address);
    let (channel, token) = provision(&runtime, &client, &server.admin, 2);

    runtime.block_on(async {
        let mut socket = ws_connect(
            &server.address,
            &format!("/v1/channels/{channel}/events"),
            &token,
        )
        .await;
        let greeting = next_text(&mut socket).await;
        assert_eq!(greeting["type"], "events.subscribed");

        // One message past the server's socket cap (the cap itself is
        // derived from the frozen pairing frame maximum). The server ends
        // the socket — mid-send if the cap trips before the write drains
        // — but never silence. Either outcome is the bounded kill.
        let oversized = "a".repeat(PAIRING_FRAME_MAX_BYTES / 3 * 4 + 4096 + 4096);
        let _ = socket.send(WsMessage::Text(oversized.into())).await;
        let ended = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(frame) = socket.next().await {
                let _ = frame;
            }
        })
        .await;
        assert!(ended.is_ok(), "the oversized frame left the socket hanging");
    });

    // The server keeps serving after the bounded kill.
    let envelopes = small_envelope("ws-cap-liveness", "ws/alive");
    let ack = runtime
        .block_on(client.append(&token, &channel, &envelopes, "ws-1"))
        .expect("a normal append still works");
    assert_eq!(ack.acks.len(), 1);

    drop(server);
    std::fs::remove_dir_all(&root).ok();
}

// ===========================================================================
// 慢客户端: a trickling header writer is cut within the header budget
// ===========================================================================

#[test]
fn a_slow_trickling_client_is_cut_within_the_header_timeout() {
    let root = scratch("header-timeout");
    let server = ServerProcess::boot(&root.join("data"), |config| {
        config["headerTimeoutSeconds"] = serde_json::json!(1);
    });

    let started = Instant::now();
    let mut stream = TcpStream::connect(&server.address).expect("the socket connects");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("a write budget");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a read budget");
    // A fraction of the headers, then stall forever: the slow client.
    stream
        .write_all(b"POST /v1/channels/x/messages HTTP/1.1\r\nHost: l")
        .expect("the head fragment writes");
    let mut drained = String::new();
    let _ = stream.read_to_string(&mut drained);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "a trickling header must be cut within the budget, survived {elapsed:?}"
    );

    drop(server);
    std::fs::remove_dir_all(&root).ok();
}

// ===========================================================================
// 队列饱和: the flooder's slow roommate is closed 1013 once it drains
// ===========================================================================

#[test]
fn a_flooding_peer_saturates_the_queue_and_the_slow_end_is_closed_1013() {
    let root = scratch("queue-saturation");
    let server = ServerProcess::boot(&root.join("data"), |_| {});
    let runtime = new_runtime();
    let client = relay_client(&server.address);
    let (channel, token) = provision(&runtime, &client, &server.admin, 3);

    // A real pairing room through the real transport: the invite carries
    // the room id and the capability both participants join with.
    let options = WsPairingOptions {
        relay_url: format!("http://{}", server.address),
        ..Default::default()
    };
    let invite = runtime
        .block_on(create_invite(&options))
        .expect("the room is created");
    let address = server.address.clone();

    runtime.block_on(async {
        let mut host = ws_connect(
            &address,
            &format!("/v1/pairing/{}", invite.room_id),
            &invite.capability,
        )
        .await;
        let greeting = next_text(&mut host).await;
        assert!(greeting.get("roomId").is_some(), "the host joined the room");
        // The roommate joins and then stops reading: everything the host
        // floods lands in the server's outbound queue for it.
        let mut slow = ws_connect(
            &address,
            &format!("/v1/pairing/{}", invite.room_id),
            &invite.capability,
        )
        .await;
        let greeting = next_text(&mut slow).await;
        assert!(
            greeting.get("roomId").is_some(),
            "the roommate joined the room"
        );

        // Flood far past the frozen outbound queue budget (~17 MiB): each
        // pairing.frame forwards as ~2.7 MiB of text, so twenty-four of
        // them (~65 MiB) outrun the queue plus whatever the kernel buffers
        // absorb on a socket the peer never reads.
        use base64::Engine as _;
        let payload = vec![0xABu8; 2 * 1024 * 1024];
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload);
        let frame =
            format!("{{\"protocolVersion\":1,\"type\":\"pairing.frame\",\"data\":\"{data}\"}}");
        for _ in 0..24 {
            host.send(WsMessage::Text(frame.clone().into()))
                .await
                .expect("the flood frame sends");
        }

        // The slow end finally drains: everything queued, then the declared
        // failure — close 1013, the bounded end of a saturated queue.
        let (code, frames) = drain_until_close(&mut slow).await;
        assert_eq!(code, 1013, "the saturated queue ends with 1013");
        assert!(frames > 0, "the drained frames arrived first");

        // A compliant client echoes the close it was given; until the
        // roommate's connection actually ends the server keeps its session
        // alive, and the flooder would never learn it left. The echo ends
        // the room: the flooder's own socket closes 1001, not a reset.
        let _ = slow.send(WsMessage::Close(None)).await;
        drop(slow);
        let (code, _frames) = drain_until_close(&mut host).await;
        assert_eq!(code, 1001, "the flooding end sees its roommate leave");
    });

    // The server kept serving throughout: a normal append still lands.
    let envelopes = small_envelope("flood-liveness", "flood/alive");
    let ack = runtime
        .block_on(client.append(&token, &channel, &envelopes, "flood-1"))
        .expect("a normal append still works");
    assert_eq!(ack.acks.len(), 1);

    drop(server);
    std::fs::remove_dir_all(&root).ok();
}

// ===========================================================================
// 配额耗尽: 507 past the channel budget, reads and admin untouched
// ===========================================================================

/// A schema-valid envelope with a `ciphertext` of `bytes` characters — the
/// quota counts stored bytes, and the crypto is the clients' business.
fn big_envelope(message_id: &str, bytes: usize) -> Envelope {
    Envelope {
        protocol_version: 1,
        group_id: GROUP_ID.to_owned(),
        sender_device_id: "quota-sender".to_owned(),
        key_epoch: 1,
        message_id: message_id.to_owned(),
        nonce: "nonce-quota-0000000000".to_owned(),
        ciphertext: "A".repeat(bytes),
    }
}

#[test]
fn a_channel_quota_exhaustion_refuses_appends_but_reads_and_admin_survive() {
    let root = scratch("quota");
    // The config floor: a channel budget of one maximal envelope.
    let budget = syncbond_relay_protocol::limits::MAX_ENVELOPE_BYTES as u64;
    let server = ServerProcess::boot(&root.join("data"), |config| {
        config["channelQuotaBytes"] = serde_json::json!(budget);
    });
    let runtime = new_runtime();
    let client = relay_client(&server.address);
    let (channel, token) = provision(&runtime, &client, &server.admin, 4);

    // Under the budget: lands and is ACKed.
    let first = big_envelope("m_quota_under_budget_0001", 2_400_000);
    let ack = runtime
        .block_on(client.append(&token, &channel, std::slice::from_ref(&first), "quota-1"))
        .expect("the under-budget append lands");
    assert_eq!(ack.acks.len(), 1);

    // Past the budget: the whole batch rolls back with 507
    // quota_exceeded — a bounded refusal, never a partial write.
    let second = big_envelope("m_quota_over_budget_0002", 2_400_000);
    let error = runtime
        .block_on(client.append(&token, &channel, &[second], "quota-2"))
        .unwrap_err();
    match error {
        RelayClientError::Relay { code, status, .. } => {
            assert_eq!(code, RelayErrorCode::QuotaExceeded);
            assert_eq!(status, 507);
        }
        other => panic!("expected a quota refusal, got {other:?}"),
    }

    // Reads are never blocked by a quota: the stored envelope pulls back.
    let page = runtime
        .block_on(client.pull(&token, &channel, 0, None, None, "quota-3"))
        .expect("reads survive the exhausted quota");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].envelope.ciphertext, first.ciphertext);
    // And the admin face keeps working on a full channel.
    let issued = runtime
        .block_on(client.issue_credential(
            &server.admin,
            &channel,
            &[CredentialScope::Pull],
            Some("resource-shutdown"),
            "quota-4",
        ))
        .expect("the admin face survives the exhausted quota");
    assert!(!issued.token.is_empty());

    drop(server);
    std::fs::remove_dir_all(&root).ok();
}

// ===========================================================================
// 中途关闭: 1001 goodbye, refused connects, exit 0, ACKed data survives
// ===========================================================================

#[test]
fn a_midflight_shutdown_is_bounded_and_acked_data_survives_restart() {
    let root = scratch("shutdown");
    let data_dir = root.join("data");
    let server = ServerProcess::boot(&data_dir, |_| {});
    let runtime = new_runtime();
    let client = relay_client(&server.address);
    let (channel, token) = provision(&runtime, &client, &server.admin, 5);

    // Three ACKed envelopes before any signal.
    for index in 1..=3 {
        let envelopes = small_envelope("shutdown-writer", &format!("shutdown/{index}"));
        let ack = runtime
            .block_on(client.append(&token, &channel, &envelopes, &format!("down-{index}")))
            .expect("the append lands");
        assert_eq!(ack.acks.len(), 1);
    }

    // The stop consumes the process; the block owns the subscription.
    let address = server.address.clone();
    let channel_ws = channel.clone();
    let token_ws = token.clone();
    runtime.block_on(async move {
        // A live subscription that must hear the goodbye.
        let mut socket = ws_connect(
            &address,
            &format!("/v1/channels/{channel_ws}/events"),
            &token_ws,
        )
        .await;
        let greeting = next_text(&mut socket).await;
        assert_eq!(greeting["type"], "events.subscribed");

        // The stop: SIGTERM, the bounded drain, the process gone.
        let started = Instant::now();
        let output = server.stop();
        assert!(
            output.status.success(),
            "the relay exited non-zero on SIGTERM: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the drain outran its budget: {:?}",
            started.elapsed()
        );

        // The live subscription ends declared: close 1001, going away.
        let (code, _frames) = drain_until_close(&mut socket).await;
        assert_eq!(code, 1001, "a live subscription hears the goodbye");
        // New connections are refused, not queued behind a dying process.
        assert!(
            TcpStream::connect(&address).is_err(),
            "a new connection must be refused once the relay stops"
        );
    });

    // Restart on the same data directory: every ACKed envelope pulls back.
    let server = ServerProcess::boot(&data_dir, |_| {});
    let runtime_after = new_runtime();
    let client_after = relay_client(&server.address);
    let page = runtime_after
        .block_on(client_after.pull(&token, &channel, 0, None, None, "down-4"))
        .expect("the restarted relay serves the channel");
    assert_eq!(page.entries.len(), 3, "every ACKed envelope survived");
    for (index, entry) in page.entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }

    drop(server);
    std::fs::remove_dir_all(&root).ok();
}
