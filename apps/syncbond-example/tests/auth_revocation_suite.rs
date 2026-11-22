//! Acceptance (todo.md DSR-46): authorization and revocation pinned over the
//! real network.
//!
//! DSR-19 proved the route semantics as handler-level tests. This suite pins
//! the client-visible contract over the same shape as production — a relay
//! booted from a directory and the real `RelayClient` — plus the one surface
//! only a live socket exercises: a subscription revoked away from under a
//! subscriber, and a removed member who keeps pulling the channel after the
//! group's key rotated.
//!
//! Scenarios (the acceptance list, one test each):
//!   1. unauthenticated and cross-channel calls — an empty token is 401, an
//!      unknown token is 401, a valid token without the scope or on the
//!      wrong channel is 403, and the same token on its own channel works;
//!   2. revocation of a live events stream — a subscribed pull credential
//!      that is revoked is refused (401) for further calls, gets one
//!      `error` message then a 4401 close on the next push, while a sibling
//!      subscription on the same channel is untouched; revoking again is
//!      200 and revoking an unknown id is 401;
//!   3. a removed member reading the relay channel cannot open post-rotation
//!      data — `rotate_for_removal` delivers the new epoch only to
//!      survivors, the removed device (its credential still valid) pulls
//!      the channel, opens the pre-rotation envelope, and refuses the
//!      post-rotation one (`MissingKeyEpoch`), with the new key never in
//!      the clear on the channel.
//!
//! Everything here is deterministic and typed: a failed assertion is a test
//! panic, never a silent skip.

use std::collections::{BTreeSet, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use futures_util::StreamExt as _;
use syncbond_core::member_crypto::MemberKeyRing;
use syncbond_core::member_distribution::{deliver_rotation, MemberChannel, MemberChannelError};
use syncbond_core::replication::Replicator;
use syncbond_core::{open_operations, seal_operations, BatchError, DeviceIdentity, KeyRing};
use syncbond_relay_client::{RelayClient, RelayClientError, TlsPolicy};
use syncbond_relay_protocol::dto::{CredentialScope, Envelope};
use syncbond_relay_protocol::error::RelayErrorCode;
use syncbond_server::test_support::{boot_relay, TestRelay};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// The replication group every in-process device in the rotation scenario
/// shares (the demo group id; the relay never sees it).
const GROUP_ID: &str = "auth-revocation-group";
/// The shared epoch-1 group key. Constant because the in-process devices
/// bypass pairing and must agree with each other.
const KEY: [u8; 32] = [0x42; 32];

/// One events-stream subscription, owned by the test.
type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

// ===========================================================================
// Client and provisioning helpers
// ===========================================================================

/// A fresh current-thread runtime for the test's blocking calls.
fn new_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
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
        .block_on(client.create_channel(admin, &format!("auth-create-{counter:08}")))
        .expect("channel creation");
    let (_, token) = issue(
        runtime,
        client,
        admin,
        &channel.channel_id,
        &[CredentialScope::Append, CredentialScope::Pull],
        counter + 1000,
    );
    (channel.channel_id, token)
}

/// One credential on an existing channel; returns (credentialId, token).
fn issue(
    runtime: &tokio::runtime::Runtime,
    client: &RelayClient,
    admin: &str,
    channel_id: &str,
    scopes: &[CredentialScope],
    counter: u64,
) -> (String, String) {
    let issued = runtime
        .block_on(client.issue_credential(
            admin,
            channel_id,
            scopes,
            Some("auth-revocation"),
            &format!("auth-issue-{counter:08}"),
        ))
        .expect("credential issuance");
    (issued.credential_id, issued.token)
}

/// Assert a relay refusal carries the exact code and HTTP status.
fn assert_refused(error: RelayClientError, code: RelayErrorCode, status: u16) {
    match error {
        RelayClientError::Relay {
            code: got_code,
            status: got_status,
            ..
        } => {
            assert_eq!(got_code, code, "wrong error code");
            assert_eq!(got_status, status, "wrong HTTP status");
        }
        other => panic!("expected a relay refusal, got {other:?}"),
    }
}

// ===========================================================================
// The events-stream client (the only socket surface the relay-client crate
// does not drive): subscribes to a channel's live stream with a bearer
// credential, exactly as the transport-ws driver does over a real socket.
// ===========================================================================

/// Subscribe to `/v1/channels/{channel}/events` with a bearer credential.
async fn ws_events(address: &str, channel: &str, token: &str) -> WsStream {
    let mut request = format!("ws://{address}/v1/channels/{channel}/events")
        .into_client_request()
        .expect("the events URL builds a request");
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("a token is header-safe"),
    );
    let (socket, _response) = connect_async(request)
        .await
        .expect("a pull credential subscribes");
    socket
}

/// The next server message as JSON, with a budget: a silent stream fails
/// the test instead of hanging CI.
async fn next_json(socket: &mut WsStream) -> serde_json::Value {
    let frame = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .unwrap_or_else(|_| panic!("the events stream went silent"));
    match frame {
        Some(Ok(WsMessage::Text(text))) => serde_json::from_str(text.as_str()).expect("json"),
        other => panic!("expected a text message, got {other:?}"),
    }
}

/// The next close frame's code, with the same budget.
async fn next_close(socket: &mut WsStream) -> u16 {
    let frame = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .unwrap_or_else(|_| panic!("the events stream never closed"));
    match frame {
        Some(Ok(WsMessage::Close(Some(frame)))) => u16::from(frame.code),
        other => panic!("expected a close frame, got {other:?}"),
    }
}

// ===========================================================================
// Scenario 1: unauthenticated and cross-channel calls
// ===========================================================================

#[test]
fn unauthenticated_and_cross_channel_calls_are_refused() {
    let relay = boot_relay();
    let runtime = new_runtime();
    let client = relay_client(&relay);
    let (channel_a, token_a) = provision(&runtime, &client, &relay.admin, 1);
    let (channel_b, _token_b) = provision(&runtime, &client, &relay.admin, 2);

    // An empty token is an absent credential: 401, never a digest lookup.
    let err = runtime
        .block_on(client.pull("", &channel_a, 0, None, None, "auth-1"))
        .unwrap_err();
    assert_refused(err, RelayErrorCode::Unauthorized, 401);
    // An unknown token is deliberately the same as a revoked one: 401.
    let err = runtime
        .block_on(client.pull("garbage-token", &channel_a, 0, None, None, "auth-2"))
        .unwrap_err();
    assert_refused(err, RelayErrorCode::Unauthorized, 401);

    // A pull-only credential cannot append: 403 (missing scope), even with
    // a well-formed envelope in the batch.
    let envelopes = seal_one(&keyring_epoch1(), "unauth-device", "auth/scope");
    let pull_only = issue(
        &runtime,
        &client,
        &relay.admin,
        &channel_a,
        &[CredentialScope::Pull],
        3,
    );
    let err = runtime
        .block_on(client.append(&pull_only.1, &channel_a, &envelopes, "auth-3"))
        .unwrap_err();
    assert_refused(err, RelayErrorCode::Forbidden, 403);

    // A credential for channel A on channel B is forbidden: 403 — the
    // refusal names the channel, not the credential.
    let err = runtime
        .block_on(client.pull(&token_a, &channel_b, 0, None, None, "auth-4"))
        .unwrap_err();
    assert_refused(err, RelayErrorCode::Forbidden, 403);
    // The same token on its own channel succeeds.
    let page = runtime
        .block_on(client.pull(&token_a, &channel_a, 0, None, None, "auth-5"))
        .expect("the credential works on its own channel");
    assert!(page.entries.is_empty());
}

// ===========================================================================
// Scenario 2: revocation of a live events stream
// ===========================================================================

#[test]
fn revoking_a_credential_disconnects_its_live_stream() {
    let relay = boot_relay();
    let runtime = new_runtime();
    let client = relay_client(&relay);
    let (channel, _token) = provision(&runtime, &client, &relay.admin, 4);
    // The credential that will be revoked, and a sibling that must survive.
    let (revoked_id, revoked_token) = issue(
        &runtime,
        &client,
        &relay.admin,
        &channel,
        &[CredentialScope::Append, CredentialScope::Pull],
        5,
    );
    let (_kept_id, kept_token) = issue(
        &runtime,
        &client,
        &relay.admin,
        &channel,
        &[CredentialScope::Pull],
        6,
    );
    // A separate writer credential, never revoked, that triggers the push.
    let writer_token = issue(
        &runtime,
        &client,
        &relay.admin,
        &channel,
        &[CredentialScope::Append],
        7,
    )
    .1;

    runtime.block_on(async {
        let mut revoked = ws_events(&relay.address, &channel, &revoked_token).await;
        let mut kept = ws_events(&relay.address, &channel, &kept_token).await;
        assert_eq!(next_json(&mut revoked).await["type"], "events.subscribed");
        assert_eq!(next_json(&mut kept).await["type"], "events.subscribed");

        // Revoke: 200, and the credential is gone for every later call.
        let reply = client
            .revoke_credential(&relay.admin, &channel, &revoked_id)
            .await
            .expect("revocation succeeds");
        assert_eq!(reply.revoked, revoked_id);
        let err = client
            .append(
                &revoked_token,
                &channel,
                &seal_one(&keyring_epoch1(), "revoked-writer", "auth/revoked"),
                "rev-1",
            )
            .await
            .unwrap_err();
        assert_refused(err, RelayErrorCode::Unauthorized, 401);
        let err = client
            .pull(&revoked_token, &channel, 0, None, None, "rev-2")
            .await
            .unwrap_err();
        assert_refused(err, RelayErrorCode::Unauthorized, 401);

        // The push that follows the revocation kills the revoked stream:
        // one `error`, then the 4401 close. The sibling is untouched.
        client
            .append(
                &writer_token,
                &channel,
                &seal_one(&keyring_epoch1(), "live-writer", "auth/push"),
                "rev-3",
            )
            .await
            .expect("the writer pushes");
        let error = next_json(&mut revoked).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(next_close(&mut revoked).await, 4401);
        let hint = next_json(&mut kept).await;
        assert_eq!(hint["type"], "channel.appended");
        assert_eq!(hint["seq"], 1);

        // Revoking again is not an error (already-revoked); an unknown id is.
        let reply = client
            .revoke_credential(&relay.admin, &channel, &revoked_id)
            .await
            .expect("revoking again is idempotent");
        assert_eq!(reply.revoked, revoked_id);
        let err = client
            .revoke_credential(&relay.admin, &channel, "unknown-credential")
            .await
            .unwrap_err();
        assert_refused(err, RelayErrorCode::Unauthorized, 401);
    });
}

// ===========================================================================
// Scenario 3: a removed member cannot open post-rotation data
// ===========================================================================

/// The replication keyring at epoch 1 (the one every device in the group
/// carries before any rotation).
fn keyring_epoch1() -> KeyRing {
    KeyRing::with_epoch(GROUP_ID, 1, KEY)
}

/// One member ring for `device` over the given member identities, epoch 1.
fn member_ring(device: &DeviceIdentity, members: &[&DeviceIdentity]) -> MemberKeyRing {
    MemberKeyRing::with_epoch(
        GROUP_ID,
        &device.device_id,
        members.iter().map(|member| member.device_id.clone()),
        members
            .iter()
            .map(|member| (member.device_id.clone(), member.public_key)),
        1,
        KEY,
    )
    .expect("shared group state")
}

/// Seal one locally generated operation under `keyring` into wire envelopes.
fn seal_one(keyring: &KeyRing, device_id: &str, key: &str) -> Vec<Envelope> {
    let mut replicator = Replicator::new(device_id.to_owned());
    let op = replicator.put(key.to_owned(), b"v".to_vec()).expect("put");
    seal_operations(&[op], keyring, device_id)
        .expect("seal")
        .into_iter()
        .flatten()
        .collect()
}

/// The application's per-device pairwise channels. Only survivors are
/// bound; the removed member is never asked.
#[derive(Default)]
struct SurvivorChannels {
    bound: BTreeSet<String>,
    delivered: Mutex<Vec<(String, Vec<u8>)>>,
}

impl SurvivorChannels {
    fn for_devices(devices: &[&str]) -> Self {
        Self {
            bound: devices.iter().map(|device| (*device).to_owned()).collect(),
            delivered: Mutex::new(Vec::new()),
        }
    }
}

impl MemberChannel for SurvivorChannels {
    fn deliver(&self, device_id: &str, bytes: &[u8]) -> Result<(), MemberChannelError> {
        if !self.bound.contains(device_id) {
            return Err(MemberChannelError::NotRecipient {
                bound: "no pairwise channel".into(),
                asked: device_id.to_owned(),
            });
        }
        self.delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((device_id.to_owned(), bytes.to_vec()));
        Ok(())
    }
}

#[test]
fn a_removed_member_pulling_the_channel_cannot_open_post_rotation_data() {
    let relay = boot_relay();
    let runtime = new_runtime();
    let client = relay_client(&relay);
    let (channel, token) = provision(&runtime, &client, &relay.admin, 8);

    // Group A/B/C, each member ring at epoch 1 with the shared key.
    let identities = [
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
    ];
    let members = [&identities[0], &identities[1], &identities[2]];
    let mut a = member_ring(&identities[0], &members);
    let mut b = member_ring(&identities[1], &members);
    let c = member_ring(&identities[2], &members);

    // A seals a pre-rotation op under the epoch-1 key — the envelope a
    // current member (C included) opens.
    let before = seal_one(&keyring_epoch1(), &identities[0].device_id, "pre-rotation");
    runtime
        .block_on(client.append(&token, &channel, &before, "rot-1"))
        .expect("append the pre-rotation op");

    // The rotation: removes C, mints the epoch-2 key, delivers only to the
    // survivors — C is never asked, so it never holds the new key.
    let result = a
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .expect("rotate");
    assert_eq!(result.epoch, 2);
    assert_eq!(result.removed_device_id, identities[2].device_id);
    let router =
        SurvivorChannels::for_devices(&[&identities[0].device_id, &identities[1].device_id]);
    let delivered = deliver_rotation(&router, &result).expect("the survivors are delivered");
    assert_eq!(delivered, result.member_ids);
    b.apply_rotation(&result.distribution).expect("B installs");
    assert_eq!(a.current_epoch(), 2);
    assert_eq!(b.current_epoch(), 2);
    assert_eq!(c.current_epoch(), 1, "the removed device never advanced");

    // A seals a post-rotation op under the epoch-2 key (the rebuild any
    // survivor performs from its advanced member ring).
    let key_epoch2 = KeyRing::with_epoch(GROUP_ID, 2, result.key);
    let after = seal_one(&key_epoch2, &identities[0].device_id, "post-rotation");
    runtime
        .block_on(client.append(&token, &channel, &after, "rot-2"))
        .expect("append the post-rotation op");

    // C's channel credential was never revoked — only its membership — so
    // it still pulls the whole channel log.
    let page = runtime
        .block_on(client.pull(&token, &channel, 0, None, None, "rot-3"))
        .expect("the removed device still pulls");
    assert_eq!(page.entries.len(), 2);

    // C still holds the epoch-1 key: the pre-rotation envelope opens...
    let mut seen = HashSet::new();
    let opened = open_operations(
        std::slice::from_ref(&page.entries[0].envelope),
        &keyring_epoch1(),
        &mut seen,
    )
    .expect("the removed device opens the pre-rotation op");
    assert_eq!(opened[0].key, "pre-rotation");
    // ...but the post-rotation one names an epoch C never received.
    let mut seen = HashSet::new();
    let error = open_operations(
        std::slice::from_ref(&page.entries[1].envelope),
        &keyring_epoch1(),
        &mut seen,
    )
    .expect_err("the post-rotation op must not open");
    assert!(matches!(error, BatchError::MissingKeyEpoch(2)));

    // The new key never appears in the clear in any byte C pulled — the
    // relay channel carries ciphertext, and the rotation record (which
    // carries the key) never rode it.
    for entry in &page.entries {
        let wire = serde_json::to_vec(&entry.envelope).expect("the wire envelope serializes");
        assert!(
            !wire.windows(32).any(|window| window == &result.key[..]),
            "the new key must not ride the channel"
        );
    }
}
