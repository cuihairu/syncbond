//! Relay driver tests (todo.md DSR-36): the C driver drives a real relay
//! end to end - both directions sync, the host interleaves writes between
//! cycles, a restart resumes from the committed cursor without re-applying,
//! and the worker's lifecycle (start, progress, stop) is clean.
//!
//! The whole surface under test lives behind the `relay` feature (see
//! `syncbond-ffi`'s Cargo.toml), so the file compiles to nothing without it.

#![cfg(feature = "relay")]

use std::time::{Duration, Instant};

use syncbond_core::batch::seal_operations;
use syncbond_core::crypto::KeyRing;
use syncbond_core::replication::Replicator as CoreReplicator;
use syncbond_core::sync_driver::DriverConfig;
use syncbond_ffi::error::{
    SB_DRIVER_STOP_CANCELLED, SB_DRIVER_STOP_NONE, SB_ERR_INPUT, SB_STRATEGY_LWW_HLC,
    SB_TLS_VALIDATE, SB_TLS_VALIDATE_CA,
};
use syncbond_ffi::handles::{
    import_snapshot, Identity, Keyring, ReceiveState, RelayDriver, Replicator,
};
use syncbond_relay_client::{RelayClient, TlsPolicy};
use syncbond_relay_protocol::dto::CredentialScope;
use syncbond_server::test_support::boot_relay;

fn fast_config() -> DriverConfig {
    DriverConfig {
        page_limit: 2,
        max_pages_per_cycle: 8,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        max_attempts: 1000,
        idle_interval: Duration::from_millis(1),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

fn client(relay_address: &str) -> RelayClient {
    RelayClient::new(
        &format!("http://{relay_address}"),
        TlsPolicy::Validate,
        Duration::from_secs(5),
    )
    .expect("a loopback location parses")
}

/// Poll until `predicate` holds or the deadline passes.
fn wait_until(mut predicate: impl FnMut() -> bool, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    predicate()
}

/// Seal and append the peer's writes through the relay, the way an outbox
/// drain would.
#[allow(clippy::too_many_arguments)]
fn peer_appends(
    runtime: &tokio::runtime::Runtime,
    client: &RelayClient,
    append_token: &str,
    channel_id: &str,
    peer: &mut CoreReplicator,
    keyring: &KeyRing,
    prefix: &str,
    count: usize,
    request_id: &str,
) {
    let ops: Vec<_> = (0..count)
        .map(|index| {
            peer.put(
                format!("{prefix}/{index}"),
                format!("v{index}").into_bytes(),
            )
            .expect("peer write")
        })
        .collect();
    let envelopes = seal_operations(&ops, keyring, "peer")
        .expect("seals")
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let ack = runtime
        .block_on(client.append(append_token, channel_id, &envelopes, request_id))
        .expect("peer append");
    assert_eq!(ack.acks.len(), count);
}

#[test]
fn the_driver_syncs_both_directions_and_resumes_after_a_restart() {
    let relay = boot_relay();
    let runtime = runtime();
    let client = client(&relay.address);

    let channel = runtime
        .block_on(client.create_channel(&relay.admin, "r-create-00000001"))
        .expect("channel");
    let append_token = runtime
        .block_on(client.issue_credential(
            &relay.admin,
            &channel.channel_id,
            &[CredentialScope::Append],
            None,
            "r-issue-00000001",
        ))
        .expect("append credential")
        .token;
    let device_token = runtime
        .block_on(client.issue_credential(
            &relay.admin,
            &channel.channel_id,
            &[CredentialScope::Append, CredentialScope::Pull],
            Some("device-2"),
            "r-issue-00000002",
        ))
        .expect("device credential")
        .token;

    // The peer and the driver share one group key, as two devices in one
    // group would; the driver's keyring is imported with the same material.
    let shared_key = KeyRing::new("group-1");
    let shared_bytes: [u8; 32] = *shared_key.current_key();
    let peer_keyring = shared_key;
    let mut peer = CoreReplicator::new("peer");
    peer_appends(
        &runtime,
        &client,
        &append_token,
        &channel.channel_id,
        &mut peer,
        &peer_keyring,
        "note",
        3,
        "r-peer-00000001",
    );

    // The local device, driven from the C ABI driver.
    let driver = RelayDriver::new(
        &format!("http://{}", relay.address),
        &channel.channel_id,
        &device_token,
        "relay-1",
        "ch",
        "group-1",
        1,
        Identity::generate(),
        Keyring::import("group-1", 1, &shared_bytes).expect("shared key"),
        Replicator::new("local", SB_STRATEGY_LWW_HLC).expect("replicator"),
        ReceiveState::new(),
        5_000,
        SB_TLS_VALIDATE,
        &[],
    )
    .expect("driver");
    driver.set_config(fast_config());
    driver.start().expect("start");
    assert!(driver.running(), "the worker is up");

    // The host writes while the worker is running: the cycle lock is
    // released between cycles, so the write waits only for the current
    // cycle, not the whole run.
    driver.write("mine/0", b"m0").expect("write 0");
    driver.write("mine/1", b"m1").expect("write 1");

    // Both directions sync: the peer's 3 land, the 2 own outbox batches send.
    let synced = wait_until(
        || {
            let (_c, _b, sent, _p, applied) = driver.counters();
            sent >= 2 && applied >= 3
        },
        Duration::from_secs(10),
    );
    assert!(
        synced,
        "the driver synced both directions: counters={:?} running={} reason={} error={:?}",
        driver.counters(),
        driver.running(),
        driver.stop_reason(),
        driver.stop_error(),
    );
    assert_eq!(driver.get("note/2").expect("peer note"), b"v2".to_vec());
    assert_eq!(driver.get("mine/0").expect("own note"), b"m0".to_vec());
    assert_eq!(driver.get("mine/1").expect("own note"), b"m1".to_vec());

    // Clean stop: the worker joins and the reason is cancellation, not an
    // error.
    driver.stop().expect("stop");
    assert!(!driver.running(), "the worker joined");
    assert_eq!(driver.stop_reason(), SB_DRIVER_STOP_CANCELLED);
    assert!(
        driver.stop_error().is_none(),
        "a clean stop has no error text"
    );

    // The committed state round-trips as one snapshot, and the restored
    // device pulls exactly what it had not seen.
    let blob = driver.export_state().expect("snapshot");
    let (restored, restored_receive) = import_snapshot(&blob, SB_STRATEGY_LWW_HLC).expect("import");
    assert_eq!(restored.get("note/2"), Some(b"v2".to_vec()));
    assert_eq!(restored.get("mine/0"), Some(b"m0".to_vec()));
    // The channel log: 3 peer envelopes (seq 1-3) plus the local echo of
    // its own 2 (seq 4-5). The cursor names the end of that page.
    assert_eq!(
        restored_receive.server_seq("relay-1", "ch"),
        Some(5),
        "the cursor sits at the end of the first life's channel log"
    );

    // The peer sends more while the local device is down.
    peer_appends(
        &runtime,
        &client,
        &append_token,
        &channel.channel_id,
        &mut peer,
        &peer_keyring,
        "later",
        2,
        "r-peer-00000002",
    );

    // A second driver, rebuilt from the snapshot alone, resumes from the
    // committed cursor: only the 2 new envelopes apply.
    let restarted = RelayDriver::new(
        &format!("http://{}", relay.address),
        &channel.channel_id,
        &device_token,
        "relay-1",
        "ch",
        "group-1",
        1,
        Identity::generate(),
        Keyring::import("group-1", 1, &shared_bytes).expect("shared key"),
        restored,
        restored_receive,
        5_000,
        SB_TLS_VALIDATE,
        &[],
    )
    .expect("restarted driver");
    restarted.set_config(fast_config());
    restarted.start().expect("start restarted");
    // The restarted device sends nothing (its outbox is fresh) and applies
    // only the two new envelopes the peer appended while it was down.
    let caught = wait_until(
        || {
            let (_c, _b, _sent, _p, applied) = restarted.counters();
            applied == 2
        },
        Duration::from_secs(10),
    );
    assert!(
        caught,
        "only the new envelopes applied: {:?}",
        restarted.counters()
    );
    assert_eq!(restarted.get("later/0").expect("new note"), b"v0".to_vec());
    restarted.stop().expect("stop restarted");
    assert_eq!(restarted.stop_reason(), SB_DRIVER_STOP_CANCELLED);

    // The restored device can still write.
    restarted.write("after/0", b"a0").expect("write after");
    assert_eq!(restarted.get("after/0"), Some(b"a0".to_vec()));
}

#[test]
fn writes_and_deletes_are_staged_and_persisted_while_the_worker_runs() {
    let relay = boot_relay();
    let runtime = runtime();
    let client = client(&relay.address);
    let channel = runtime
        .block_on(client.create_channel(&relay.admin, "r-create-00000001"))
        .expect("channel");
    let device_token = runtime
        .block_on(client.issue_credential(
            &relay.admin,
            &channel.channel_id,
            &[CredentialScope::Append, CredentialScope::Pull],
            Some("device-2"),
            "r-issue-00000002",
        ))
        .expect("device credential")
        .token;

    let driver = RelayDriver::new(
        &format!("http://{}", relay.address),
        &channel.channel_id,
        &device_token,
        "relay-1",
        "ch",
        "group-1",
        1,
        Identity::generate(),
        Keyring::new("group-1"),
        Replicator::new("local", SB_STRATEGY_LWW_HLC).expect("replicator"),
        ReceiveState::new(),
        5_000,
        SB_TLS_VALIDATE,
        &[],
    )
    .expect("driver");
    driver.set_config(fast_config());
    driver.start().expect("start");

    driver.write("note/1", b"one").expect("write");
    assert_eq!(driver.get("note/1"), Some(b"one".to_vec()));
    driver.delete("note/1").expect("delete");
    assert_eq!(driver.get("note/1"), None, "the tombstone wins");

    // The write and the delete are both staged and sent; the worker's own
    // echo comes back and stays a no-op.
    let sent = wait_until(|| driver.counters().2 >= 2, Duration::from_secs(10));
    assert!(
        sent,
        "both envelopes left the outbox: {:?}",
        driver.counters()
    );
    driver.stop().expect("stop");
    assert_eq!(driver.stop_reason(), SB_DRIVER_STOP_CANCELLED);

    // The committed snapshot carries the tombstone, so a restart keeps the
    // delete dead.
    let blob = driver.export_state().expect("snapshot");
    let (restored, _) = import_snapshot(&blob, SB_STRATEGY_LWW_HLC).expect("import");
    assert_eq!(
        restored.get("note/1"),
        None,
        "the tombstone survives the trip"
    );
}

#[test]
fn construction_and_argument_validation() {
    // Empty ids and a zero timeout are refused before any resource is built.
    let error = RelayDriver::new(
        "http://127.0.0.1:9",
        "",
        "token",
        "s",
        "c",
        "g",
        0,
        Identity::generate(),
        Keyring::new("g"),
        Replicator::new("n", SB_STRATEGY_LWW_HLC).expect("r"),
        ReceiveState::new(),
        100,
        SB_TLS_VALIDATE,
        &[],
    )
    .err()
    .unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);

    let error = RelayDriver::new(
        "http://127.0.0.1:9",
        "ch",
        "token",
        "s",
        "c",
        "g",
        0,
        Identity::generate(),
        Keyring::new("g"),
        Replicator::new("n", SB_STRATEGY_LWW_HLC).expect("r"),
        ReceiveState::new(),
        0,
        SB_TLS_VALIDATE,
        &[],
    )
    .err()
    .unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);

    // An unknown TLS mode and a missing pinned CA are refused.
    let error = RelayDriver::new(
        "http://127.0.0.1:9",
        "ch",
        "token",
        "s",
        "c",
        "g",
        0,
        Identity::generate(),
        Keyring::new("g"),
        Replicator::new("n", SB_STRATEGY_LWW_HLC).expect("r"),
        ReceiveState::new(),
        100,
        7,
        &[],
    )
    .err()
    .unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);

    let error = RelayDriver::new(
        "http://127.0.0.1:9",
        "ch",
        "token",
        "s",
        "c",
        "g",
        0,
        Identity::generate(),
        Keyring::new("g"),
        Replicator::new("n", SB_STRATEGY_LWW_HLC).expect("r"),
        ReceiveState::new(),
        100,
        SB_TLS_VALIDATE_CA,
        &[],
    )
    .err()
    .unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);

    // A valid construction against a dead port builds a driver that reports
    // no progress and no stop reason yet, then starts cleanly.
    let driver = RelayDriver::new(
        "http://127.0.0.1:1",
        "ch",
        "token",
        "s",
        "c",
        "g",
        0,
        Identity::generate(),
        Keyring::new("g"),
        Replicator::new("n", SB_STRATEGY_LWW_HLC).expect("r"),
        ReceiveState::new(),
        100,
        SB_TLS_VALIDATE,
        &[],
    )
    .expect("a dead-port driver still constructs");
    assert!(!driver.running());
    assert_eq!(driver.stop_reason(), SB_DRIVER_STOP_NONE);
    assert_eq!(driver.counters(), (0, 0, 0, 0, 0));
    assert!(driver.stop_error().is_none());
    assert!(driver.get("missing").is_none());

    // A second start while running is an input error.
    driver.set_config(fast_config());
    driver.start().expect("start");
    assert!(driver.start().is_err(), "start twice is refused");
    driver.stop().expect("stop");
    assert!(!driver.running());
    assert_eq!(driver.stop_reason(), SB_DRIVER_STOP_CANCELLED);

    // An empty-key write and delete are refused.
    assert!(driver.write("", b"x").is_err());
    assert!(driver.delete("").is_err());

    // Freeing a running driver stops it first: the worker joins before the
    // runtime drops.
    driver.start().expect("restart");
    assert!(driver.running());
    drop(driver);
}
