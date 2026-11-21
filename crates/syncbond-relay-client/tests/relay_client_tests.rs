//! The real relay, in process (test-support): provisioning, the append
//! and pull contract with idempotent retries, and the core driver end to
//! end — first cycle, then a restart that resumes from the committed
//! cursor.

use std::sync::Arc;
use std::time::Duration;

use syncbond_core::batch::{open_operations, seal_operations};
use syncbond_core::conflict::LwwHlc;
use syncbond_core::crypto::KeyRing;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::outbox::{drain, stage_operations, MemoryOutboxStore, OutboxStore};
use syncbond_core::receive::{load_receive, ReceiveState};
use syncbond_core::replication::Replicator;
use syncbond_core::storage::MemoryStorage;
use syncbond_core::sync_driver::{DriverConfig, SyncDriver};
use syncbond_relay_client::{DriverTransport, RelayClient, RelayClientError, TlsPolicy};
use syncbond_relay_protocol::dto::CredentialScope;
use syncbond_server::test_support::boot_relay;

fn client(relay_address: &str) -> RelayClient {
    RelayClient::new(
        &format!("http://{relay_address}"),
        TlsPolicy::Validate,
        Duration::from_secs(5),
    )
    .expect("a loopback location parses")
}

fn fast_config() -> DriverConfig {
    DriverConfig {
        page_limit: 2,
        max_pages_per_cycle: 8,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        max_attempts: 2,
        idle_interval: Duration::from_millis(1),
    }
}

/// A device's fresh writes. The peer's replicator is the caller's own:
/// kept alive across batches, exactly like a real device that persists
/// its cursor (a fresh one would restart its op ids).
fn peer_ops(
    peer: &mut Replicator,
    prefix: &str,
    count: usize,
) -> Vec<syncbond_core::replication::Operation> {
    (0..count)
        .map(|index| {
            peer.put(
                format!("{prefix}/{index}"),
                format!("v{index}").into_bytes(),
            )
            .expect("peer write")
        })
        .collect()
}

/// Seal operations the way an outbox would.
fn sealed(
    operations: &[syncbond_core::replication::Operation],
    keyring: &KeyRing,
) -> Vec<syncbond_relay_protocol::dto::Envelope> {
    seal_operations(operations, keyring, "peer")
        .expect("seals")
        .into_iter()
        .flatten()
        .collect()
}

#[tokio::test]
async fn provisioning_append_and_pull_round_trip_through_the_real_relay() {
    let relay = boot_relay();
    let client = client(&relay.address);

    let channel = client
        .create_channel(&relay.admin, "r-create-00000001")
        .await
        .expect("channel");
    let append_token = client
        .issue_credential(
            &relay.admin,
            &channel.channel_id,
            &[CredentialScope::Append],
            None,
            "r-issue-00000001",
        )
        .await
        .expect("append credential")
        .token;
    let pull_token = client
        .issue_credential(
            &relay.admin,
            &channel.channel_id,
            &[CredentialScope::Pull],
            None,
            "r-issue-00000002",
        )
        .await
        .expect("pull credential")
        .token;

    // The sender side: seal like the outbox would, append once.
    let keyring = KeyRing::new("group-1");
    let mut peer = Replicator::new("peer");
    let envelopes = sealed(&peer_ops(&mut peer, "note", 2), &keyring);
    let ack = client
        .append(
            &append_token,
            &channel.channel_id,
            &envelopes,
            "r-append-00000001",
        )
        .await
        .expect("append");
    assert_eq!(ack.acks.len(), 2);
    let mut seqs: Vec<u64> = ack.acks.iter().map(|ack| ack.seq).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, vec![1, 2]);

    // A retry of the same envelopes commits as duplicates: the
    // (channel, messageId) idempotency record answers.
    let retry = client
        .append(
            &append_token,
            &channel.channel_id,
            &envelopes,
            "r-append-00000002",
        )
        .await
        .expect("re-append");
    assert!(retry.acks.iter().all(|ack| ack.duplicate));

    let page = client
        .pull(
            &pull_token,
            &channel.channel_id,
            0,
            None,
            None,
            "r-pull-00000001",
        )
        .await
        .expect("pull");
    assert_eq!(page.entries.len(), 2);
    assert!(!page.has_more);

    let pulled: Vec<_> = page
        .entries
        .into_iter()
        .map(|entry| entry.envelope)
        .collect();
    let mut seen = std::collections::HashSet::new();
    let opened = open_operations(&pulled, &keyring, &mut seen).expect("opens");
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[0].key, "note/0");
    assert_eq!(opened[0].payload, b"v0".to_vec());
    assert_eq!(opened[1].key, "note/1");

    // The append credential does not pull: a wrong scope is a typed
    // relay refusal, not prose.
    let refused = client
        .pull(
            &append_token,
            &channel.channel_id,
            0,
            None,
            None,
            "r-pull-00000002",
        )
        .await;
    assert!(
        matches!(refused, Err(RelayClientError::Relay { .. })),
        "got: {refused:?}"
    );
}

#[test]
fn the_driver_syncs_both_directions_and_resumes_after_a_restart() {
    let relay = boot_relay();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
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

    let keyring = KeyRing::new("group-1");
    let identity = DeviceIdentity::generate();

    // The peer (a second device) stages and drains through the same
    // relay — its own outbox discipline, sent via the client. The peer
    // replicator stays alive: the second batch below continues its op
    // ids, exactly like a device that persists its cursor.
    let mut peer = Replicator::new("peer");
    let peer_outbox = MemoryOutboxStore::default();
    let first_ops = peer_ops(&mut peer, "note", 3);
    stage_operations(&peer_outbox, &first_ops, &keyring, "peer").expect("stage");
    let peer_client = client.clone();
    let peer_channel = channel.channel_id.clone();
    let sent = drain(&peer_outbox, |batch| {
        let envelopes = batch.envelopes.clone();
        runtime
            .block_on(peer_client.append(
                &append_token,
                &peer_channel,
                &envelopes,
                "r-peer-00000001",
            ))
            .map(|ack| ack.acks)
    })
    .expect("peer drain");
    assert_eq!(sent, 1);

    // The local device: the core driver served by the adapter.
    let store = MemoryStorage::new();
    let mut local = Replicator::new("local");
    let mut receive = ReceiveState::default();
    let outbox = MemoryOutboxStore::default();
    let own: Vec<_> = (0..2)
        .map(|index| {
            local
                .put(format!("mine/{index}"), format!("m{index}").into_bytes())
                .expect("local write")
        })
        .collect();
    stage_operations(&outbox, &own, &keyring, "local").expect("stage local");
    // One device credential with both scopes serves both directions.
    let transport = DriverTransport::new(
        client.clone(),
        channel.channel_id.clone(),
        device_token,
        runtime.handle().clone(),
    );

    let report = {
        let mut driver = SyncDriver {
            replicator: &mut local,
            receive: &mut receive,
            store: &store,
            keyring: &keyring,
            identity: &identity,
            group: "group-1",
            key_epoch: 1,
            outbox: &outbox,
            transport: &transport,
            server_id: "relay-1",
            channel_id: "ch",
            config: fast_config(),
        };
        driver.sync_once().expect("first cycle")
    };
    assert_eq!(report.sent_envelopes, 2, "the local outbox drained");
    assert_eq!(report.applied, 3, "the peer's three envelopes applied");
    assert_eq!(local.record_count(), 5, "3 peer notes + 2 own");

    let (state, committed) = load_receive(&store).expect("load").expect("committed");
    // The channel log: 3 peer envelopes (seq 1-3) + the local echo of
    // its own 2 (seq 4-5). The cursor names the end of that page.
    assert_eq!(
        committed
            .cursor_for("relay-1", "ch")
            .expect("cursor")
            .server_seq,
        5
    );
    assert!(outbox.pending().expect("pending").is_empty());

    // The peer sends more while the local device is gone — new keys, so
    // the catch-up's effect on records is visible.
    let more = sealed(&peer_ops(&mut peer, "later", 2), &keyring);
    runtime
        .block_on(client.append(&append_token, &channel.channel_id, &more, "r-peer-00000002"))
        .expect("peer sends more");

    // Restart: rebuilt from the committed snapshot alone, the cursor is
    // exactly where the first life left it.
    let mut restarted = Replicator::from_state(&state, Arc::new(LwwHlc)).expect("replays");
    let mut restarted_receive = committed;
    let second = {
        let mut driver = SyncDriver {
            replicator: &mut restarted,
            receive: &mut restarted_receive,
            store: &store,
            keyring: &keyring,
            identity: &identity,
            group: "group-1",
            key_epoch: 1,
            outbox: &outbox,
            transport: &transport,
            server_id: "relay-1",
            channel_id: "ch",
            config: fast_config(),
        };
        driver.sync_once().expect("catch-up cycle")
    };
    assert_eq!(second.applied, 2, "only the two new envelopes");
    assert_eq!(second.sent_envelopes, 0, "nothing pending to send");
    assert_eq!(restarted.record_count(), 7);
    let (_, final_state) = load_receive(&store).expect("load").expect("committed");
    assert_eq!(
        final_state
            .cursor_for("relay-1", "ch")
            .expect("cursor")
            .server_seq,
        7
    );
    assert_eq!(final_state.seen_message_ids.len(), 7);
}
