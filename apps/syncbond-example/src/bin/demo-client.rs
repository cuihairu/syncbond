//! The demo client process: identity and storage in one directory, pairing
//! through the relay, offline writes, and restart sync through the core
//! driver. Every invocation is a fresh process, so each step after pairing
//! is a restart that recovers from the files on disk.
//!
//! ```text
//! demo-client pair-host   <data-dir> <relay-url> <room-id> <capability>
//! demo-client pair-joiner <data-dir> <relay-url> <room-id> <capability> <code>
//! demo-client write       <data-dir> <key> <value>
//! demo-client sync        <data-dir> <relay-url> <channel-id> <token>
//! demo-client count       <data-dir>
//! ```
//!
//! Machine-readable stdout: `code <CODE>` (host, at issue), `paired
//! <device-id>` (after a pairing), `records <n>` (after write, sync, or
//! count). Anything else goes to stderr with exit 1.

use std::path::Path;
use std::time::Duration;

use syncbond_core::outbox::stage_operations;
use syncbond_core::sync_driver::{DriverConfig, SyncDriver};
use syncbond_core::KeyRing;
use syncbond_example::{bootstrap, load_device, persist, FileOutboxStore, FileStorage, GroupFacts};
use syncbond_relay_client::{DriverTransport, RelayClient, TlsPolicy};
use syncbond_transport_ws::{pair_as_host, pair_as_joiner, Invite, WsPairingOptions};

/// The demo's replication group. Both devices join it through the pairing
/// session; the group key rides only that session, never the relay.
const GROUP_ID: &str = "example-group";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(message) = run(&args) {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [command, data_dir, relay_url, room_id, capability] if command == "pair-host" => {
            pair_host(Path::new(data_dir), relay_url, room_id, capability)
        }
        [command, data_dir, relay_url, room_id, capability, code] if command == "pair-joiner" => {
            pair_joiner(Path::new(data_dir), relay_url, room_id, capability, code)
        }
        [command, data_dir, key, value] if command == "write" => {
            write(Path::new(data_dir), key, value)
        }
        [command, data_dir, relay_url, channel_id, token] if command == "sync" => {
            sync(Path::new(data_dir), relay_url, channel_id, token)
        }
        [command, data_dir] if command == "count" => count(Path::new(data_dir)),
        _ => Err("usage: demo-client <pair-host|pair-joiner|write|sync|count> ...".into()),
    }
}

fn pair_host(
    data_dir: &Path,
    relay_url: &str,
    room_id: &str,
    capability: &str,
) -> Result<(), String> {
    // A multi-threaded runtime, not current_thread: the pairing pump that
    // the bridge spawns (WS reader/writer tasks) must keep running while
    // this thread does the blocking session I/O below. A current_thread
    // runtime only drives its spawned tasks while block_on is active, so
    // seal_and_send would block on a queue no one drains.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let options = WsPairingOptions {
        relay_url: relay_url.to_owned(),
        ..Default::default()
    };
    let invite = Invite {
        room_id: room_id.to_owned(),
        capability: capability.to_owned(),
    };
    let identity = syncbond_core::identity::DeviceIdentity::generate();
    let session = runtime
        .block_on(pair_as_host(&options, &identity, &invite, |code| {
            println!("code {code}");
        }))
        .map_err(|error| error.to_string())?;

    // The host mints the replication group's key and hands it over the
    // encrypted session — the relay never sees it.
    let keyring = KeyRing::new(GROUP_ID);
    let facts = GroupFacts {
        group_id: GROUP_ID.to_owned(),
        key_epoch: keyring.current_epoch(),
        key: *keyring.current_key(),
    };
    let facts_bytes = serde_json::to_vec(&facts).map_err(|error| error.to_string())?;
    session
        .seal_and_send(&facts_bytes)
        .map_err(|error| error.to_string())?;

    // seal_and_send enqueues into the bridge's outbound queue; it does not
    // wait for the writer task to put the frame on the wire. Keep the
    // runtime driven a beat so the frame is flushed before this process
    // exits and the socket closes — otherwise the joiner can see a close
    // before the group facts and fail the pairing.
    runtime.block_on(async { tokio::time::sleep(Duration::from_millis(500)).await });

    bootstrap(data_dir, &identity, &facts)?;
    println!("paired {}", session.device_id);
    Ok(())
}

fn pair_joiner(
    data_dir: &Path,
    relay_url: &str,
    room_id: &str,
    capability: &str,
    code: &str,
) -> Result<(), String> {
    // Same reasoning as the host: the bridge's pump must keep driving
    // while the blocking recv below waits on the session channel.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let options = WsPairingOptions {
        relay_url: relay_url.to_owned(),
        ..Default::default()
    };
    let invite = Invite {
        room_id: room_id.to_owned(),
        capability: capability.to_owned(),
    };
    let identity = syncbond_core::identity::DeviceIdentity::generate();
    let session = runtime
        .block_on(pair_as_joiner(&options, &identity, code, &invite))
        .map_err(|error| error.to_string())?;

    // The joiner takes the group facts from the session it just paired on.
    let facts_bytes = session.recv_and_open().map_err(|error| error.to_string())?;
    let facts: GroupFacts =
        serde_json::from_slice(&facts_bytes).map_err(|error| error.to_string())?;
    bootstrap(data_dir, &identity, &facts)?;
    println!("paired {}", session.device_id);
    Ok(())
}

fn write(data_dir: &Path, key: &str, value: &str) -> Result<(), String> {
    let facts = GroupFacts::load(data_dir)?;
    let (store, outbox) = (FileStorage::new(data_dir), FileOutboxStore::new(data_dir));
    let mut device = load_device(data_dir, &facts)?;
    let operation = device
        .replicator
        .put(key.to_owned(), value.as_bytes().to_vec())
        .map_err(|error| error.to_string())?;
    stage_operations(
        &outbox,
        &[operation],
        &device.keyring,
        &device.identity.device_id,
    )
    .map_err(|error| error.to_string())?;
    persist(&store, &device)?;
    println!("records {}", device.replicator.record_count());
    Ok(())
}

fn sync(data_dir: &Path, relay_url: &str, channel_id: &str, token: &str) -> Result<(), String> {
    let facts = GroupFacts::load(data_dir)?;
    let (store, outbox) = (FileStorage::new(data_dir), FileOutboxStore::new(data_dir));
    let mut device = load_device(data_dir, &facts)?;

    // The driver runs on this plain thread; the transport hops into the
    // runtime for each request (block_on may not nest, so the driver must
    // never run inside it).
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let client = RelayClient::new(relay_url, TlsPolicy::Validate, Duration::from_secs(10))
        .map_err(|error| error.to_string())?;
    let transport = DriverTransport::new(
        client,
        channel_id.to_owned(),
        token.to_owned(),
        runtime.handle().clone(),
    );

    // Whole cycles until nothing moves, bounded — a wedged relay fails
    // the run instead of hanging it.
    let mut moved = true;
    let mut cycles = 0;
    while moved && cycles < 8 {
        cycles += 1;
        let report = {
            let mut driver = SyncDriver {
                replicator: &mut device.replicator,
                receive: &mut device.receive,
                store: &store,
                keyring: &device.keyring,
                identity: &device.identity,
                group: &device.facts.group_id,
                key_epoch: device.facts.key_epoch,
                outbox: &outbox,
                transport: &transport,
                server_id: "relay-1",
                channel_id,
                config: driver_config(),
            };
            driver.sync_once().map_err(|error| error.to_string())?
        };
        moved = report.sent_envelopes > 0 || report.applied > 0;
    }
    println!("records {}", device.replicator.record_count());
    Ok(())
}

fn count(data_dir: &Path) -> Result<(), String> {
    let facts = GroupFacts::load(data_dir)?;
    let device = load_device(data_dir, &facts)?;
    println!("records {}", device.replicator.record_count());
    Ok(())
}

fn driver_config() -> DriverConfig {
    DriverConfig {
        page_limit: 32,
        max_pages_per_cycle: 16,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(200),
        max_attempts: 3,
        idle_interval: Duration::from_millis(5),
    }
}
