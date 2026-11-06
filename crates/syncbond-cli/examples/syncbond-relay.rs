//! syncbond-relay: KV sync between two device processes through a durable
//! file relay store, with cursor resume across restarts.
//!
//! Every invocation is a fresh process, so each step below also exercises
//! the crash-restart persistence path (identity, oplog, cursor reload).
//!
//! ```sh
//! # Terminal A (or any shell): write two keys into the relay
//! cargo run -p syncbond-cli --example syncbond-relay -- --role a put theme dark
//! cargo run -p syncbond-cli --example syncbond-relay -- --role a put font_size 14
//! # Terminal B: pull them, then write one back
//! cargo run -p syncbond-cli --example syncbond-relay -- --role b sync
//! cargo run -p syncbond-cli --example syncbond-relay -- --role b put greeting hello
//! # Terminal A: resumes from its persisted relay cursor — only the new op
//! cargo run -p syncbond-cli --example syncbond-relay -- --role a sync
//! cargo run -p syncbond-cli --example syncbond-relay -- --role a show
//! cargo run -p syncbond-cli --example syncbond-relay -- --role b show
//! ```
//!
//! The two `show` outputs converge. The relay channel stores oplog entries
//! as plaintext: envelopes protect pairing sessions, not the relay store.
//! Run the commands one at a time: the file relay store is not safe for
//! concurrent writers (state is cached per process).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use syncbond_cli::{load_device, optional_flag, require_flag, save_device, PersistedDevice};
use syncbond_core::conflict::LwwHlc;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::relay::{apply_pull_response, FileRelayStore, RelayStore};
use syncbond_core::replication::Replicator;
use syncbond_core::storage::SyncState;

const CHANNEL: &str = "relay-demo-kv";

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

struct Device {
    replicator: Replicator,
    pull_cursor: u64,
    applied_remote: Vec<syncbond_core::replication::Operation>,
    state: SyncState,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let role = require_flag(&args, "--role")?;
    if role != "a" && role != "b" {
        return Err(format!("unknown --role {role}: use a or b").into());
    }
    let dir = PathBuf::from(
        optional_flag(&args, "--dir").unwrap_or_else(|| "./syncbond-relay-demo".to_string()),
    );
    let (action, action_args) = split_action(&args)?;

    let relay = FileRelayStore::open(dir.join("relay-log.json"))?;
    let state_path = device_state_path(&dir, &role);
    let mut device = match load_device(&state_path)? {
        None => {
            let node_id = format!("relay-demo-{role}");
            let identity = DeviceIdentity::generate();
            println!(
                "fresh device: no state at {}; created node {node_id}",
                state_path.display()
            );
            Device {
                replicator: Replicator::new(node_id.clone()),
                pull_cursor: 0,
                applied_remote: Vec::new(),
                state: SyncState {
                    node_id,
                    identity,
                    group_id: String::new(),
                    key_epoch: 1,
                    cursor: 0,
                    oplog: Vec::new(),
                    gc_barriers: Default::default(),
                },
            }
        }
        Some(persisted) => {
            let mut replicator = Replicator::from_state(&persisted.state, Arc::new(LwwHlc))?;
            // Rebuild the received side of the state: remote ops are merged
            // into the record map but never enter the local oplog, so the
            // snapshot alone does not carry them across a restart.
            for op in &persisted.applied_remote {
                replicator.apply_remote(op)?;
            }
            println!(
                "restored device: {} live records, local cursor {}, relay pull cursor {}",
                replicator.live_keys().len(),
                replicator.cursor(),
                persisted.pull_cursor
            );
            Device {
                replicator,
                pull_cursor: persisted.pull_cursor,
                applied_remote: persisted.applied_remote,
                state: persisted.state,
            }
        }
    };

    match action.as_str() {
        "put" => {
            let pairs = pairs_from(&action_args)?;
            if pairs.is_empty() {
                return Err("put needs KEY VALUE pairs: put theme dark".into());
            }
            for (key, value) in pairs {
                let op = device.replicator.put(&key, value.clone().into_bytes())?;
                println!("put {key}=\"{value}\" (op {})", op.op_id);
            }
            push(&relay, &device.replicator)?;
        }
        "sync" => {
            push(&relay, &device.replicator)?;
            let pull = relay.pull_after(CHANNEL, device.pull_cursor)?;
            let applied = apply_pull_response(&mut device.replicator, &pull)?;
            println!(
                "pull: relay cursor {} -> {}, received {} ops, {} newly applied (log holds {} ops total)",
                device.pull_cursor,
                pull.after,
                pull.ops.len(),
                applied,
                pull.after
            );
            device.pull_cursor = pull.after;
            device.applied_remote.extend(pull.ops);
        }
        "show" => {}
        other => {
            return Err(
                format!("unknown action \"{other}\": use put KEY VALUE..., sync, or show").into(),
            );
        }
    }

    println!("local state of {}:", device.replicator.node_id);
    for key in device.replicator.live_keys() {
        let record = device.replicator.get(&key).expect("live key exists");
        println!("  {key} = {}", String::from_utf8_lossy(&record.payload));
    }
    println!(
        "oplog: {} local ops, local cursor {}, relay pull cursor {}",
        device.replicator.oplog().len(),
        device.replicator.cursor(),
        device.pull_cursor
    );

    device.state = device.replicator.snapshot_state(
        &device.state.identity,
        &device.state.group_id,
        device.state.key_epoch,
    );
    save_device(
        &state_path,
        &PersistedDevice {
            pull_cursor: device.pull_cursor,
            applied_remote: device.applied_remote.clone(),
            state: device.state.clone(),
        },
    )?;
    println!(
        "state saved to {}; next invocation resumes from here",
        state_path.display()
    );
    Ok(())
}

fn device_state_path(dir: &Path, role: &str) -> PathBuf {
    dir.join(format!("state-{role}.json"))
}

fn split_action(args: &[String]) -> Result<(String, Vec<String>), String> {
    let position = args
        .iter()
        .position(|arg| matches!(arg.as_str(), "put" | "sync" | "show"))
        .ok_or_else(|| "missing action: put KEY VALUE..., sync, or show".to_string())?;
    Ok((args[position].clone(), args[position + 1..].to_vec()))
}

fn pairs_from(rest: &[String]) -> Result<Vec<(String, String)>, String> {
    if !rest.len().is_multiple_of(2) {
        return Err("put needs KEY VALUE pairs (even argument count)".into());
    }
    Ok(rest
        .chunks(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect())
}

fn push(relay: &FileRelayStore, replicator: &Replicator) -> Result<(), Box<dyn std::error::Error>> {
    for op in replicator.oplog() {
        relay.append(CHANNEL, op)?;
    }
    let total = relay.pull_after(CHANNEL, 0)?.ops.len();
    println!(
        "push: {} local ops submitted (relay log holds {} ops; duplicate op ids are ignored by the store)",
        replicator.oplog().len(),
        total
    );
    Ok(())
}
