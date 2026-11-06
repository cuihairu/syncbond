//! syncbond-pair: two-terminal pairing demo over a real TCP connection.
//!
//! Terminal A (initiator, shows the pairing code):
//!
//! ```sh
//! cargo run -p syncbond-cli --example syncbond-pair -- --role a --addr 127.0.0.1:47560
//! ```
//!
//! Terminal B (responder, types the code):
//!
//! ```sh
//! cargo run -p syncbond-cli --example syncbond-pair -- --role b --addr 127.0.0.1:47560
//! ```
//!
//! The run walks the whole core path: SPAKE2 pairing (RFC 9382) over TCP,
//! encrypted application messages (XChaCha20-Poly1305 envelopes on the
//! session channel), an oplog exchange with merge, and a snapshot
//! save/reload round-trip through a `SyncStorage` file.
//!
//! Flags: `--code` forces a code (scripted runs), `--message` sends one
//! scripted message instead of the interactive prompt, `--state-dir` picks
//! the snapshot directory.

use std::collections::VecDeque;
use std::net::TcpListener;
use std::sync::Arc;
use syncbond_cli::{
    load_pair_state, optional_flag, prompt, require_flag, save_pair_state, FileStorage,
    PersistedPairState, TcpTransport,
};
use syncbond_core::codes::generate_code;
use syncbond_core::conflict::LwwHlc;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::{self, PairingSession};
use syncbond_core::replication::{
    decode_state, encode_state, Operation, ReplicationError, Replicator,
};
use syncbond_core::storage::SyncStorage;

const TERM: &str = "/exit";

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let role = require_flag(&args, "--role")?;
    let addr = optional_flag(&args, "--addr").unwrap_or_else(|| "127.0.0.1:47560".to_string());
    let forced_code = optional_flag(&args, "--code");
    let scripted_message = optional_flag(&args, "--message");
    let state_dir = optional_flag(&args, "--state-dir").unwrap_or_else(|| ".".to_string());

    let identity = DeviceIdentity::generate();
    println!("device id: {}", identity.device_id);

    let (session, code, is_initiator) = match role.as_str() {
        "a" => {
            let listener = TcpListener::bind(&addr)?;
            println!("terminal A (initiator) listening on {addr}");
            let code = forced_code.unwrap_or_else(generate_code);
            println!("\nPAIRING CODE: {code}");
            println!("type this code in terminal B, then wait here.\n");
            let transport = TcpTransport::accept(&listener)?;
            let session = pairing::pair(&code, &identity, Arc::new(transport))?;
            (session, code, true)
        }
        "b" => {
            println!("terminal B (responder) connecting to {addr}");
            let transport = TcpTransport::connect(&addr)?;
            let code = match forced_code {
                Some(code) => code,
                None => prompt("enter the pairing code shown in terminal A: ")?,
            };
            let session = pairing::accept(&code, &identity, Arc::new(transport))?;
            (session, code, false)
        }
        other => return Err(format!("unknown --role {other}: use a or b").into()),
    };

    println!(
        "paired. peer device: {} | group: {} | code: {code}",
        session.peer_identity.device_id, session.group_id
    );

    // Envelope phase: sealed messages on the session channel. Termination is
    // a two-way handshake (the first side to finish sends TERM and waits for
    // the peer's TERM back), so no stray frame ever leaks into the oplog
    // phase regardless of which side is scripted.
    println!("\n--- encrypted message exchange (type {TERM} to stop) ---");
    chat(&session, is_initiator, scripted_message.as_deref())?;

    // Oplog phase: both sides write one record and exchange their oplogs over
    // the same encrypted session; dedup + HLC-LWW merge converge both sides.
    println!("\n--- oplog exchange over the paired session ---");
    let mut replicator = Replicator::new(session.device_id.clone());
    let record_key = format!("pair-demo/{role}");
    let record_value = format!("written by terminal {role} ({})", identity.device_id);
    replicator.put(&record_key, record_value.clone().into_bytes())?;
    let sent = replicator.oplog().len();
    let received = exchange_oplogs(&mut replicator, &session, is_initiator)?;
    println!(
        "sync: sent {sent} ops, received {} ops ({} newly applied)",
        received.len(),
        received.len()
    );
    println!(
        "converged state ({} live records):",
        replicator.live_keys().len()
    );
    for key in replicator.live_keys() {
        let record = replicator.get(&key).expect("live key exists");
        println!("  {key} = {}", String::from_utf8_lossy(&record.payload));
    }

    // Storage phase: snapshot plus the received ops (which live only in the
    // record map and never in the local oplog), saved together, then
    // reloaded from file alone and replayed so both sides survive a restart.
    let state_path =
        std::path::Path::new(&state_dir).join(format!("syncbond-pair-state-{role}.json"));
    let storage = FileStorage::open(&state_path);
    let snapshot = replicator.snapshot_state(&identity, &session.group_id, pairing::SESSION_EPOCH);
    storage.save(&encode_state(&snapshot)?)?;
    save_pair_state(
        &state_path,
        &PersistedPairState {
            state: snapshot.clone(),
            received: received.clone(),
        },
    )?;
    let persisted = load_pair_state(&state_path)?.expect("pair state just saved");
    let mut restored = Replicator::from_state(
        &decode_state(&encode_state(&persisted.state)?)?,
        Arc::new(LwwHlc),
    )?;
    for op in &persisted.received {
        restored.apply_remote(op)?;
    }
    println!(
        "storage: snapshot + {} received ops saved to {} and reloaded; {} live records survive the round-trip:",
        persisted.received.len(),
        state_path.display(),
        restored.live_keys().len()
    );
    for key in restored.live_keys() {
        let record = restored.get(&key).expect("live key exists");
        println!("  {key} = {}", String::from_utf8_lossy(&record.payload));
    }
    println!("\ndone.");
    Ok(())
}

/// Alternating message loop. `speak_next` tracks whose turn it is; the loop
/// ends only once this side has both sent and received TERM, so both sides
/// always arrive at the oplog phase with an empty frame queue.
fn chat(
    session: &PairingSession,
    is_initiator: bool,
    scripted: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut scripted_queue =
        scripted.map(|message| VecDeque::from(vec![message.to_string(), TERM.to_string()]));
    let mut speak_next = is_initiator;
    let mut term_sent = false;
    let mut term_received = false;

    while !(term_sent && term_received) {
        if speak_next {
            if !term_sent {
                let message = next_message(&mut scripted_queue)?;
                session.seal_and_send(message.as_bytes())?;
                println!("[sent] {message}");
                if message == TERM {
                    term_sent = true;
                }
            }
        } else {
            let incoming = session.recv_and_open()?;
            let text = String::from_utf8_lossy(&incoming).into_owned();
            if text == TERM {
                term_received = true;
                if !term_sent {
                    session.seal_and_send(TERM.as_bytes())?;
                    println!("[sent] {TERM}");
                    term_sent = true;
                }
            } else {
                println!("[peer] {text}");
            }
        }
        speak_next = !speak_next;
    }
    Ok(())
}

/// Scripted messages first (the message, then TERM), then the interactive
/// prompt. An empty line or EOF on stdin is treated as TERM so a piped or
/// closed stdin can never turn the chat into an empty-message spin loop.
fn next_message(scripted_queue: &mut Option<VecDeque<String>>) -> Result<String, std::io::Error> {
    if let Some(queue) = scripted_queue {
        if let Some(message) = queue.pop_front() {
            return Ok(message);
        }
    }
    let line = prompt("you> ")?;
    if line.is_empty() {
        return Ok(TERM.to_string());
    }
    Ok(line)
}

/// The same wire format `Replicator::sync_over` uses — a serde_json oplog —
/// but the received ops are returned so they can be persisted: the core
/// snapshot's oplog carries only locally issued ops.
fn exchange_oplogs(
    replicator: &mut Replicator,
    session: &PairingSession,
    send_first: bool,
) -> Result<Vec<Operation>, ReplicationError> {
    let encode = |replicator: &Replicator| -> Result<Vec<u8>, ReplicationError> {
        serde_json::to_vec(replicator.oplog())
            .map_err(|error| ReplicationError::Encoding(error.to_string()))
    };
    let received = if send_first {
        session.seal_and_send(&encode(replicator)?)?;
        recv_oplog(session)?
    } else {
        let received = recv_oplog(session)?;
        session.seal_and_send(&encode(replicator)?)?;
        received
    };
    let mut applied = Vec::new();
    for op in &received {
        if replicator.apply_remote(op)? {
            applied.push(op.clone());
        }
    }
    Ok(applied)
}

fn recv_oplog(session: &PairingSession) -> Result<Vec<Operation>, ReplicationError> {
    let bytes = session.recv_and_open()?;
    serde_json::from_slice(&bytes).map_err(|error| ReplicationError::Encoding(error.to_string()))
}
