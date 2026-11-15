//! The two ends of a pairing, as processes: the smallest real driver of
//! the transport, and the other end of the two-process integration test.
//!
//! ```text
//! pair-end host <relay-url> <room-id> <capability> [--insecure]
//! pair-end join <relay-url> <room-id> <capability> <code> [--insecure]
//! ```
//!
//! Machine-readable stdout: `code <CODE>` (host, as soon as it is issued),
//! then on success `self <device-id>`, `peer <device-id>`, `group <id>`.
//! Anything else goes to stderr with exit 1.

use syncbond_core::identity::DeviceIdentity;
use syncbond_transport_ws::{
    create_invite, pair_as_host, pair_as_joiner, TlsPolicy, WsPairingOptions,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (insecure, args) = match args.as_slice() {
        [rest @ .., flag] if flag == "--insecure" => (true, rest.to_vec()),
        rest => (false, rest.to_vec()),
    };
    let code = run(args, insecure);
    match code {
        Ok(()) => {}
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }
}

fn run(args: Vec<String>, insecure: bool) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async_run(args, insecure))
}

async fn async_run(args: Vec<String>, insecure: bool) -> Result<(), String> {
    let mut options = WsPairingOptions::default();
    if insecure {
        options.tls = TlsPolicy::AcceptInvalid;
    }
    match args.as_slice() {
        [command, relay_url, room_id, capability] if command == "host" => {
            let invite = syncbond_transport_ws::Invite {
                room_id: room_id.clone(),
                capability: capability.clone(),
            };
            options.relay_url = relay_url.clone();
            let identity = DeviceIdentity::generate();
            let session = pair_as_host(&options, &identity, &invite, |code| {
                emit("code", code);
            })
            .await
            .map_err(|error| error.to_string())?;
            emit("self", &session.device_id);
            emit("peer", &session.peer_identity.device_id);
            emit("group", &session.group_id);
            Ok(())
        }
        [command, relay_url, room_id, capability, code] if command == "join" => {
            let invite = syncbond_transport_ws::Invite {
                room_id: room_id.clone(),
                capability: capability.clone(),
            };
            options.relay_url = relay_url.clone();
            let identity = DeviceIdentity::generate();
            let session = pair_as_joiner(&options, &identity, code, &invite)
                .await
                .map_err(|error| error.to_string())?;
            emit("self", &session.device_id);
            emit("peer", &session.peer_identity.device_id);
            emit("group", &session.group_id);
            Ok(())
        }
        // The full flow needs a room first; expose room creation too so a
        // human can run the whole dance by hand.
        [command, relay_url] if command == "create" => {
            options.relay_url = relay_url.clone();
            let invite = create_invite(&options)
                .await
                .map_err(|error| error.to_string())?;
            emit("room", &invite.room_id);
            emit("capability", &invite.capability);
            Ok(())
        }
        _ => Err("usage: pair-end host <relay-url> <room-id> <capability> | \
             join <relay-url> <room-id> <capability> <code> | \
             create <relay-url> [--insecure]"
            .into()),
    }
}

fn emit(key: &str, value: &str) {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{key} {value}");
    let _ = stdout.flush();
}
