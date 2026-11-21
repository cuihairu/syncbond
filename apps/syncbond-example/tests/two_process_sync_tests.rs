//! Acceptance (todo.md DSR-33): the whole sync story as real processes.
//!
//! The relay boots from an empty directory (the same router, serve loop,
//! SQLite store, and shutdown edge the binary runs — `syncbond-server` is
//! a thin wrapper over exactly this). Two client processes, each with its
//! own identity and storage directory, pair through the relay, write
//! offline, and sync across restarts. Every subcommand is a fresh process,
//! so the restart path (recover oplog, cursor, and pending outbox from
//! disk) is what the assertions exercise. Any failure is a test panic —
//! a non-zero script exit.

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use syncbond_relay_client::{RelayClient, TlsPolicy};
use syncbond_relay_protocol::dto::CredentialScope;
use syncbond_server::test_support::boot_relay;
use syncbond_transport_ws::{create_invite, WsPairingOptions};

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

/// Read the host's stdout line by line until the code appears, keeping
/// the remaining lines available on the same channel. On timeout the
/// host's stderr file is read, so a failed pairing says why.
fn read_code_line(
    stdout: std::process::ChildStdout,
    host_stderr: &std::path::Path,
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

#[test]
fn two_client_processes_pair_write_offline_and_sync_across_a_restart() {
    // The relay boots from an empty data directory.
    let relay = boot_relay();
    let relay_url = format!("http://{}", relay.address);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    // One channel, one Append+Pull credential per device.
    let client = RelayClient::new(&relay_url, TlsPolicy::Validate, Duration::from_secs(5))
        .expect("a loopback location parses");
    let channel = runtime
        .block_on(client.create_channel(&relay.admin, "demo-create-00000001"))
        .expect("channel");
    let token_a = runtime
        .block_on(client.issue_credential(
            &relay.admin,
            &channel.channel_id,
            &[CredentialScope::Append, CredentialScope::Pull],
            Some("device-a"),
            "demo-issue-00000001",
        ))
        .expect("credential a")
        .token;
    let token_b = runtime
        .block_on(client.issue_credential(
            &relay.admin,
            &channel.channel_id,
            &[CredentialScope::Append, CredentialScope::Pull],
            Some("device-b"),
            "demo-issue-00000002",
        ))
        .expect("credential b")
        .token;

    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let root = std::env::temp_dir().join(format!(
        "syncbond-demo-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let dir_a = root.join("a").to_string_lossy().into_owned();
    let dir_b = root.join("b").to_string_lossy().into_owned();

    // Pair: the host creates the room, the joiner types the code. The
    // group key rides the encrypted session inside each process.
    let options = WsPairingOptions {
        relay_url: relay_url.clone(),
        ..Default::default()
    };
    let invite = runtime
        .block_on(create_invite(&options))
        .expect("room created");
    std::fs::create_dir_all(&root).ok();
    let host_stderr = root.join("host.stderr");
    let joiner_stderr = root.join("joiner.stderr");
    let mut host = Command::new(env!("CARGO_BIN_EXE_demo-client"))
        .args([
            "pair-host",
            &dir_a,
            &relay_url,
            &invite.room_id,
            &invite.capability,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            std::fs::File::create(&host_stderr).expect("host stderr file"),
        ))
        .spawn()
        .expect("host process starts");
    let (code, host_lines_rx) =
        read_code_line(host.stdout.take().expect("stdout piped"), &host_stderr);

    let joiner = Command::new(env!("CARGO_BIN_EXE_demo-client"))
        .args([
            "pair-joiner",
            &dir_b,
            &relay_url,
            &invite.room_id,
            &invite.capability,
            &code,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            std::fs::File::create(&joiner_stderr).expect("joiner stderr file"),
        ))
        .spawn()
        .expect("joiner process starts");
    let joiner_output = wait_with_budget(joiner, Duration::from_secs(60));
    let host_output = wait_with_budget(host, Duration::from_secs(60));
    assert!(
        joiner_output.status.success(),
        "joiner stderr: {}",
        std::fs::read_to_string(&joiner_stderr).unwrap_or_default()
    );
    assert!(
        host_output.status.success(),
        "host stderr: {}",
        std::fs::read_to_string(&host_stderr).unwrap_or_default()
    );
    let mut host_lines = vec![format!("code {code}")];
    loop {
        match host_lines_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(line) => host_lines.push(line),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
        }
    }
    let host_paired = field(&host_lines.join("\n"), "paired");
    let joiner_paired = field(
        &String::from_utf8(joiner_output.stdout).expect("stdout is utf-8"),
        "paired",
    );
    assert!(!host_paired.is_empty());
    assert!(!joiner_paired.is_empty());

    // Offline writes: each device stages into its own outbox, no network.
    assert_eq!(
        field(&run_demo(&["write", &dir_a, "mine/0", "v0"]), "records"),
        "1"
    );
    assert_eq!(
        field(&run_demo(&["write", &dir_a, "mine/1", "v1"]), "records"),
        "2"
    );
    assert_eq!(
        field(&run_demo(&["write", &dir_b, "yours/0", "w0"]), "records"),
        "1"
    );

    // First sync: each process pushes its offline writes and pulls the
    // other's. A has written two but nothing is on the relay yet.
    assert_eq!(
        field(
            &run_demo(&["sync", &dir_a, &relay_url, &channel.channel_id, &token_a]),
            "records"
        ),
        "2"
    );
    assert_eq!(
        field(
            &run_demo(&["sync", &dir_b, &relay_url, &channel.channel_id, &token_b]),
            "records"
        ),
        "3"
    );
    // A restarts and catches up on B's write.
    assert_eq!(
        field(
            &run_demo(&["sync", &dir_a, &relay_url, &channel.channel_id, &token_a]),
            "records"
        ),
        "3"
    );

    // B writes more offline, then both restart-sync to convergence.
    assert_eq!(
        field(&run_demo(&["write", &dir_b, "yours/1", "w1"]), "records"),
        "4"
    );
    assert_eq!(
        field(
            &run_demo(&["sync", &dir_b, &relay_url, &channel.channel_id, &token_b]),
            "records"
        ),
        "4"
    );
    assert_eq!(
        field(
            &run_demo(&["sync", &dir_a, &relay_url, &channel.channel_id, &token_a]),
            "records"
        ),
        "4"
    );

    // Convergence, confirmed by plain count with no network at all.
    assert_eq!(field(&run_demo(&["count", &dir_a]), "records"), "4");
    assert_eq!(field(&run_demo(&["count", &dir_b]), "records"), "4");

    std::fs::remove_dir_all(&root).ok();
}
