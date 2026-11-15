//! The whole flow as two real processes: the relay boots in-process, the
//! room is created in-process, and `pair-end host` / `pair-end join` —
//! separate binaries with separate identities, separate runtimes, no
//! shared memory — complete a pairing and agree on the session. This is
//! the shape a real deployment runs.

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use syncbond_server::test_support::boot_relay;
use syncbond_transport_ws::{create_invite, WsPairingOptions};

/// Wait for a child to end, with a budget: a hung pairing fails the test
/// instead of hanging CI.
fn wait_with_budget(child: std::process::Child, budget: Duration) -> std::process::Output {
    let (output_tx, output_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let output = child.wait_with_output().expect("child io ends");
        let _ = output_tx.send(output);
    });
    output_rx
        .recv_timeout(budget)
        .expect("the pairing ends within the budget")
}

/// Read the host's stdout line by line until the code appears, keeping
/// the remaining lines available on the same channel.
fn read_code_line(
    stdout: std::process::ChildStdout,
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
        let line = line_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the host prints the code within the budget");
        if let Some(code) = line.strip_prefix("code ") {
            return (code.to_owned(), line_rx);
        }
    }
}

/// Pull one `key value` line out of the pair-end protocol output.
fn field(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(key).map(|value| value.trim().to_owned()))
        .unwrap_or_else(|| panic!("pair-end printed no {key} line in: {stdout:?}"))
}

#[test]
fn two_processes_pair_through_a_real_relay() {
    let relay = boot_relay();
    let options = WsPairingOptions {
        relay_url: format!("http://{}", relay.address),
        ..Default::default()
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let invite = runtime
        .block_on(create_invite(&options))
        .expect("room created");

    let mut host = Command::new(env!("CARGO_BIN_EXE_pair-end"))
        .args([
            "host",
            &options.relay_url,
            &invite.room_id,
            &invite.capability,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("host process starts");
    let (code, host_lines_rx) = read_code_line(host.stdout.take().expect("stdout piped"));

    let joiner = Command::new(env!("CARGO_BIN_EXE_pair-end"))
        .args([
            "join",
            &options.relay_url,
            &invite.room_id,
            &invite.capability,
            &code,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("joiner process starts");
    let joiner_output = wait_with_budget(joiner, Duration::from_secs(60));
    let host_output = wait_with_budget(host, Duration::from_secs(60));

    assert!(
        joiner_output.status.success(),
        "joiner stderr: {}",
        String::from_utf8_lossy(&joiner_output.stderr)
    );
    assert!(
        host_output.status.success(),
        "host stderr: {}",
        String::from_utf8_lossy(&host_output.stderr)
    );

    // The code reader owns the host's stdout pipe: everything after the
    // code line arrives on the channel (wait_with_output sees none of it
    // — the pipe was already taken).
    let mut host_lines = vec![format!("code {code}")];
    loop {
        match host_lines_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(line) => host_lines.push(line),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
        }
    }
    let host_stdout = host_lines.join("\n");
    let joiner_stdout = String::from_utf8(joiner_output.stdout).expect("stdout is utf-8");

    let host_self = field(&host_stdout, "self");
    let host_peer = field(&host_stdout, "peer");
    let host_group = field(&host_stdout, "group");
    let joiner_self = field(&joiner_stdout, "self");
    let joiner_peer = field(&joiner_stdout, "peer");
    let joiner_group = field(&joiner_stdout, "group");

    // Each process learned exactly the other's identity through the
    // authenticated exchange, and both name the same conversation.
    assert_eq!(host_peer, joiner_self, "host saw the joiner's identity");
    assert_eq!(joiner_peer, host_self, "joiner saw the host's identity");
    assert_eq!(host_group, joiner_group, "one conversation, one group");
    assert!(!host_group.is_empty());
}
