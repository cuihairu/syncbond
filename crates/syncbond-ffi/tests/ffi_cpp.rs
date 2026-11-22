//! C++-side acceptance: the RAII wrapper header compiles under strict
//! warnings, a pure C++ program completes the pair/sync flow against the
//! built cdylib, and the relay driver syncs two C++ processes through a real
//! relay and recovers them from exported state.

use std::path::{Path, PathBuf};
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn run(command: &mut Command) {
    let output = command.output().expect("failed to spawn command");
    if !output.stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(
        output.status.success(),
        "command failed ({:?}): {:?}",
        output.status,
        command
    );
}

/// Acceptance: the wrapper header compiles with `g++ -std=c++17 -Wall -Wextra -Werror`.
#[test]
fn wrapper_header_compiles_under_strict_warnings() {
    let include = manifest_dir().join("include");
    run(Command::new("g++")
        .args([
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsyntax-only",
            "-x",
            "c++",
            "-I",
        ])
        .arg(&include)
        .arg(include.join("syncbond.hpp")));
}

/// Acceptance: a pure C++ program completes pair/sync end to end.
#[test]
fn pure_cpp_program_completes_pair_and_sync() {
    let manifest = manifest_dir();
    // Build the cdylib into its own target dir so the nested cargo does not
    // wait on the outer test build's lock.
    let target = manifest.join("../../target/ffi-cpp");
    let status = Command::new(cargo_bin())
        .args(["build", "-p", "syncbond-ffi"])
        .env("CARGO_TARGET_DIR", &target)
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "nested cargo build failed");

    let libdir = target.join("debug");
    let out_dir = target.join("cpp-example");
    std::fs::create_dir_all(&out_dir).expect("create out dir");
    let exe = out_dir.join("pair_sync");

    run(Command::new("g++")
        .args(["-std=c++17", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&exe)
        .arg(manifest.join("examples/pair_sync.cpp"))
        .arg("-I")
        .arg(manifest.join("include"))
        .arg("-L")
        .arg(&libdir)
        .arg("-lsyncbond_ffi")
        .arg(format!("-Wl,-rpath,{}", libdir.display()))
        .arg("-lpthread"));

    // Pin the library search path to the freshly built cdylib: the test
    // runner's inherited LD_LIBRARY_PATH (target/debug) would otherwise load
    // a stale shared library over the one just built here.
    run(Command::new(&exe)
        .env("LD_LIBRARY_PATH", &libdir)
        .arg(manifest.join("fixtures/conformance.json"))
        .arg(manifest.join("fixtures/conformance.expected.json"))
        .current_dir(&out_dir));
}

// --------------------------------------------------------------- relay e2e
//
// The C++ binding's relay driver (todo.md DSR-42) must sync two real C++
// processes through a live relay and recover them from exported state. The
// acceptance's "two C++ processes" run as children of this harness; the relay
// itself is booted in-process and provisioned over its admin REST.

/// One report a relay_child wrote (see examples/relay_child.cpp for the line
/// format).
#[derive(Default)]
struct ChildReport {
    node: String,
    max_stall_ms: i64,
    reference_gap_ms: i64,
    converged: bool,
    running: bool,
    cycles: u64,
    sent_batches: u64,
    sent_envelopes: u64,
    pages_pulled: u64,
    applied: u64,
    stop_reason: i64,
    error: String,
    state_hex: String,
    got: std::collections::HashMap<String, String>,
}

fn parse_report(path: &Path) -> ChildReport {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read relay child report {}: {e}", path.display()));
    let mut report = ChildReport::default();
    for line in text.lines() {
        let (field, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("relay child report line without '=': {line:?}"));
        match field {
            "phase" => {}
            "node" => report.node = value.to_string(),
            "maxStallMs" => report.max_stall_ms = value.parse().unwrap(),
            "referenceGapMs" => report.reference_gap_ms = value.parse().unwrap(),
            "converged" => report.converged = value == "1",
            "running" => report.running = value == "1",
            "cycles" => report.cycles = value.parse().unwrap(),
            "sentBatches" => report.sent_batches = value.parse().unwrap(),
            "sentEnvelopes" => report.sent_envelopes = value.parse().unwrap(),
            "pagesPulled" => report.pages_pulled = value.parse().unwrap(),
            "applied" => report.applied = value.parse().unwrap(),
            "stopReason" => report.stop_reason = value.parse().unwrap(),
            "error" => report.error = value.to_string(),
            "stateHex" => report.state_hex = value.to_string(),
            _ if field.starts_with("got ") => {
                report
                    .got
                    .insert(field["got ".len()..].to_string(), value.to_string());
            }
            other => panic!("unexpected relay child report field {other:?}"),
        }
    }
    report
}

/// One JSON POST to the relay's admin REST with the bearer token; returns the
/// decoded object. Uses a hand-rolled HTTP/1.1 request over a socket so the
/// harness needs no HTTP client dependency.
fn post_admin(address: &str, admin: &str, path: &str, body: &str) -> serde_json::Value {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(address)
        .unwrap_or_else(|e| panic!("connect to relay {address}: {e}"));
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("set read timeout");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         authorization: Bearer {admin}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("write admin request");
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .expect("read admin response");
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .expect("a response always has a header block");
    let status: u16 = head
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(599);
    assert_eq!(status, 201, "POST {path}: status {status}: {body}");
    serde_json::from_str(body).unwrap_or_else(|e| panic!("decode {path} response: {e}"))
}

/// The shared 32-byte group key, hex-encoded (the same 0x07 material every
/// binding's relay test uses).
fn group_key_hex() -> String {
    "07".repeat(32)
}

/// The common config lines for one device.
fn base_config(relay_url: &str, channel_id: &str, token: &str, node: &str) -> Vec<String> {
    vec![
        format!("relayUrl {relay_url}"),
        format!("channelId {channel_id}"),
        format!("token {token}"),
        "serverId relay-1".to_string(),
        "cursorChannel ch".to_string(),
        "groupId group-1".to_string(),
        format!("groupKeyHex {}", group_key_hex()),
        format!("node {node}"),
        "waitMs 15000".to_string(),
    ]
}

/// Write one child config and return its path; the child reads it with a
/// trivial line parser so the config is plain text, not JSON.
fn write_config(tmp: &Path, basename: &str, lines: &[String]) -> PathBuf {
    let path = tmp.join(format!("{basename}-config.txt"));
    std::fs::write(&path, lines.join("\n") + "\n")
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    path
}

/// Run one relay_child and return its report. The child asserts its own
/// invariants (convergence, no stall, clean stop) and exits non-zero on any
/// failure, which surfaces as this panic.
fn run_child(
    child: &Path,
    libdir: &Path,
    tmp: &Path,
    phase: &str,
    basename: &str,
    config: &[String],
) -> ChildReport {
    let config_path = write_config(tmp, basename, config);
    let report_path = tmp.join(format!("{basename}-out.txt"));
    run(Command::new(child)
        .env("LD_LIBRARY_PATH", libdir)
        .arg(phase)
        .arg(&config_path)
        .arg(&report_path));
    parse_report(&report_path)
}

/// The checks every device's run must satisfy. `pulled` marks the devices that
/// must have applied an op pulled from the relay: a restarted device that only
/// writes its own key has nothing to pull and legitimately reports zero.
fn assert_child_ok(phase: &str, run: &ChildReport, pulled: bool) {
    assert_eq!(
        run.stop_reason, 1,
        "{phase}: stop reason, want 1 (cancelled)"
    );
    assert!(
        run.error.is_empty(),
        "{phase}: clean stop must have no error, got {}",
        run.error
    );
    assert!(
        run.max_stall_ms < 250,
        "{phase}: stalled {}ms (>= 250ms) during the sync",
        run.max_stall_ms
    );
    assert!(run.converged, "{phase}: reported convergence");
    if pulled {
        assert!(
            run.applied > 0,
            "{phase}: must have applied ops pulled from the relay"
        );
    }
}

/// Acceptance (todo.md DSR-42): two C++ processes sync through a real relay
/// and recover after a restart, and the RAII wrappers release the driver and
/// its sub-handles cleanly.
#[test]
fn cpp_relay_two_processes_sync_and_recover() {
    let manifest = manifest_dir();
    let target = manifest.join("../../target/ffi-cpp");
    let status = Command::new(cargo_bin())
        .args(["build", "-p", "syncbond-ffi"])
        .env("CARGO_TARGET_DIR", &target)
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "nested cargo build failed");

    let libdir = target.join("debug");
    let out_dir = target.join("cpp-relay");
    std::fs::create_dir_all(&out_dir).expect("create out dir");
    let child = out_dir.join("relay_child");
    run(Command::new("g++")
        .args(["-std=c++17", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&child)
        .arg(manifest.join("examples/relay_child.cpp"))
        .arg("-I")
        .arg(manifest.join("include"))
        .arg("-L")
        .arg(&libdir)
        .arg("-lsyncbond_ffi")
        .arg(format!("-Wl,-rpath,{}", libdir.display()))
        .arg("-lpthread"));

    // The relay is booted in-process and held alive for the whole test by
    // keeping this handle bound.
    let relay = syncbond_server::test_support::boot_relay();
    let relay_url = format!("http://{}", relay.address);
    let created = post_admin(
        &relay.address,
        &relay.admin,
        "/v1/channels",
        r#"{"protocolVersion":1,"requestId":"cpp-channel-1"}"#,
    );
    let channel_id = created["channelId"]
        .as_str()
        .expect("channelId")
        .to_string();
    assert!(!channel_id.is_empty(), "channel: no channelId");

    let credential_path = format!("/v1/channels/{channel_id}/credentials");
    let issue = |label: &str| -> String {
        let body = format!(
            r#"{{"protocolVersion":1,"requestId":"cpp-cred-{label}","scopes":["append","pull"],"label":"cpp-{label}"}}"#
        );
        let issued = post_admin(&relay.address, &relay.admin, &credential_path, &body);
        let token = issued["token"].as_str().expect("token").to_string();
        assert!(!token.is_empty(), "credential {label}: no token");
        token
    };
    let token_a = issue("a");
    let token_b = issue("b");

    let tmp = std::env::temp_dir().join(format!("syncbond-cpp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");

    // Phase 1: two fresh devices write concurrently and converge both ways.
    // They must run at the same time: each waits on a key only the other
    // writes, so running them sequentially would deadlock.
    let mut config_a = base_config(&relay_url, &channel_id, &token_a, "cpp-a");
    config_a.push("write a/0=a0".to_string());
    config_a.push("expect a/0=a0".to_string());
    config_a.push("expect b/1=b1".to_string());
    let mut config_b = base_config(&relay_url, &channel_id, &token_b, "cpp-b");
    config_b.push("write b/0=b0".to_string());
    config_b.push("write b/1=b1".to_string());
    config_b.push("expect a/0=a0".to_string());
    config_b.push("expect b/1=b1".to_string());

    let tmp_a = tmp.clone();
    let tmp_b = tmp.clone();
    let config_a_run = config_a.clone();
    let config_b_run = config_b.clone();
    let child_a = child.clone();
    let child_b = child.clone();
    let libdir_a = libdir.clone();
    let libdir_b = libdir.clone();
    let phase1_a = std::thread::spawn(move || {
        run_child(
            &child_a,
            &libdir_a,
            &tmp_a,
            "live",
            "live-cpp-a",
            &config_a_run,
        )
    });
    let phase1_b = std::thread::spawn(move || {
        run_child(
            &child_b,
            &libdir_b,
            &tmp_b,
            "live",
            "live-cpp-b",
            &config_b_run,
        )
    });
    // Join both before asserting so a flake on one side still surfaces the
    // other's full report — a child that times out leaves the peer's final
    // state as the key evidence.
    let live_a_result = phase1_a.join();
    let live_b_result = phase1_b.join();
    let (live_a, live_b) = match (live_a_result, live_b_result) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            let describe = |r: &Result<ChildReport, Box<dyn std::any::Any + Send>>| match r {
                Ok(r) => format!(
                    "node={} converged={} stop={} applied={} pulled={} sent={}",
                    r.node, r.converged, r.stop_reason, r.applied, r.pages_pulled, r.sent_batches
                ),
                Err(panic) => panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "non-string panic".to_string()),
            };
            panic!(
                "phase 1 child failed:\n  a: {}\n  b: {}",
                describe(&a),
                describe(&b)
            );
        }
    };

    // Phase 2, sequential restarts: B resumes from its snapshot and writes
    // b/2 while A is already down (A's phase-1 child exited), then A resumes
    // and must pull what it missed while down. The restored state of each
    // device is verified by the child before it starts the worker.
    let mut restart_b = base_config(&relay_url, &channel_id, &token_b, "cpp-b");
    restart_b.push(format!("stateHex {}", live_b.state_hex));
    restart_b.push("expectBefore b/0=b0".to_string());
    restart_b.push("expectBefore b/1=b1".to_string());
    restart_b.push("write b/2=b2".to_string());
    restart_b.push("expect b/0=b0".to_string());
    restart_b.push("expect b/1=b1".to_string());
    restart_b.push("expect b/2=b2".to_string());
    let restarted_b = run_child(
        &child,
        &libdir,
        &tmp,
        "restart",
        "restart-cpp-b",
        &restart_b,
    );

    let mut restart_a = base_config(&relay_url, &channel_id, &token_a, "cpp-a");
    restart_a.push(format!("stateHex {}", live_a.state_hex));
    restart_a.push("expectBefore a/0=a0".to_string());
    restart_a.push("write a/1=a1".to_string());
    restart_a.push("expect a/0=a0".to_string());
    restart_a.push("expect a/1=a1".to_string());
    restart_a.push("expect b/1=b1".to_string());
    restart_a.push("expect b/2=b2".to_string());
    let restarted_a = run_child(
        &child,
        &libdir,
        &tmp,
        "restart",
        "restart-cpp-a",
        &restart_a,
    );

    assert_child_ok("live-a", &live_a, true);
    assert_child_ok("live-b", &live_b, true);
    assert_child_ok("restart-b", &restarted_b, false);
    assert_child_ok("restart-a", &restarted_a, true);
    assert_eq!(
        restarted_a.got.get("b/2").map(String::as_str),
        Some("b2"),
        "A must catch what B wrote while A was down, got {:?}",
        restarted_a.got.get("b/2")
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
