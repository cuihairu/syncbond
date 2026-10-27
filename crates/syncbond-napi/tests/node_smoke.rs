//! Node acceptance for the napi-rs binding: builds the addon (`napi build`)
//! and runs the Node test suite. The suite exercises pairing, the full-duplex
//! encrypted sync exchange (both halves concurrently), convergence, delete
//! tombstoning, and invalidated-session rejection over the C ABI.
//!
//! Skips (with a notice) when `node`/`npm` or the local `node_modules` (the
//! napi CLI) is missing, so the plain `cargo test` job stays green on
//! machines without the Node toolchain; the CI `bindings-ts` job is the
//! canonical Node gate.

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
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

#[test]
fn node_smoke_passes() {
    let root = manifest_dir().join("../..");
    let package = root.join("packages/ts-bindings");
    if !tool_available("node") || !tool_available("npm") {
        eprintln!("skipping Node smoke: node or npm not on PATH");
        return;
    }
    if !package.join("node_modules/.bin/napi").exists() {
        eprintln!("skipping Node smoke: node_modules (napi CLI) not installed");
        return;
    }

    // Build the addon into src/native (gitignored), then run the suite.
    run(Command::new("npm")
        .args(["run", "build"])
        .current_dir(&package));
    run(Command::new("node")
        .args(["--test", "src/index.test.js"])
        .current_dir(&package));
}
