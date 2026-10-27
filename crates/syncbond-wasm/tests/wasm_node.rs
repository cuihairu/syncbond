//! Browser-WASM acceptance: wasm-pack builds the crate for
//! `wasm32-unknown-unknown`, and the Node test suite runs the generated glue
//! against the `web` target. The suite covers replicator CRUD, the byte
//! save/load round-trip, the cross-language conformance runner, and the
//! explicit in-memory degradation path when IndexedDB is absent.
//!
//! Skips (with a notice) when `wasm-pack` or `node` is not on PATH, so the
//! plain `cargo test` job can run on machines without the wasm toolchain.

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
fn wasm_node_suite_passes() {
    if !tool_available("wasm-pack") || !tool_available("node") {
        eprintln!("skipping wasm Node suite: wasm-pack or node not on PATH");
        return;
    }
    let root = manifest_dir().join("../..");
    let package = root.join("packages/ts-bindings");

    // Build the web-target wasm package into the TS package's src/wasm.
    run(Command::new("wasm-pack")
        .arg("build")
        .arg(manifest_dir())
        .args(["--target", "web", "--release"])
        .args(["--out-dir", "../../packages/ts-bindings/src/wasm-gen"])
        .current_dir(&root));

    // Run the wasm-specific Node suite.
    run(Command::new("node")
        .args(["--test", "src/wasm.test.js"])
        .current_dir(&package));
}
