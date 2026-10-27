//! Go-side acceptance: the cgo binding builds against the static library,
//! `go test` passes with cgo, `CGO_ENABLED=0 go test` still passes by failing
//! every entry point loudly, and the example program completes pair/sync.

use std::path::PathBuf;
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

/// Acceptance: one ordered run — build the release static library, place it
/// where the binding's `#cgo LDFLAGS` looks for it, run `go vet` and the cgo
/// test suite, run the suite again with CGO_ENABLED=0 (every entry point must
/// report ErrCgoDisabled), then run the example program. A single test keeps
/// the build -> test -> example order deterministic.
#[test]
fn go_suite_passes() {
    let manifest = manifest_dir();
    // Build the staticlib into its own target dir so the nested cargo does
    // not wait on the outer test build's lock.
    let target = manifest.join("../../target/ffi-go");
    let status = Command::new(cargo_bin())
        .args(["build", "--release", "-p", "syncbond-ffi"])
        .env("CARGO_TARGET_DIR", &target)
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "nested cargo build failed");

    // The binding links <repo>/target/release/libsyncbond_ffi.a; copy the
    // fresh static library there so the link step sees this build's artifact.
    let release = manifest.join("../../target/release");
    std::fs::create_dir_all(&release).expect("create release dir");
    std::fs::copy(
        target.join("release/libsyncbond_ffi.a"),
        release.join("libsyncbond_ffi.a"),
    )
    .expect("copy static library into target/release");

    let go_dir = manifest.join("go");

    run(Command::new("go")
        .args(["vet", "./..."])
        .current_dir(&go_dir));
    run(Command::new("go")
        .env("CGO_ENABLED", "1")
        .args(["test", "./..."])
        .current_dir(&go_dir));
    // Without cgo the suite must still pass: every entry point fails loudly
    // with ErrCgoDisabled instead of silently producing empty state.
    run(Command::new("go")
        .env("CGO_ENABLED", "0")
        .args(["test", "./..."])
        .current_dir(&go_dir));
    run(Command::new("go")
        .env("CGO_ENABLED", "1")
        .args(["run", "pair_sync.go"])
        .current_dir(&go_dir));
}
