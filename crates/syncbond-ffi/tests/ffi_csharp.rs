//! C#-side acceptance: the library packs into a local NuGet feed, the test
//! project restores that package from the feed, the xUnit suite passes, and
//! the example program completes pair/sync.

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

/// Acceptance: one ordered run — build the release shared library into its
/// own target dir, pack the library into the local feed, drop the cached
/// copy of the same version so restore sees this build, run the xUnit suite
/// against the restored package, then run the example. A single test keeps
/// the order deterministic.
#[test]
fn csharp_suite_passes() {
    let manifest = manifest_dir();
    let target = manifest.join("../../target/ffi-csharp");
    let status = Command::new(cargo_bin())
        .args(["build", "--release", "-p", "syncbond-ffi"])
        .env("CARGO_TARGET_DIR", &target)
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "nested cargo build failed");
    let native = target.join("release/libsyncbond_ffi.so");
    assert!(native.exists(), "shared library missing after build");

    let csharp = manifest.join("csharp");

    // Pack the library into the local feed; the test project restores it
    // from there (see NuGet.config), which is the pullability proof.
    run(Command::new("dotnet")
        .args(["pack", "Syncbond", "-c", "Release", "-o", "artifacts"])
        .current_dir(&csharp));

    // A fixed package version caches globally; drop the cached copy so this
    // build's package is what the restore resolves.
    let _ = std::fs::remove_dir_all(
        std::env::home_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join(".nuget/packages/syncbond/0.1.0"),
    );

    run(Command::new("dotnet")
        .args(["test", "Syncbond.Tests", "-c", "Release"])
        .env("SYNCBOND_NATIVE", &native)
        .current_dir(&csharp));
    run(Command::new("dotnet")
        .args(["run", "--project", "Syncbond.Example"])
        .env("SYNCBOND_NATIVE", &native)
        .current_dir(&csharp));
}
