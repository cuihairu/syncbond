//! Java-side acceptance: the JNI shim compiles against the release C ABI
//! shared library, the JUnit suite passes, the artifact publishes to the
//! local Maven repository (pullable), and the example program completes
//! pair/sync.

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
/// own target dir, copy it into target/release (the Gradle build copies it
/// beside the shim and links against it), run `gradle test`, publish the
/// artifact to the local Maven repository, then compile and run the example
/// program. A single test keeps the order deterministic.
#[test]
fn java_suite_passes() {
    let manifest = manifest_dir();
    let target = manifest.join("../../target/ffi-java");
    let status = Command::new(cargo_bin())
        .args(["build", "--release", "-p", "syncbond-ffi"])
        .env("CARGO_TARGET_DIR", &target)
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "nested cargo build failed");

    let release = manifest.join("../../target/release");
    std::fs::create_dir_all(&release).expect("create release dir");
    std::fs::copy(
        target.join("release/libsyncbond_ffi.so"),
        release.join("libsyncbond_ffi.so"),
    )
    .expect("copy shared library into target/release");

    let java_dir = manifest.join("java");

    // The JUnit suite compiles the JNI shim and runs the 13 tests.
    run(Command::new("gradle")
        .args(["--no-daemon", "test"])
        .current_dir(&java_dir));
    // Local publication proves the artifact is pullable without any remote.
    run(Command::new("gradle")
        .args(["--no-daemon", "publishToMavenLocal"])
        .current_dir(&java_dir));

    // Compile and run the example program against the built classes.
    run(Command::new("javac")
        .args([
            "-cp",
            "build/classes/java/main",
            "-d",
            "build/classes/java/example",
            "examples/PairSync.java",
        ])
        .current_dir(&java_dir));
    run(Command::new("java")
        .args([
            "-Dsyncbond.lib=build/libs/libsyncbond_java.so",
            "-cp",
            "build/classes/java/main:build/classes/java/example",
            "PairSync",
        ])
        .current_dir(&java_dir));
}
