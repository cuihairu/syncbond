//! C-side acceptance: the header compiles under strict warnings, and a pure C
//! program completes the pair/sync flow against the built cdylib.

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

/// Acceptance: the header compiles with `gcc -Wall -Werror`.
#[test]
fn header_compiles_under_strict_warnings() {
    let include = manifest_dir().join("include");
    run(Command::new("gcc")
        .args(["-Wall", "-Werror", "-fsyntax-only", "-I"])
        .arg(&include)
        .arg(include.join("syncbond.h")));
}

/// Acceptance: a pure C program completes pair/sync end to end.
#[test]
fn pure_c_program_completes_pair_and_sync() {
    let manifest = manifest_dir();
    // Build the cdylib into its own target dir so the nested cargo does not
    // wait on the outer test build's lock.
    let target = manifest.join("../../target/ffi-c");
    let status = Command::new(cargo_bin())
        .args(["build", "-p", "syncbond-ffi"])
        .env("CARGO_TARGET_DIR", &target)
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "nested cargo build failed");

    let libdir = target.join("debug");
    let out_dir = target.join("c-example");
    std::fs::create_dir_all(&out_dir).expect("create out dir");
    let exe = out_dir.join("pair_sync");

    run(Command::new("gcc")
        .args(["-Wall", "-Werror", "-o"])
        .arg(&exe)
        .arg(manifest.join("examples/pair_sync.c"))
        .arg("-I")
        .arg(manifest.join("include"))
        .arg("-L")
        .arg(&libdir)
        .arg("-lsyncbond_ffi")
        .arg(format!("-Wl,-rpath,{}", libdir.display()))
        .arg("-lpthread"));

    run(Command::new(&exe).current_dir(&out_dir));
}
