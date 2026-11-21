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

/// Build the cdylib into its own target dir so the nested cargo does not
/// wait on the outer test build's lock; returns (libdir, out_dir).
fn build_cdylib() -> (PathBuf, PathBuf) {
    let manifest = manifest_dir();
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
    (libdir, out_dir)
}

/// Compile one pure C example against the built cdylib and run it.
fn compile_and_run_c(source: &str, exe_name: &str, args: &[&std::path::Path]) {
    let manifest = manifest_dir();
    let (libdir, out_dir) = build_cdylib();
    let exe = out_dir.join(exe_name);
    run(Command::new("gcc")
        .args(["-Wall", "-Werror", "-o"])
        .arg(&exe)
        .arg(manifest.join("examples").join(source))
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
    let mut command = Command::new(&exe);
    command
        .env("LD_LIBRARY_PATH", &libdir)
        .current_dir(&out_dir);
    for arg in args {
        command.arg(arg);
    }
    run(&mut command);
}

/// Acceptance: a pure C program completes pair/sync end to end.
#[test]
fn pure_c_program_completes_pair_and_sync() {
    compile_and_run_c(
        "pair_sync.c",
        "pair_sync",
        &[
            &manifest_dir().join("fixtures/conformance.json"),
            &manifest_dir().join("fixtures/conformance.expected.json"),
        ],
    );
}

/// Acceptance (DSR-34): a pure C program starts two separated pairing ends
/// from two existing identities, routes the protocol frames itself, and
/// exercises cancel, late-frame, ownership and error semantics.
#[test]
fn pure_c_program_drives_separated_pairing_ends() {
    compile_and_run_c("pair_frames.c", "pair_frames", &[]);
}

/// Acceptance (DSR-35): a pure C program exports a device's committed state
/// and receive cursors, restores them into fresh handles, loses no remote
/// data, and hits the snapshot's version and input validation.
#[test]
fn pure_c_program_restores_a_replicated_state() {
    compile_and_run_c("state_snapshot.c", "state_snapshot", &[]);
}
