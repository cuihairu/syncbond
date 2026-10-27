//! Python-side acceptance: the wheel builds and installs, the example program
//! completes the pair/sync flow, and the pytest suite passes.

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn python() -> &'static str {
    std::env::var("SYNCBOND_PYTHON")
        .unwrap_or_else(|_| "python3".to_string())
        .leak()
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

/// Acceptance: the wheel builds and installs, the pytest suite passes against
/// it, the example program completes pair/sync, and the module imports.
/// One test keeps the build -> install -> run order deterministic.
#[test]
fn python_wheel_installs_and_pytest_passes() {
    let manifest = manifest_dir();
    // Build into its own target dir so the nested cargo does not wait on the
    // outer test build's lock.
    let target = manifest.join("../../target/ffi-python");
    let dist = target.join("dist");
    std::fs::create_dir_all(&dist).expect("create dist dir");

    run(Command::new("maturin")
        .args(["build", "-m"])
        .arg(manifest.join("Cargo.toml"))
        .arg("--release")
        .arg("-o")
        .arg(&dist)
        .env("CARGO_TARGET_DIR", &target));

    let wheel = std::fs::read_dir(&dist)
        .expect("read dist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "whl"))
        .expect("maturin produced no wheel");

    let site = target.join("site");
    std::fs::create_dir_all(&site).expect("create site dir");
    run(Command::new(python())
        .args(["-m", "pip", "install", "--quiet", "--upgrade", "--target"])
        .arg(&site)
        .arg(&wheel));

    run(Command::new(python())
        .args(["-c", "import syncbond; assert syncbond.err_none() == 0"])
        .env("PYTHONPATH", &site));

    run(Command::new(python())
        .args(["-m", "pytest", "-q", "--rootdir"])
        .arg(&manifest)
        .arg(manifest.join("tests/test_pair_sync.py"))
        .env("PYTHONPATH", &site));

    let run_dir = target.join("py-example");
    std::fs::create_dir_all(&run_dir).expect("create out dir");
    run(Command::new(python())
        .arg(manifest.join("examples/pair_sync.py"))
        .current_dir(&run_dir)
        .env("PYTHONPATH", &site));
}
