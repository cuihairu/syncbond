//! The cross-language conformance anchor: every binding runs THIS fixture
//! (`fixtures/conformance.json`) through the same `sb_conformance_run` and
//! asserts the same facts. This Rust-side test is the reference: it pins the
//! three core behaviors — LWW merge, tombstone GC blocking resurrection, and
//! key-epoch rotation evicting a removed device — and the exact canonical
//! report bytes, so any language drift shows up as a report mismatch.

use std::collections::BTreeSet;

fn fixture() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/conformance.json");
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read fixture: {error}"))
}

fn report_raw(fixture: &str) -> String {
    unsafe {
        let c_fixture = std::ffi::CString::new(fixture).expect("fixture is valid c string");
        let raw = syncbond_ffi::abi::sb_conformance_run(c_fixture.as_ptr());
        if raw.is_null() {
            let message = std::ffi::CStr::from_ptr(syncbond_ffi::abi::sb_last_error())
                .to_string_lossy()
                .into_owned();
            let code = syncbond_ffi::abi::sb_last_error_code();
            panic!("conformance run failed: {message} (code {code})");
        }
        let text = std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned();
        syncbond_ffi::abi::sb_free_string(raw);
        text
    }
}

fn report(fixture: &str) -> serde_json::Value {
    serde_json::from_str(&report_raw(fixture)).expect("report is valid json")
}

#[test]
fn canonical_fixture_passes_all_checks() {
    let report = report(&fixture());
    assert_eq!(report["version"], 1, "fixture version");
    assert_eq!(report["ok"], true, "overall report ok");

    let scenarios: BTreeSet<String> = report["scenarios"]
        .as_array()
        .expect("scenarios array")
        .iter()
        .map(|scenario| scenario["name"].as_str().expect("name").to_string())
        .collect();
    assert_eq!(
        scenarios,
        BTreeSet::from([
            "merge_lww".to_string(),
            "tombstone_gc_blocks_resurrection".to_string(),
            "malformed_strategy_payload_is_rejected".to_string(),
            "malformed_pn_counter_payload_is_rejected".to_string(),
            "rotation".to_string(),
        ]),
        "exactly the canonical scenarios"
    );

    for scenario in report["scenarios"].as_array().expect("scenarios") {
        assert_eq!(scenario["ok"], true, "scenario ok: {scenario}");
        for check in scenario["checks"].as_array().expect("checks") {
            assert_eq!(check["ok"], true, "check ok: {check}");
        }
    }
}

#[test]
fn canonical_fixture_pins_each_behavior() {
    let report = report(&fixture());
    let scenarios: Vec<serde_json::Value> =
        report["scenarios"].as_array().expect("scenarios").clone();
    let by_name = |name: &str| {
        scenarios
            .iter()
            .find(|scenario| scenario["name"] == name)
            .unwrap_or_else(|| panic!("missing scenario {name}"))
            .clone()
    };
    let check = |scenario: &serde_json::Value, name: &str| {
        scenario["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .find(|check| check["name"] == name)
            .unwrap_or_else(|| panic!("missing check {name}"))
            .clone()
    };

    // merge: both sides converge on the newer write.
    let merge = by_name("merge_lww");
    for name in ["left_sees_newer_write", "right_keeps_newer_write"] {
        assert_eq!(check(&merge, name)["ok"], true, "{name}");
    }

    // tombstone GC: the barrier blocks the pre-delete write, both sides stay
    // tombstoned, and the barrier holds the compacted tombstone.
    let gc = by_name("tombstone_gc_blocks_resurrection");
    for name in [
        "old_write_cannot_resurrect_after_gc",
        "barrier_keeps_tombstone",
        "peer_stays_tombstoned",
    ] {
        assert_eq!(check(&gc, name)["ok"], true, "{name}");
    }

    // malformed strategy payloads: the binding must reject them with an explicit
    // error rather than panicking, so no language can crash or diverge here.
    for scenario_name in [
        "malformed_strategy_payload_is_rejected",
        "malformed_pn_counter_payload_is_rejected",
    ] {
        let scenario = by_name(scenario_name);
        let check_name = if scenario_name.contains("pn_counter") {
            "malformed_pn_counter_payload_rejected"
        } else {
            "malformed_or_set_payload_rejected"
        };
        let rejection = scenario["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .find(|candidate| candidate["name"] == check_name)
            .unwrap_or_else(|| panic!("missing check {check_name} in {scenario_name}"))
            .clone();
        assert_eq!(rejection["ok"], true, "reject check ok: {rejection}");
        assert_eq!(
            rejection["actual"], "true",
            "payload must be rejected, not accepted"
        );
    }

    // keyEpoch: the removed device cannot open the envelope sealed after
    // rotation (SB_ERR_KEY_EPOCH_MISMATCH), survivors can.
    let rotation = by_name("rotation");
    assert_eq!(
        check(
            &rotation,
            "removed_device_cannot_open_envelope_sealed_after_rotation"
        )["ok"],
        true
    );
    let rejected = rotation["rotations"]
        .as_array()
        .expect("rotations")
        .iter()
        .find(|row| row["device"] == "gone")
        .expect("removed device row");
    assert_eq!(rejected["rotated_error"], -5, "key epoch mismatch code");
    assert_eq!(rejected["opened_rotated"], false);
}

#[test]
fn canonical_report_is_stable() {
    // The report is deterministic: re-running the same fixture yields the
    // same canonical JSON, which is what every language compares against.
    let first = report(&fixture());
    let second = report(&fixture());
    assert_eq!(first, second, "report must be deterministic");
}

#[test]
fn canonical_report_matches_expected_file() {
    // Every binding byte-compares its report against
    // `fixtures/conformance.expected.json` (regenerate with
    // `cargo test -p syncbond-ffi --test conformance_fixture --
    //  --ignored regenerate_expected_report`).
    let expected = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/conformance.expected.json"),
    )
    .unwrap_or_else(|error| panic!("read expected report: {error}"));
    // Byte-for-byte: the report is deterministic, so a strict string compare
    // is the strongest cross-language guarantee (a language that mangles the
    // fixture or the report fails here, not just on a semantic check).
    assert_eq!(
        report_raw(&fixture()),
        expected.trim_end(),
        "canonical report"
    );
}

/// Regenerates `fixtures/conformance.expected.json` from the canonical
/// fixture. Kept behind `--ignored` so normal runs never write to the tree;
/// after changing the runner or the fixture, re-run it and commit the diff
/// together with the change.
#[test]
#[ignore]
fn regenerate_expected_report() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/conformance.expected.json");
    // No trailing newline: every language compares its report string against
    // this file byte-for-byte, and the runner output has no newline either.
    std::fs::write(&path, report_raw(&fixture())).expect("write expected report");
    println!("wrote {}", path.display());
}
