//! Direct coverage of scenario-runner error branches and check states that
//! the canonical conformance fixture does not reach.

use syncbond_ffi::scenario::run;

fn expect_input_error(fixture: &str, needle: &str) {
    let error = run(fixture).expect_err("expected input error");
    assert!(error.message.contains(needle), "{needle} not in {}", error.message);
}

#[test]
fn invalid_fixture_and_version_are_rejected() {
    expect_input_error("{bad", "invalid fixture json");
    expect_input_error(r#"{"version":2,"scenarios":[]}"#, "unsupported fixture version");
    expect_input_error(r#"{"version":1,"scenarios":["not-an-object"]}"#, "missing field type");
    expect_input_error(r#"{"version":1,"scenarios":[{"type":"unknown"}]}"#, "unknown scenario type");
}

#[test]
fn replication_step_validation_is_covered() {
    let base = r#"{"version":1,"scenarios":[{"type":"replication","name":"r","strategy":"lww","nodes":{"a":1000},"steps":[STEP]}]}"#;
    for (step, needle) in [
        (r#"{"put":{"node":"b","key":"k","payload":"YQ"}}"#, "unknown node b"),
        (r#"{"delete":{"node":"b","key":"k"}}"#, "unknown node b"),
        (r#"{"sync":["a"]}"#, "sync needs two nodes"),
        (r#"{"gc":{"node":"b","older_than_ms":1,"now_ms":2}}"#, "unknown node b"),
        (r#"{"gc":{"node":"a","older_than_ms":1,"now_ms":2,"mode":"weird"}}"#, "unknown gc mode"),
        (r#"{"check":{"name":"c","node":"b"}}"#, "unknown node b"),
        (r#"{"check":{"name":"c","node":"a"}}"#, "needs key, live_keys or barriers"),
        (r#"{"check":{"name":"c","node":"a","key":"k","state":"wat"}}"#, "unknown check state"),
        (r#"{"nonsense":{"node":"a"}}"#, "unknown step type"),
        (r#"{"put":{"node":"a","key":"k"}}"#, "missing field payload"),
    ] {
        expect_input_error(&base.replace("STEP", step), needle);
    }
    // Two keys in one step object must be rejected.
    expect_input_error(
        r#"{"version":1,"scenarios":[{"type":"replication","name":"r","strategy":"lww","nodes":{"a":1000},"steps":[{"put":{"node":"a","key":"k","payload":"YQ"},"delete":{"node":"a","key":"k"}}]}]}"#,
        "one-key object",
    );
}

#[test]
fn replication_checks_evaluate_live_and_absent_states() {
    let report = run(r#"{"version":1,"scenarios":[{"type":"replication","name":"r","strategy":"lww","nodes":{"a":1000,"b":1000},"steps":[
        {"put":{"node":"a","key":"k","payload":"YQ"}},
        {"sync":["a","b"]},
        {"check":{"name":"live","node":"a","key":"k","state":"live"}},
        {"check":{"name":"absent","node":"a","key":"m","state":"absent"}},
        {"check":{"name":"keys","node":"a","live_keys":["k"]}}
    ]}]}"#).unwrap();
    assert!(report.contains("\"ok\":true"), "{report}");
}

#[test]
fn key_epoch_scenario_validation_is_covered() {
    let base = r#"{"version":1,"scenarios":[{"type":"key_epoch","name":"r","group":"g","epoch":1,"next_epoch":2,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","next_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","survivors":["a"],"removed":["b"],"plaintext":"YQ"}]}"#;
    let report = run(base).unwrap();
    assert!(report.contains("\"type\":\"key_epoch\""));
    // A key_epoch with no survivors fails when choosing a sender.
    expect_input_error(
        r#"{"version":1,"scenarios":[{"type":"key_epoch","name":"r","group":"g","epoch":1,"next_epoch":2,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","next_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","survivors":[],"removed":["b"],"plaintext":"YQ"}]}"#,
        "needs at least one survivor",
    );
}
