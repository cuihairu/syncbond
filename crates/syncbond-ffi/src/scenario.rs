//! Cross-language conformance runner.
//!
//! Every language binding drives this same runner over the same fixture
//! file, so the merge / keyEpoch / tombstone-GC behavior can be compared
//! byte-for-byte. It only calls public core APIs; it contains no protocol
//! logic of its own.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use syncbond_core::crypto::b64url_encode;

use crate::error::FfiError;
use crate::handles::{Keyring, Replicator};

pub const FIXTURE_VERSION: u32 = 1;

/// Run one fixture and return the canonical report.
pub fn run(fixture_json: &str) -> Result<String, FfiError> {
    let fixture: Value = serde_json::from_str(fixture_json)
        .map_err(|error| FfiError::input(format!("invalid fixture json: {error}")))?;
    let version = u64_field(&fixture, "version")?;
    if version != FIXTURE_VERSION as u64 {
        return Err(FfiError::input(format!(
            "unsupported fixture version {version}; this library runs version {FIXTURE_VERSION}"
        )));
    }
    let mut report = Vec::with_capacity(array_entries(&fixture, "scenarios")?.len());
    for spec in array_entries(&fixture, "scenarios")? {
        report.push(match string_field(spec, "type")?.as_str() {
            "replication" => run_replication(spec),
            "key_epoch" => run_key_epoch(spec),
            other => Err(FfiError::input(format!("unknown scenario type {other}"))),
        }?);
    }
    let ok = report
        .iter()
        .all(|scenario| scenario.get("ok") == Some(&Value::Bool(true)));
    Ok(serde_json::to_string(&json!({
        "ok": ok,
        "scenarios": report,
        "version": FIXTURE_VERSION,
    }))
    .expect("report serialization is infallible"))
}

fn run_replication(spec: &Value) -> Result<Value, FfiError> {
    let name = string_field(spec, "name")?;
    let strategy_code = match string_field(spec, "strategy")?.as_str() {
        "or_set" => crate::error::SB_STRATEGY_OR_SET,
        "pn_counter" => crate::error::SB_STRATEGY_PN_COUNTER,
        "lww" | "" => crate::error::SB_STRATEGY_LWW_HLC,
        other => return Err(FfiError::input(format!("unknown strategy {other}"))),
    };
    let mut nodes: BTreeMap<String, Replicator> = BTreeMap::new();
    for (node_id, now_ms) in object_field(spec, "nodes")? {
        let clock = now_ms
            .as_u64()
            .ok_or_else(|| FfiError::input(format!("node {node_id} clock must be a number")))?;
        nodes.insert(
            node_id.clone(),
            Replicator::new_clock(node_id, strategy_code, clock)?,
        );
    }
    let mut checks = Vec::new();
    for step in array_entries(spec, "steps")? {
        match step_type(step)?.as_str() {
            "put" => {
                let args = object_field(step, "put")?;
                let node_id = map_string_field(args, "node")?;
                let key = map_string_field(args, "key")?;
                let payload = decode(&map_string_field(args, "payload")?)?;
                nodes
                    .get_mut(&node_id)
                    .ok_or_else(|| FfiError::input(format!("unknown node {node_id}")))?
                    .put(&key, &payload)?;
            }
            // A step that must fail with an explicit error (not a panic). The
            // cross-language runner records whether the binding rejected the
            // malformed payload, so every language can be compared inline.
            "reject_put" => {
                let args = object_field(step, "reject_put")?;
                let node_id = map_string_field(args, "node")?;
                let key = map_string_field(args, "key")?;
                let name = args
                    .get("name")
                    .map(string_value)
                    .transpose()?
                    .unwrap_or_else(|| "reject_put".to_string());
                let payload = decode(&map_string_field(args, "payload")?)?;
                let rejected = nodes
                    .get_mut(&node_id)
                    .ok_or_else(|| FfiError::input(format!("unknown node {node_id}")))?
                    .put(&key, &payload)
                    .map(|_| false)
                    .map_err(|_| ());
                let (accepted, reason) = match rejected {
                    Ok(accepted) => (accepted, "no error".to_string()),
                    Err(()) => (true, "explicit error".to_string()),
                };
                checks.push(json!({
                    "actual": accepted.to_string(),
                    "expected": "true",
                    "name": name,
                    "ok": accepted,
                    "reason": reason,
                }));
            }
            "delete" => {
                let args = object_field(step, "delete")?;
                let node_id = map_string_field(args, "node")?;
                let key = map_string_field(args, "key")?;
                nodes
                    .get_mut(&node_id)
                    .ok_or_else(|| FfiError::input(format!("unknown node {node_id}")))?
                    .delete(&key)?;
            }
            "sync" => {
                let peers = strings(array_field(step, "sync")?)?;
                let (left, right) = peers
                    .first()
                    .zip(peers.get(1))
                    .ok_or_else(|| FfiError::input("sync needs two nodes"))?;
                exchange_oplogs(&mut nodes, left, right)?;
            }
            "gc" => {
                let args = object_field(step, "gc")?;
                let node_id = map_string_field(args, "node")?;
                let older_than_ms = map_u64_field(args, "older_than_ms")?;
                let now_ms = args
                    .get("now_ms")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| FfiError::input("gc needs now_ms"))?;
                let mode = args
                    .get("mode")
                    .and_then(Value::as_str)
                    .unwrap_or("dominance");
                let replicator = nodes
                    .get_mut(&node_id)
                    .ok_or_else(|| FfiError::input(format!("unknown node {node_id}")))?;
                match mode {
                    // The default (and safe) mode requires causal dominance;
                    // it is not deterministic under fixed clocks, so fixtures
                    // that must collect use `time_only`.
                    "dominance" => {
                        replicator.gc_tombstones(now_ms, older_than_ms)?;
                    }
                    "time_only" => {
                        replicator.gc_tombstones_time_only(now_ms, older_than_ms)?;
                    }
                    other => return Err(FfiError::input(format!("unknown gc mode {other}"))),
                }
            }
            "check" => checks.push(run_check(object_field(step, "check")?, &nodes)?),
            other => return Err(FfiError::input(format!("unknown step type {other}"))),
        }
    }
    let mut state = BTreeMap::new();
    for (node_id, replicator) in &nodes {
        state.insert(node_id.clone(), replicator.dump());
    }
    Ok(json!({
        "checks": checks,
        "name": name,
        "ok": checks.iter().all(|check| check.get("ok") == Some(&Value::Bool(true))),
        "state": state,
        "type": "replication",
    }))
}

fn run_check(
    spec: &Map<String, Value>,
    nodes: &BTreeMap<String, Replicator>,
) -> Result<Value, FfiError> {
    let name = map_string_field(spec, "name")?;
    let node_id = map_string_field(spec, "node")?;
    let replicator = nodes
        .get(&node_id)
        .ok_or_else(|| FfiError::input(format!("unknown node {node_id}")))?;
    let (ok, expected, actual) = if let Some(key) = spec.get("key") {
        let key = string_value(key)?;
        let state = spec
            .get("state")
            .map(string_value)
            .transpose()?
            .unwrap_or_else(|| "live".to_string());
        match (replicator.get(&key), state.as_str()) {
            (Some(payload), "live") => {
                let want = match spec.get("payload") {
                    Some(payload) => Some(decode(&string_value(payload)?)?),
                    None => None,
                };
                let payload_b64 = b64url_encode(&payload);
                let matches = want.as_deref() == Some(payload.as_slice());
                (
                    matches,
                    want.map(|value| b64url_encode(&value))
                        .unwrap_or_else(|| "any".to_string()),
                    payload_b64,
                )
            }
            (Some(_), "absent") => (false, "absent".to_string(), "live".to_string()),
            (None, "live") => (false, "live".to_string(), "absent".to_string()),
            (None, "absent") => (true, "absent".to_string(), "absent".to_string()),
            (_, other) => return Err(FfiError::input(format!("unknown check state {other}"))),
        }
    } else if let Some(want) = spec.get("live_keys") {
        let want = strings(want)?;
        let actual = replicator.live_keys();
        (want == actual, want.join(","), actual.join(","))
    } else if let Some(want) = spec.get("barriers") {
        let want = strings(want)?;
        // The barrier dump is a key -> compacted-tombstone object; compare
        // its sorted keys against the expected barrier list.
        let actual: Vec<String> =
            serde_json::from_str::<BTreeMap<String, Value>>(&replicator.gc_barriers_json())
                .map_err(|error| FfiError::internal(error.to_string()))?
                .into_keys()
                .collect();
        (want == actual, want.join(","), actual.join(","))
    } else {
        return Err(FfiError::input(format!(
            "check {name} needs key, live_keys or barriers"
        )));
    };
    Ok(json!({
        "actual": actual,
        "expected": expected,
        "name": name,
        "ok": ok,
    }))
}

/// Exchange both oplogs the way a relay round trip would deliver them.
fn exchange_oplogs(
    nodes: &mut BTreeMap<String, Replicator>,
    left: &str,
    right: &str,
) -> Result<(), FfiError> {
    let snapshot =
        |nodes: &BTreeMap<String, Replicator>, node_id: &str| -> Result<Vec<String>, FfiError> {
            let replicator = nodes
                .get(node_id)
                .ok_or_else(|| FfiError::input(format!("unknown node {node_id}")))?;
            (0..replicator.oplog_len())
                .map(|index| replicator.op_json(index))
                .collect()
        };
    let left_ops = snapshot(nodes, left)?;
    let right_ops = snapshot(nodes, right)?;
    apply_all(nodes, left, &right_ops)?;
    apply_all(nodes, right, &left_ops)
}

fn apply_all(
    nodes: &mut BTreeMap<String, Replicator>,
    node_id: &str,
    ops: &[String],
) -> Result<(), FfiError> {
    for op in ops {
        let _applied = nodes
            .get_mut(node_id)
            .ok_or_else(|| FfiError::input(format!("unknown node {node_id}")))?
            .apply_remote_json(op)?;
    }
    Ok(())
}

fn run_key_epoch(spec: &Value) -> Result<Value, FfiError> {
    let name = string_field(spec, "name")?;
    let group = string_field(spec, "group")?;
    let epoch = u64_field(spec, "epoch")?;
    let next_epoch = u64_field(spec, "next_epoch")?;
    let key = decode(&string_field(spec, "key")?)?;
    let next_key = decode(&string_field(spec, "next_key")?)?;
    let survivors = strings(
        spec.get("survivors")
            .ok_or_else(|| FfiError::input("missing survivors"))?,
    )?;
    let removed = strings(
        spec.get("removed")
            .ok_or_else(|| FfiError::input("missing removed"))?,
    )?;
    let plaintext = match spec.get("plaintext") {
        Some(value) => Some(decode(&string_value(value)?)?),
        None => None,
    }
    .unwrap_or_else(|| b"payload after rotation".to_vec());
    let sender = spec
        .get("sender")
        .and_then(Value::as_str)
        .unwrap_or(
            survivors
                .first()
                .ok_or_else(|| FfiError::input("needs at least one survivor"))?,
        )
        .to_string();

    // Every device holds the pre-rotation key; only survivors receive the new one.
    let mut devices: BTreeMap<String, Keyring> = BTreeMap::new();
    for device in survivors.iter().chain(removed.iter()) {
        devices.insert(device.clone(), Keyring::import(&group, epoch, &key)?);
    }
    for device in &survivors {
        devices.insert(
            device.clone(),
            Keyring::import(&group, next_epoch, &next_key)?,
        );
    }

    let rotated = devices[&survivors[0]].seal_json(&sender, &plaintext);
    let pre_rotation = devices[&removed[0]].seal_json(&removed[0], &plaintext);

    let mut rows = Vec::new();
    for (device, keyring) in &devices {
        let rotated_result = keyring.open_json(&rotated);
        let pre_rotation_result = keyring.open_json(&pre_rotation);
        rows.push(json!({
            "device": device,
            "epoch": keyring.epoch(),
            "opened_pre_rotation": pre_rotation_result.is_ok(),
            "opened_rotated": rotated_result.is_ok(),
            "rotated_payload": rotated_result.as_ref().ok().map(|payload| b64url_encode(payload)),
            "rotated_error": rotated_result.as_ref().err().map(|error| error.code),
        }));
    }

    let for_devices = |rows: &[Value], devices: &[String], field: &str| -> Vec<bool> {
        rows.iter()
            .filter(|row| device_match(row, devices))
            .map(|row| row.get(field).and_then(Value::as_bool).unwrap_or(false))
            .collect()
    };
    let check = |rows: &[Value], devices: &[String], field: &str, want: bool, name: &str| {
        let actual = for_devices(rows, devices, field);
        json!({
            "actual": actual,
            "expected": vec![want; actual.len()],
            "name": name,
            "ok": actual.iter().all(|flag| *flag == want),
        })
    };

    let checks = vec![
        check(
            &rows,
            &survivors,
            "opened_rotated",
            true,
            "survivor_opens_envelope_sealed_after_rotation",
        ),
        check(
            &rows,
            &survivors,
            "opened_pre_rotation",
            false,
            "survivor_cannot_open_pre_rotation_envelope",
        ),
        check(
            &rows,
            &removed,
            "opened_rotated",
            false,
            "removed_device_cannot_open_envelope_sealed_after_rotation",
        ),
        check(
            &rows,
            &removed,
            "opened_pre_rotation",
            true,
            "removed_device_keeps_pre_rotation_access",
        ),
    ];
    Ok(json!({
        "checks": checks,
        "name": name,
        "ok": checks.iter().all(|check| check.get("ok") == Some(&Value::Bool(true))),
        "rotations": rows,
        "type": "key_epoch",
    }))
}

fn device_match(row: &Value, devices: &[String]) -> bool {
    row.get("device")
        .and_then(Value::as_str)
        .is_some_and(|device| devices.iter().any(|want| want == device))
}

fn step_type(step: &Value) -> Result<String, FfiError> {
    let keys: Vec<String> = step
        .as_object()
        .ok_or_else(|| FfiError::input("each step must be an object"))?
        .keys()
        .cloned()
        .collect();
    if keys.len() == 1 {
        Ok(keys.into_iter().next().unwrap())
    } else {
        Err(FfiError::input("each step must be a one-key object"))
    }
}

fn object_field<'a>(spec: &'a Value, field: &str) -> Result<&'a Map<String, Value>, FfiError> {
    spec.get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| FfiError::input(format!("missing object {field}")))
}

fn array_field<'a>(spec: &'a Value, field: &str) -> Result<&'a Value, FfiError> {
    let value = spec
        .get(field)
        .ok_or_else(|| FfiError::input(format!("missing array {field}")))?;
    if !value.is_array() {
        return Err(FfiError::input(format!("field {field} must be an array")));
    }
    Ok(value)
}

fn array_entries<'a>(spec: &'a Value, field: &str) -> Result<&'a [Value], FfiError> {
    Ok(array_field(spec, field)?
        .as_array()
        .expect("array checked by array_field")
        .as_slice())
}

fn string_field(spec: &Value, field: &str) -> Result<String, FfiError> {
    string_value(
        spec.get(field)
            .ok_or_else(|| FfiError::input(format!("missing field {field}")))?,
    )
}

fn map_string_field(map: &Map<String, Value>, field: &str) -> Result<String, FfiError> {
    string_value(
        map.get(field)
            .ok_or_else(|| FfiError::input(format!("missing field {field}")))?,
    )
}

fn map_u64_field(map: &Map<String, Value>, field: &str) -> Result<u64, FfiError> {
    map.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| FfiError::input(format!("missing numeric field {field}")))
}

fn string_value(value: &Value) -> Result<String, FfiError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| FfiError::input("expected a string"))
}

fn strings(value: &Value) -> Result<Vec<String>, FfiError> {
    let mut out = Vec::new();
    for element in value
        .as_array()
        .ok_or_else(|| FfiError::input("expected an array"))?
    {
        out.push(string_value(element)?);
    }
    Ok(out)
}

fn u64_field(spec: &Value, field: &str) -> Result<u64, FfiError> {
    spec.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| FfiError::input(format!("missing numeric field {field}")))
}

fn decode(text: &str) -> Result<Vec<u8>, FfiError> {
    crate::handles::decode_b64url(text)
}
