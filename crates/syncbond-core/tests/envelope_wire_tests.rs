//! Envelope wire-format regressions (todo.md, DSR-08): the serialized JSON
//! matches the frozen schema exactly, legacy snake_case envelopes still
//! open, and unknown fields are rejected.

use serde_json::Value;
use std::collections::HashSet;
use syncbond_core::crypto::PROTOCOL_VERSION;
use syncbond_core::crypto::{open, seal, EncryptedEnvelope, EnvelopeContext, SessionKey};

const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/envelope.schema.json"
);

fn load_schema() -> Value {
    let raw = std::fs::read_to_string(SCHEMA_PATH)
        .expect("schemas/envelope.schema.json is part of the repository");
    serde_json::from_str(&raw).expect("the frozen schema is valid JSON")
}

fn key() -> SessionKey {
    [7u8; 32]
}

// The frozen schema is authoritative: a real serialized envelope — produced
// by the production seal path — passes it (additionalProperties: false
// included).
#[test]
fn serialized_envelope_passes_the_frozen_schema() {
    let envelope = seal(&key(), "group", "device-a", 1, b"payload");
    let value = serde_json::to_value(&envelope).unwrap();

    let validator = jsonschema::validator_for(&load_schema()).unwrap();
    validator.validate(&value).unwrap_or_else(|error| {
        panic!("a real envelope must pass the frozen schema: {error}");
    });
}

// The emitted keys are exactly the schema's camelCase field set: the legacy
// snake_case emitter shape is gone from the wire output.
#[test]
fn envelope_json_uses_the_schema_camel_case_keys() {
    let envelope = seal(&key(), "group", "device-a", 1, b"payload");
    let value = serde_json::to_value(&envelope).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut sorted = keys;
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        [
            "ciphertext",
            "groupId",
            "keyEpoch",
            "messageId",
            "nonce",
            "protocolVersion",
            "senderDeviceId"
        ],
        "emitters produce the schema shape only"
    );
    assert_eq!(value["protocolVersion"], PROTOCOL_VERSION as u64);
}

// Migration record: emitters built before 2026-11-14 serialized snake_case
// keys. Receivers accept that legacy shape (per-field aliases) and the
// envelope still opens — the AEAD associated data is computed from the
// field values, never from the JSON keys, so only the parser is affected.
#[test]
fn legacy_snake_case_envelope_still_opens() {
    let envelope = seal(&key(), "group", "device-a", 1, b"legacy payload");
    let camel = serde_json::to_value(&envelope).unwrap();

    let snake_keys = [
        ("protocolVersion", "protocol_version"),
        ("groupId", "group_id"),
        ("senderDeviceId", "sender_device_id"),
        ("keyEpoch", "key_epoch"),
        ("messageId", "message_id"),
    ];
    let mut legacy = serde_json::Map::new();
    for (field, value) in camel.as_object().unwrap() {
        let name = snake_keys
            .iter()
            .find(|(camel_name, _)| camel_name == field)
            .map_or(field.as_str(), |(_, snake_name)| *snake_name);
        legacy.insert(name.to_string(), value.clone());
    }

    let parsed: EncryptedEnvelope =
        serde_json::from_value(Value::Object(legacy)).expect("legacy shape must parse");
    assert_eq!(parsed, envelope, "the aliases round-trip the same envelope");

    let mut seen = HashSet::new();
    let mut ctx = EnvelopeContext {
        group_id: "group",
        current_key_epoch: 1,
        seen_message_ids: &mut seen,
    };
    let plaintext = open(&key(), &parsed, &mut ctx).unwrap();
    assert_eq!(plaintext, b"legacy payload");
}

// Unknown fields are rejected, mirroring the schema's
// `additionalProperties: false`.
#[test]
fn unknown_envelope_fields_are_rejected() {
    let envelope = seal(&key(), "group", "device-a", 1, b"payload");
    let mut value = serde_json::to_value(&envelope).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("extra".to_string(), Value::Bool(true));
    assert!(
        serde_json::from_value::<EncryptedEnvelope>(value).is_err(),
        "unknown fields must be rejected, not ignored"
    );
}

// Every schema-required field is a real serde requirement: dropping one
// fails the parse (the schema's `required` list and the struct agree).
#[test]
fn missing_envelope_fields_are_rejected() {
    let envelope = seal(&key(), "group", "device-a", 1, b"payload");
    let value = serde_json::to_value(&envelope).unwrap();
    for field in [
        "protocolVersion",
        "groupId",
        "senderDeviceId",
        "keyEpoch",
        "messageId",
        "nonce",
        "ciphertext",
    ] {
        let mut stripped = value.clone();
        stripped.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<EncryptedEnvelope>(stripped).is_err(),
            "missing {field} must be rejected"
        );
    }
}
