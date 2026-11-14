//! Contract fixtures (todo.md, DSR-09): every frozen wire example in
//! fixtures/ parses into the shared DTOs, the envelope fixture validates
//! against the frozen schema, a real core-sealed envelope rides the relay
//! shape unchanged, and mutated shapes are rejected.

use syncbond_relay_protocol::dto::{
    AppendAck, AppendRequest, Envelope, PullRequest, PullResponse, RoomCreated, WsServerMessage,
};
use syncbond_relay_protocol::error::{ErrorBody, RelayErrorCode};
use syncbond_relay_protocol::{check_batch, check_envelope, RELAY_PROTOCOL_VERSION};

const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/envelope.schema.json"
);

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../fixtures/", $name))
    };
}

fn parse<T: serde::de::DeserializeOwned>(raw: &str) -> T {
    serde_json::from_str(raw).unwrap_or_else(|error| panic!("fixture must parse: {error}"))
}

/// The canonical envelope fixture is the envelope-schema authority made
/// concrete: it passes the frozen schema and matches the core DTO field
/// for field (via a real round trip, see below).
#[test]
fn envelope_fixture_passes_the_frozen_schema() {
    let raw = fixture!("envelope.json");
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(SCHEMA_PATH).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    validator.validate(&value).unwrap_or_else(|error| {
        panic!("the envelope fixture must pass the frozen schema: {error}")
    });

    let envelope: Envelope = parse(raw);
    assert_eq!(envelope.protocol_version, RELAY_PROTOCOL_VERSION);
    assert_eq!(envelope.message_id, "m_0192f3e4d5c6b7a8");
    assert!(check_envelope(&envelope).is_ok());
    assert!(check_batch(&[envelope]).is_ok());
}

/// The legacy snake_case emitter shape (pre-2026-11-14, PROTOCOL.md §4
/// migration record) parses through the same aliases core accepts.
#[test]
fn legacy_snake_case_envelope_fixture_parses() {
    let envelope: Envelope = parse(fixture!("legacy_envelope_snake.json"));
    let canonical: Envelope = parse(fixture!("envelope.json"));
    assert_eq!(envelope, canonical, "only the key casing differs");
}

#[test]
fn append_fixtures_round_trip() {
    let request: AppendRequest = parse(fixture!("append_request.json"));
    assert_eq!(request.protocol_version, RELAY_PROTOCOL_VERSION);
    assert_eq!(request.request_id, "req_5f6e7d8c9b0a1f2e3d4c");
    assert_eq!(request.envelopes.len(), 1);
    assert!(check_batch(&request.envelopes).is_ok());

    let ack: AppendAck = parse(fixture!("append_ack.json"));
    assert_eq!(ack.channel_id, "ch_9f8e7d6c5b4a3f2e1d0c");
    assert_eq!(ack.acks.len(), 1);
    assert_eq!(ack.acks[0].seq, 42);
    assert!(!ack.acks[0].duplicate);
}

#[test]
fn pull_fixtures_round_trip() {
    let request: PullRequest = parse(fixture!("pull_request.json"));
    assert_eq!(request.after, 41);
    let (limit, max_bytes) =
        syncbond_relay_protocol::effective_pull_limits(request.limit, request.max_bytes).unwrap();
    assert_eq!((limit, max_bytes), (16, 4 * 1024 * 1024));

    let response: PullResponse = parse(fixture!("pull_response.json"));
    assert_eq!(response.entries.len(), 1);
    assert_eq!(response.entries[0].seq, 42);
    assert_eq!(response.next_cursor, 42);
    assert!(!response.has_more);
    // Contiguity as the contract defines it for a non-empty page.
    assert_eq!(response.entries[0].seq, request.after + 1);
}

#[test]
fn error_and_room_fixtures_round_trip() {
    let body: ErrorBody = parse(fixture!("error_conflict.json"));
    assert_eq!(body.error.code, RelayErrorCode::IdempotencyConflict);
    assert!(!body.error.retryable);
    assert_eq!(body.error.code.http_status(), 409);

    let room: RoomCreated = parse(fixture!("room_created.json"));
    assert_eq!(room.capability, "7JezN-xQt0Wm9cLpA2bV_w");
    assert_eq!(room.capability.len(), 22, "128 bits of base64url");
}

#[test]
fn ws_fixtures_parse_into_the_tagged_messages() {
    let joined: WsServerMessage = parse(fixture!("ws_room_joined.json"));
    match joined {
        WsServerMessage::PairingRoomJoined {
            room_id,
            peer_joined,
            ..
        } => {
            assert_eq!(room_id, "rm_5a6b7c8d9e0f");
            assert!(!peer_joined);
        }
        other => panic!("expected room.joined, got {other:?}"),
    }

    let frame: WsServerMessage = parse(fixture!("ws_pairing_frame.json"));
    match frame {
        WsServerMessage::PairingFrame { data, .. } => assert_eq!(data, "AAECAwQFBgcICQ"),
        other => panic!("expected pairing.frame, got {other:?}"),
    }

    let appended: WsServerMessage = parse(fixture!("ws_channel_appended.json"));
    match appended {
        WsServerMessage::ChannelAppended {
            channel_id, seq, ..
        } => {
            assert_eq!(channel_id, "ch_9f8e7d6c5b4a3f2e1d0c");
            assert_eq!(seq, 43);
        }
        other => panic!("expected channel.appended, got {other:?}"),
    }
}

/// A mutated fixture — an unknown field, the shape the contract rejects —
/// must fail the closed-shape parse.
#[test]
fn mutated_fixtures_are_rejected() {
    let mut extra: serde_json::Value =
        serde_json::from_str(fixture!("append_request.json")).unwrap();
    extra["ttl"] = 30.into();
    assert!(serde_json::from_value::<AppendRequest>(extra).is_err());

    let mut envelope_extra: serde_json::Value =
        serde_json::from_str(fixture!("envelope.json")).unwrap();
    envelope_extra["extra"] = true.into();
    assert!(serde_json::from_value::<Envelope>(envelope_extra).is_err());
}

/// Alignment with the end-to-end layer: a REAL envelope produced by
/// `syncbond-core`'s production seal path parses into the relay DTO
/// unchanged, passes the frozen schema and the relay's own checks, and
/// re-serializes to the identical JSON.
#[test]
fn real_core_envelope_rides_the_relay_shape_unchanged() {
    let mut key = [0u8; 32];
    key.iter_mut().for_each(|byte| *byte = 0x42);
    let sealed = syncbond_core::crypto::seal(&key, "g_ab12cd34", "dev_phone", 3, b"payload");

    let wire = serde_json::to_value(&sealed).unwrap();
    let relay_envelope: Envelope = serde_json::from_value(wire.clone())
        .expect("a real sealed envelope must parse as the relay Envelope");
    assert_eq!(relay_envelope.message_id, sealed.message_id);
    assert_eq!(relay_envelope.key_epoch, 3);

    // The relay form serializes to the same bytes as the core form: the
    // two DTOs agree on the wire shape.
    let relay_wire = serde_json::to_value(&relay_envelope).unwrap();
    assert_eq!(relay_wire, wire);

    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(SCHEMA_PATH).unwrap()).unwrap();
    jsonschema::validator_for(&schema)
        .unwrap()
        .validate(&relay_wire)
        .unwrap_or_else(|error| panic!("relay form must pass the frozen schema: {error}"));

    check_envelope(&relay_envelope).unwrap();
    check_batch(&[relay_envelope]).unwrap();
}
