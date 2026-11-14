//! Outer relay DTOs. JSON conventions (frozen, docs/design/relay-protocol.md):
//! camelCase keys, unknown fields rejected, `protocolVersion` validated via
//! `check_version` after parsing so errors can still echo `requestId`.

use crate::error::RelayErrorCode;
use serde::{Deserialize, Serialize};

/// The relay-side view of an end-to-end encrypted envelope. Field-for-field
/// the frozen wire shape of `schemas/envelope.schema.json`; `nonce` and
/// `ciphertext` stay base64url text because a relay never decodes them.
/// Legacy snake_case emitters (pre-2026-11-14, see PROTOCOL.md §4) are
/// accepted through the same aliases `syncbond-core` accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    #[serde(alias = "protocol_version")]
    pub protocol_version: u16,
    #[serde(alias = "group_id")]
    pub group_id: String,
    #[serde(alias = "sender_device_id")]
    pub sender_device_id: String,
    #[serde(alias = "key_epoch")]
    pub key_epoch: u64,
    #[serde(alias = "message_id")]
    pub message_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub envelopes: Vec<Envelope>,
}

/// The commit ACK for one envelope: the monotonic per-channel sequence,
/// returned only after the transaction is durable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeAck {
    pub message_id: String,
    pub seq: u64,
    /// True when this retry hit the `(channel, messageId)` idempotency
    /// record; the seq is the originally committed one either way.
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendAck {
    pub protocol_version: u16,
    pub request_id: String,
    pub channel_id: String,
    pub acks: Vec<EnvelopeAck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullRequest {
    pub protocol_version: u16,
    pub request_id: String,
    /// The client's cursor: the last durably delivered `seq`.
    pub after: u64,
    pub limit: Option<u16>,
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullEntry {
    pub seq: u64,
    pub envelope: Envelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullResponse {
    pub protocol_version: u16,
    pub request_id: String,
    pub channel_id: String,
    /// Ordered by `seq` ascending and contiguous; an empty page preserves
    /// the input cursor in `next_cursor`.
    pub entries: Vec<PullEntry>,
    pub next_cursor: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelCreated {
    pub protocol_version: u16,
    pub request_id: String,
    pub channel_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialScope {
    Append,
    Pull,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueCredentialRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub scopes: Vec<CredentialScope>,
    pub label: Option<String>,
}

/// The token is shown exactly once; the server keeps only its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialIssued {
    pub protocol_version: u16,
    pub request_id: String,
    pub credential_id: String,
    pub token: String,
    pub scopes: Vec<CredentialScope>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRevoked {
    pub protocol_version: u16,
    pub request_id: String,
    pub revoked: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRoomRequest {
    pub protocol_version: u16,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoomCreated {
    pub protocol_version: u16,
    pub request_id: String,
    pub room_id: String,
    /// 128-bit fresh randomness (base64url), independent of the short code.
    pub capability: String,
    /// RFC 3339 timestamp; the room dies at this instant.
    pub expires_at: String,
}

/// Server-to-client WebSocket messages, internally tagged by `"type"`.
/// Pairing frames stay opaque (base64url bytes ≤ the pairing frame cap);
/// channel notifications are lossy hints, never authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsServerMessage {
    #[serde(rename = "room.joined", rename_all = "camelCase")]
    PairingRoomJoined {
        protocol_version: u16,
        room_id: String,
        /// Flips to true when the second participant connects; the message
        /// is not re-sent at that point.
        peer_joined: bool,
    },
    #[serde(rename = "pairing.frame", rename_all = "camelCase")]
    PairingFrame {
        protocol_version: u16,
        /// base64url of the raw pairing frame, forwarded verbatim.
        data: String,
    },
    #[serde(rename = "events.subscribed", rename_all = "camelCase")]
    EventsSubscribed {
        protocol_version: u16,
        channel_id: String,
    },
    #[serde(rename = "channel.appended", rename_all = "camelCase")]
    ChannelAppended {
        protocol_version: u16,
        channel_id: String,
        seq: u64,
    },
    #[serde(rename = "error", rename_all = "camelCase")]
    Error {
        protocol_version: u16,
        /// A subset of the HTTP codes (room/expiry/close-code reasons).
        code: RelayErrorCode,
        message: String,
    },
}

/// The pairing-room frame relay message, client-to-server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsClientMessage {
    #[serde(rename = "pairing.frame", rename_all = "camelCase")]
    PairingFrame {
        protocol_version: u16,
        /// base64url of the raw pairing frame; the relay forwards it to the
        /// other participant unchanged.
        data: String,
    },
}

pub use WsClientMessage::PairingFrame as ClientPairingFrame;
pub use WsServerMessage::PairingFrame as ServerPairingFrame;
pub use WsServerMessage::PairingRoomJoined;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_request_is_closed_and_camel_cased() {
        let request = AppendRequest {
            protocol_version: 1,
            request_id: "req_5f6e7d8c9b0a1f2e3d4c".to_string(),
            envelopes: vec![Envelope {
                protocol_version: 1,
                group_id: "g_ab12".to_string(),
                sender_device_id: "dev_phone".to_string(),
                key_epoch: 3,
                message_id: "m_0192f3e4d5c6b7a8".to_string(),
                nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
            }],
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["protocolVersion"], 1);
        assert_eq!(value["requestId"], "req_5f6e7d8c9b0a1f2e3d4c");
        assert_eq!(value["envelopes"][0]["messageId"], "m_0192f3e4d5c6b7a8");
        assert_eq!(value["envelopes"][0]["keyEpoch"], 3);
        let round_trip: AppendRequest = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, request);

        // Unknown fields are rejected, same closed-shape policy as the
        // envelope schema.
        let mut extra = serde_json::to_value(&request).unwrap();
        extra["ttl"] = 30.into();
        assert!(serde_json::from_value::<AppendRequest>(extra).is_err());
    }

    #[test]
    fn ws_messages_tag_by_type_and_round_trip() {
        let joined = PairingRoomJoined {
            protocol_version: 1,
            room_id: "rm_5a6b7c8d9e0f".to_string(),
            peer_joined: false,
        };
        let value = serde_json::to_value(&joined).unwrap();
        assert_eq!(value["type"], "room.joined");
        assert_eq!(value["roomId"], "rm_5a6b7c8d9e0f");
        assert_eq!(value["peerJoined"], false);
        let round_trip: WsServerMessage = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, joined);

        let frame = ClientPairingFrame {
            protocol_version: 1,
            data: "AAEC".to_string(),
        };
        let value = serde_json::to_value(&frame).unwrap();
        assert_eq!(value["type"], "pairing.frame");
        let round_trip: WsClientMessage = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, frame);
    }

    #[test]
    fn credential_scopes_are_lowercase() {
        assert_eq!(
            serde_json::to_value(CredentialScope::Append).unwrap(),
            "append"
        );
        assert_eq!(serde_json::to_value(CredentialScope::Pull).unwrap(), "pull");
    }
}
