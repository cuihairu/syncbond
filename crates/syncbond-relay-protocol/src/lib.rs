//! Shared wire contract for the default syncbond relay (v1), frozen in
//! docs/design/relay-protocol.md (todo.md DSR-07).
//!
//! This crate holds only what both the server (`apps/syncbond-server`) and
//! every client transport need to agree on: outer DTOs, stable error codes
//! and the size limits. It depends on nothing but serde — no application
//! server, no merge implementation, no async runtime. The end-to-end
//! `EncryptedEnvelope` stays opaque to this contract; the relay-side
//! [`dto::Envelope`] mirrors its frozen JSON shape (`schemas/envelope.schema.json`)
//! with base64 fields kept as text, because a relay never decodes them.
//!
//! JSON conventions: camelCase keys, unknown fields rejected (same
//! closed-shape policy as the envelope schema), `protocolVersion` must be
//! [`RELAY_PROTOCOL_VERSION`] and is validated explicitly via
//! [`check_version`] so a server can still echo the `requestId` in its
//! error body.

pub mod dto;
pub mod error;
pub mod limits;

pub use dto::{
    AppendAck, AppendRequest, ChannelCreated, CredentialIssued, CredentialRevoked, CredentialScope,
    Envelope, EnvelopeAck, IssueCredentialRequest, PullEntry, PullRequest, PullResponse,
    RoomCreated, WsClientMessage, WsServerMessage,
};
pub use error::{ErrorBody, ErrorDetail, RelayError, RelayErrorCode};
pub use limits::{check_batch, check_envelope, effective_pull_limits, BatchError, PullLimitsError};

/// The relay contract version. Independent of the end-to-end envelope
/// `protocolVersion` inside each envelope; hard-reject everything else
/// (no negotiation, per docs/design/PROTOCOL.md §3).
pub const RELAY_PROTOCOL_VERSION: u16 = 1;

/// Validate an outer `protocolVersion`. A mismatch is
/// [`RelayErrorCode::VersionUnsupported`]; callers echo `requestId` in the
/// resulting [`ErrorBody`].
pub fn check_version(protocol_version: u16) -> Result<(), RelayError> {
    if protocol_version == RELAY_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(RelayError::new(
            RelayErrorCode::VersionUnsupported,
            format!(
                "relay contract version {protocol_version} is not supported (expected {RELAY_PROTOCOL_VERSION})"
            ),
        ))
    }
}

/// Validate a client-chosen `requestId`: 1..=64 chars.
pub fn check_request_id(request_id: &str) -> Result<(), RelayError> {
    if request_id.is_empty() || request_id.len() > limits::MAX_REQUEST_ID_LEN {
        return Err(RelayError::new(
            RelayErrorCode::BadRequest,
            format!(
                "requestId must be 1..={} chars, got {}",
                limits::MAX_REQUEST_ID_LEN,
                request_id.len()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_passes_and_others_fail() {
        assert_eq!(check_version(RELAY_PROTOCOL_VERSION), Ok(()));
        let error = check_version(2).unwrap_err();
        assert_eq!(error.code, RelayErrorCode::VersionUnsupported);
        assert!(!error.is_retryable());
        assert_eq!(error.code.http_status(), 400);
    }

    #[test]
    fn request_id_bounds() {
        assert!(check_request_id("a").is_ok());
        assert!(check_request_id(&"x".repeat(64)).is_ok());
        assert!(check_request_id("").is_err());
        assert!(check_request_id(&"x".repeat(65)).is_err());
    }
}
