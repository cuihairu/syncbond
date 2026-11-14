//! The frozen v1 size limits and the validation helpers enforcing them
//! (docs/design/relay-protocol.md §9). A server MAY configure lower
//! values; nothing above these maxima is accepted.

use crate::dto::Envelope;
use crate::error::{RelayError, RelayErrorCode};

/// One serialized envelope, at most.
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
/// Envelopes per append request.
pub const MAX_BATCH_COUNT: usize = 16;
/// Total serialized envelope bytes per append request.
pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_PULL_LIMIT: u16 = 16;
pub const MAX_PULL_LIMIT: u16 = 64;
pub const DEFAULT_PULL_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_PULL_BYTES: u64 = 16 * 1024 * 1024;
/// Room constants; the capability is 128 bits of base64url.
pub const MAX_ROOM_PARTICIPANTS: usize = 2;
pub const ROOM_TTL_MS: u64 = 120_000;
pub const MAX_ROOM_JOIN_ATTEMPTS: usize = 16;
/// Parity with the core's `MAX_FRAME_BYTES`; the relay enforces it while
/// reading, before allocation.
pub const PAIRING_FRAME_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_REQUEST_ID_LEN: usize = 64;
pub const MAX_CHANNEL_ID_LEN: usize = 128;
/// The envelope schema pins `messageId` to 16..=64 chars; the relay enforces
/// the same bound because `(channel, messageId)` is its idempotency key.
pub const MESSAGE_ID_MIN_LEN: usize = 16;
pub const MESSAGE_ID_MAX_LEN: usize = 64;
/// Group and device ids carry the schema's 1..=128 bound.
pub const ID_MAX_LEN: usize = 128;

/// Batch-level append validation. Any failure rejects the whole batch:
/// partial batches never exist.
pub fn check_batch(envelopes: &[Envelope]) -> Result<(), BatchError> {
    if envelopes.is_empty() || envelopes.len() > MAX_BATCH_COUNT {
        return Err(BatchError::TooMany {
            got: envelopes.len(),
            max: MAX_BATCH_COUNT,
        });
    }
    let mut total = 0usize;
    for (index, envelope) in envelopes.iter().enumerate() {
        let serialized =
            serde_json::to_vec(envelope).map_err(|error| BatchError::Unserializable {
                index,
                reason: error.to_string(),
            })?;
        if serialized.len() > MAX_ENVELOPE_BYTES {
            return Err(BatchError::EnvelopeTooLarge {
                index,
                got: serialized.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        total += serialized.len();
        if total > MAX_BATCH_BYTES {
            return Err(BatchError::TooManyBytes {
                got: total,
                max: MAX_BATCH_BYTES,
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BatchError {
    #[error("batch holds {got} envelopes (limit {max})")]
    TooMany { got: usize, max: usize },
    #[error("envelope #{index} is {got} bytes (limit {max})")]
    EnvelopeTooLarge {
        index: usize,
        got: usize,
        max: usize,
    },
    #[error("batch totals {got} bytes (limit {max})")]
    TooManyBytes { got: usize, max: usize },
    #[error("envelope #{index} does not serialize: {reason}")]
    Unserializable { index: usize, reason: String },
}

impl BatchError {
    /// The stable relay error code this maps to on the wire.
    pub fn code(&self) -> RelayErrorCode {
        match self {
            Self::TooMany { .. } | Self::TooManyBytes { .. } => RelayErrorCode::BatchTooLarge,
            Self::EnvelopeTooLarge { .. } => RelayErrorCode::PayloadTooLarge,
            Self::Unserializable { .. } => RelayErrorCode::BadRequest,
        }
    }
}

/// Envelope-level checks the relay applies before storage: the schema's
/// field bounds (the schema itself stays the shape authority) plus the
/// serialized size cap.
pub fn check_envelope(envelope: &Envelope) -> Result<(), RelayError> {
    if !(MESSAGE_ID_MIN_LEN..=MESSAGE_ID_MAX_LEN).contains(&envelope.message_id.len()) {
        return Err(RelayError::new(
            RelayErrorCode::BadRequest,
            format!(
                "messageId must be {MESSAGE_ID_MIN_LEN}..={MESSAGE_ID_MAX_LEN} chars, got {}",
                envelope.message_id.len()
            ),
        ));
    }
    if envelope.group_id.is_empty() || envelope.group_id.len() > ID_MAX_LEN {
        return Err(RelayError::new(
            RelayErrorCode::BadRequest,
            "groupId must be 1..=128 chars",
        ));
    }
    if envelope.sender_device_id.is_empty() || envelope.sender_device_id.len() > ID_MAX_LEN {
        return Err(RelayError::new(
            RelayErrorCode::BadRequest,
            "senderDeviceId must be 1..=128 chars",
        ));
    }
    if envelope.key_epoch == 0 {
        return Err(RelayError::new(
            RelayErrorCode::BadRequest,
            "keyEpoch must be >= 1",
        ));
    }
    let serialized = serde_json::to_vec(envelope)
        .map_err(|error| RelayError::new(RelayErrorCode::BadRequest, error.to_string()))?;
    if serialized.len() > MAX_ENVELOPE_BYTES {
        return Err(RelayError::new(
            RelayErrorCode::PayloadTooLarge,
            format!(
                "envelope is {} bytes (limit {MAX_ENVELOPE_BYTES})",
                serialized.len()
            ),
        ));
    }
    Ok(())
}

/// Resolve a pull request's `limit`/`maxBytes` to their effective values:
/// `None` takes the frozen default, anything above the maximum is rejected.
pub fn effective_pull_limits(
    limit: Option<u16>,
    max_bytes: Option<u64>,
) -> Result<(u16, u64), PullLimitsError> {
    let limit = limit.unwrap_or(DEFAULT_PULL_LIMIT);
    if limit == 0 || limit > MAX_PULL_LIMIT {
        return Err(PullLimitsError::PageTooLarge {
            got: limit,
            max: MAX_PULL_LIMIT,
        });
    }
    let max_bytes = max_bytes.unwrap_or(DEFAULT_PULL_BYTES);
    if max_bytes == 0 || max_bytes > MAX_PULL_BYTES {
        return Err(PullLimitsError::BytesTooLarge {
            got: max_bytes,
            max: MAX_PULL_BYTES,
        });
    }
    Ok((limit, max_bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PullLimitsError {
    #[error("pull limit {got} exceeds the maximum of {max}")]
    PageTooLarge { got: u16, max: u16 },
    #[error("pull maxBytes {got} exceeds the maximum of {max}")]
    BytesTooLarge { got: u64, max: u64 },
}

impl PullLimitsError {
    pub fn code(&self) -> RelayErrorCode {
        match self {
            Self::PageTooLarge { .. } => RelayErrorCode::PageTooLarge,
            Self::BytesTooLarge { .. } => RelayErrorCode::PageTooLarge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope {
            protocol_version: 1,
            group_id: "g_ab12".to_string(),
            sender_device_id: "dev_phone".to_string(),
            key_epoch: 3,
            message_id: "m_0192f3e4d5c6b7a8".to_string(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
        }
    }

    #[test]
    fn batch_bounds() {
        assert!(check_batch(&[]).is_err(), "empty batch is rejected");
        assert!(check_batch(&(0..MAX_BATCH_COUNT).map(|_| envelope()).collect::<Vec<_>>()).is_ok());
        let too_many = (0..=MAX_BATCH_COUNT)
            .map(|_| envelope())
            .collect::<Vec<_>>();
        match check_batch(&too_many) {
            Err(BatchError::TooMany { got, max }) => {
                assert_eq!((got, max), (MAX_BATCH_COUNT + 1, MAX_BATCH_COUNT));
            }
            other => panic!("expected TooMany, got {other:?}"),
        }
    }

    #[test]
    fn oversized_envelope_is_payload_too_large() {
        let mut huge = envelope();
        huge.ciphertext = "A".repeat(MAX_ENVELOPE_BYTES);
        match check_batch(&[huge]) {
            Err(BatchError::EnvelopeTooLarge { index, max, .. }) => {
                assert_eq!((index, max), (0, MAX_ENVELOPE_BYTES));
            }
            other => panic!("expected EnvelopeTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn envelope_field_bounds() {
        assert!(check_envelope(&envelope()).is_ok());
        let mut short_id = envelope();
        short_id.message_id = "short".to_string();
        assert!(check_envelope(&short_id).is_err());
        let mut zero_epoch = envelope();
        zero_epoch.key_epoch = 0;
        assert!(check_envelope(&zero_epoch).is_err());
        let mut empty_group = envelope();
        empty_group.group_id = String::new();
        assert!(check_envelope(&empty_group).is_err());
    }

    #[test]
    fn pull_limit_resolution() {
        assert_eq!(effective_pull_limits(None, None), Ok((16, 4 * 1024 * 1024)));
        assert_eq!(
            effective_pull_limits(Some(64), Some(MAX_PULL_BYTES)),
            Ok((64, MAX_PULL_BYTES))
        );
        assert_eq!(
            effective_pull_limits(Some(65), None),
            Err(PullLimitsError::PageTooLarge { got: 65, max: 64 })
        );
        assert!(effective_pull_limits(None, Some(MAX_PULL_BYTES + 1)).is_err());
        assert!(effective_pull_limits(Some(0), None).is_err());
    }
}
