//! The ciphertext relay storage interface (todo.md DSR-10).
//!
//! This trait is the whole contract between the server and its storage
//! engine. It accepts only:
//!
//! - one channel id (routing metadata), and
//! - a vector of `relay::Envelope` values (opaque ciphertext blobs plus
//!   their routing fields).
//!
//! It deliberately knows nothing else. The implementation must not decrypt,
//! merge, or interpret any field inside an envelope: grouping, device
//! identity and content are the client's business. A backend that needs any
//! of that is not a relay backend, it is a different product.
//!
//! `MemoryRelayStore` / `FileRelayStore` in `syncbond-core` are plaintext
//! *prototypes* for the core's own replication path; they are not acceptable
//! as the default network service's storage and are not wired into this
//! trait by design.
//!
//! Nothing in this crate constructs a backend yet: DSR-12..14 do. This
//! module is the reviewed interface contract, not dead code.
#![allow(dead_code)]

use std::fmt;
use syncbond_relay_protocol::dto::{Envelope, EnvelopeAck, PullEntry};
use syncbond_relay_protocol::error::RelayErrorCode;

/// Every storage failure carries the stable relay error code the server
/// must put on the wire. Storage never invents codes; the code/status/
/// retryability mapping lives in `relay-protocol` and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageError(RelayErrorCode);

impl StorageError {
    pub fn new(code: RelayErrorCode) -> Self {
        Self(code)
    }

    pub fn code(&self) -> RelayErrorCode {
        self.0
    }

    pub fn message(&self) -> String {
        self.0.as_str().to_string()
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "relay storage error: {}", self.0.as_str())
    }
}

impl std::error::Error for StorageError {}

/// One channel's append outcome: the sequence numbers assigned inside the
/// transaction that just committed, and whether each was a duplicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOutcome {
    pub acks: Vec<EnvelopeAck>,
}

/// One pull page. `entries` is contiguous and starts at `after + 1`; an
/// empty page means the cursor was already at the channel head.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullPage {
    pub entries: Vec<PullEntry>,
    pub has_more: bool,
}

/// Ciphertext-only relay storage. See the module docs for what a backend
/// may and may not look at.
pub trait RelayStorage: Send + Sync {
    /// The channel's highest committed sequence (0 for an empty channel).
    /// The server compares a pull cursor against this before reading.
    fn head(&self, channel: &str) -> Result<u64, StorageError>;

    /// Append envelopes to `channel`, assigning per-channel sequence
    /// numbers inside one transaction. Returns the ACK list on commit. A
    /// failure rolls the whole batch back (all-or-nothing).
    fn append(&self, channel: &str, envelopes: &[Envelope]) -> Result<AppendOutcome, StorageError>;

    /// Read the next page of `channel` starting after sequence `after`.
    /// `limit` caps the entry count and `max_bytes` the serialized page
    /// size; a single entry above the byte cap is an error, never an empty
    /// page (an empty page would loop forever on the client).
    fn pull(
        &self,
        channel: &str,
        after: u64,
        limit: u16,
        max_bytes: u64,
    ) -> Result<PullPage, StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncbond_relay_protocol::error::RelayError;

    #[test]
    fn storage_errors_carry_the_relay_code() {
        let error = StorageError::new(RelayErrorCode::IdempotencyConflict);
        assert_eq!(error.code(), RelayErrorCode::IdempotencyConflict);
        assert_eq!(error.code().http_status(), 409);
        assert!(!error.code().is_retryable());
        assert_eq!(
            error.to_string(),
            "relay storage error: idempotency_conflict"
        );
    }

    #[test]
    fn relay_error_wraps_into_storage_error() {
        let wrapped: RelayError = RelayError::new(
            RelayErrorCode::QuotaExceeded,
            "channel byte budget exhausted",
        );
        let error = StorageError::new(wrapped.code);
        assert!(error.code().is_retryable());
        assert_eq!(error.code().http_status(), 507);
    }
}
