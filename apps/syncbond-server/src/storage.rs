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
//! `SqliteRelayStore` in `sqlite.rs` implements this contract (DSR-12
//! onward); the HTTP layer that calls it arrives with DSR-19. Until then
//! most items are exercised by tests only, hence the `allow`.
#![allow(dead_code)]

use std::fmt;
use syncbond_relay_protocol::dto::{CredentialScope, Envelope, EnvelopeAck, PullEntry};
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

/// A freshly issued channel credential. The `token` is shown exactly
/// once — this call is the only moment it exists in the clear anywhere
/// on the server; afterwards only its SHA-256 digest is stored. The
/// manual [`fmt::Debug`] keeps that promise even if someone logs it.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    pub credential_id: String,
    pub token: String,
    pub scopes: Vec<CredentialScope>,
    pub label: Option<String>,
}

impl fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCredential")
            .field("credential_id", &self.credential_id)
            .field("token", &"[redacted]")
            .field("scopes", &self.scopes)
            .field("label", &self.label)
            .finish()
    }
}

/// One stored credential, as the admin list endpoint may show it. The
/// digest is included because the contract requires "digests and metadata
/// only" — and the token is never recoverable from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub credential_id: String,
    pub digest: String,
    pub scopes: Vec<CredentialScope>,
    pub label: Option<String>,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
}

/// What a revocation attempt actually changed on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The credential was active and is now refused.
    Revoked,
    /// It was already revoked: nothing new happened.
    AlreadyRevoked,
}

/// Ciphertext-only relay storage. See the module docs for what a backend
/// may and may not look at.
pub trait RelayStorage: Send + Sync {
    /// Create a channel and return its fresh server-assigned id. The
    /// admin-authorized HTTP route that calls this arrives with DSR-19.
    fn create_channel(&self) -> Result<String, StorageError>;

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

    /// Issue a credential for `channel` with `scopes` (relay-protocol.md
    /// §3.2). Only the token's digest is persisted; the token itself is
    /// returned here once and then gone.
    fn issue_credential(
        &self,
        channel: &str,
        scopes: &[CredentialScope],
        label: Option<&str>,
    ) -> Result<IssuedCredential, StorageError>;

    /// Check a presented token against the requested `(channel, scope)`.
    /// Unknown, empty, or revoked tokens are `Unauthorized`; a valid
    /// credential aimed at another channel, or lacking the requested
    /// scope, is `Forbidden` — relay-protocol.md §auth and §scope
    /// checks map those two cases to 401 and 403 respectively, and
    /// cross-channel access stays 403 rather than 404.
    fn authorize(
        &self,
        channel: &str,
        token: &str,
        scope: CredentialScope,
    ) -> Result<(), StorageError>;

    /// Revoke the named credential on `channel`. Revocation is a
    /// persisted flag, not a cache invalidation: it survives a restart,
    /// and every later [`RelayStorage::authorize`] call re-reads it, so
    /// an already-connected device is refused on its next request
    /// (relay-protocol.md §3.2 revocation semantics).
    fn revoke_credential(
        &self,
        channel: &str,
        credential_id: &str,
    ) -> Result<RevokeOutcome, StorageError>;

    /// List a channel's credentials as metadata. The wire contract asks for
    /// "digests and metadata only, never tokens" (relay-protocol.md §3.2),
    /// which this shape makes structural: there is no token field to
    /// accidentally fill in.
    fn list_credentials(&self, channel: &str) -> Result<Vec<CredentialRecord>, StorageError>;

    /// Whether the store can answer a trivial read *right now*. Liveness
    /// does not imply this: a process that has not yet finished opening
    /// its database is alive and not ready.
    fn ready(&self) -> bool;
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
