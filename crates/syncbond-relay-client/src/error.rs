//! Client-side failures. The relay's own failures arrive in the frozen
//! error shape (relay-protocol.md §6) and are kept as typed
//! [`RelayClientError::Relay`] values, so callers switch on the code,
//! never on prose.

use syncbond_relay_protocol::error::RelayErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum RelayClientError {
    #[error("io: {0}")]
    Io(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("the relay did not answer in time")]
    Timeout,
    #[error("contract violation: {0}")]
    Protocol(String),
    /// The relay answered with its frozen failure body: a refused
    /// credential, a bad request, an exhausted quota. `status` is the
    /// HTTP status that carried it.
    #[error("relay refused (status {status}): {message}")]
    Relay {
        code: RelayErrorCode,
        status: u16,
        message: String,
    },
}
