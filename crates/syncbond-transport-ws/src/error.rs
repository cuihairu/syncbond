//! The transport's error surface. Clients match on the variant, not the
//! message: relay-side failures carry the frozen [`RelayErrorCode`], TLS
//! failures are their own kind so the validation policy is observable,
//! and pairing-protocol failures surface the core's typed error.

use syncbond_core::codes::CodeError;
use syncbond_core::pairing::PairingError;
use syncbond_relay_protocol::error::RelayErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum WsPairingError {
    /// A TLS handshake or certificate-validation failure. Only raised by
    /// the validation path: an `AcceptInvalid` connection whose TLS
    /// succeeds never reports this variant.
    #[error("tls: {0}")]
    Tls(String),
    /// Sockets and HTTP plumbing outside TLS: connect, read, write, and
    /// malformed HTTP responses.
    #[error("transport: {0}")]
    Io(String),
    /// The overall budget (`pairingTimeoutMs`) elapsed.
    #[error("pairing timed out")]
    Timeout,
    /// The relay refused something with a frozen error code (rate limit,
    /// bad version) on the HTTP surface.
    #[error("relay {} (http {status}): {message}", code.as_str())]
    Relay {
        code: RelayErrorCode,
        status: u16,
        message: String,
    },
    /// The room's socket closed with a frozen close code (§7: 4401
    /// capability invalid, 4404 not found, 4409 full, 4410 expired,
    /// 1001 gone/shutdown).
    #[error("room closed with code {0}")]
    RoomClosed(u16),
    /// The relay sent something that is not the §7 message shape.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The pairing exchange itself failed (wrong code, aborted peer,
    /// malformed frame) — the core's typed error, verbatim.
    #[error(transparent)]
    Core(#[from] PairingError),
    /// The code board refused (expired, consumed, locked) — only the host
    /// entry can raise this, and only where `accept_gated` would.
    #[error("pairing code: {0}")]
    Code(#[from] CodeError),
}
