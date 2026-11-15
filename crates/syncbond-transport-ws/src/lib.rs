//! WebSocket pairing transport (todo.md DSR-27): two devices pair through
//! a relay pairing room (relay-protocol.md §7) using the non-blocking
//! pairing driver ([`syncbond_core::pairing_driver`]), with the short code
//! never leaving the devices.
//!
//! The shape, device A (issues the code, joins the room first):
//!
//! ```ignore
//! let invite = create_invite(&options).await?;          // POST /v1/pairing/rooms
//! let session = pair_as_host(&options, &identity, &invite, |code| {
//!     // show the code out-of-band (QR, print) — the relay never sees it
//! }).await?;
//! ```
//!
//! Device B (types the code, scans the invite):
//!
//! ```ignore
//! let session = pair_as_joiner(&options, &identity, &code, &invite).await?;
//! ```
//!
//! Guarantees this crate owns:
//!
//! - **Identity injection**: both entries take an existing
//!   [`DeviceIdentity`]; nothing is generated for the caller.
//! - **Policy**: the host side runs the code board's settle discipline
//!   ([`syncbond_core::pairing::accept_gated`]'s shape, pumped async) —
//!   a completed pairing consumes the code, a wire-level failure burns
//!   one attempt, a transport error burns nothing.
//! - **TLS validation** ([`TlsPolicy`]): on by default against the
//!   webpki roots or a pinned private CA; `AcceptInvalid` is explicit
//!   opt-out, never the default.
//! - **Timeouts and cancellation**: every entry runs under
//!   `pairingTimeoutMs`; each connect step under `connectTimeoutMs`;
//!   dropping the future closes the socket, which ends the peer's side
//!   promptly.
//! - **Bounded bridge**: frames cross between the async WebSocket world
//!   and the blocking [`syncbond_core::transport::Transport`] the sync
//!   core speaks through [`WsTransport`] — a bounded queue in each
//!   direction, so a slow end backpressures the wire instead of buffering
//!   without limit.

mod bridge;
mod error;
mod options;
mod pair;
mod rest;
mod room_ws;
mod tls;

pub use error::WsPairingError;
pub use options::{Invite, TlsPolicy, WsPairingOptions};
pub use pair::{create_invite, pair_as_host, pair_as_joiner};
