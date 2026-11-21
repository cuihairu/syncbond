//! syncbond-relay-client: the HTTP client for the relay's channel
//! contract — channel provisioning, append, pull — and the bridge that
//! serves the core sync driver over it.
//!
//! The wire is exactly the frozen v1 shapes (syncbond-relay-protocol);
//! TLS validates by default and only a deliberate construction accepts
//! invalid certificates. The core stays network-free (DSR-11): this
//! crate is where the network touches the driver's seam.

pub mod adapter;
pub mod client;
pub mod error;
mod http;
mod tls;

pub use adapter::DriverTransport;
pub use client::{RelayClient, RelayLocation};
pub use error::RelayClientError;
pub use tls::TlsPolicy;
