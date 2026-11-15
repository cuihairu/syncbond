//! The relay server crate. The binary target (`src/main.rs`) owns its own
//! module tree; this library target exists so other crates can assemble
//! the exact same server, and — behind the `test-support` feature — boot
//! one in-process for integration tests. Nothing here is a stable public
//! API for embedders; the embeddable surface is `syncbond-core` and the
//! transport crates.

pub mod config;
pub mod http;
pub mod proxy;
pub mod rooms;
pub mod serve;
pub mod sqlite;
pub mod storage;
pub mod ws;

#[cfg(feature = "test-support")]
pub mod test_support;
