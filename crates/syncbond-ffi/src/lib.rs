//! syncbond-ffi: the stable C ABI over syncbond-core.
//!
//! All protocol logic lives in syncbond-core. This crate is a thin,
//! handle-based translation layer: opaque handles, byte buffers and owned
//! strings. `include/syncbond.h` is the contract, and
//! `SYNCBOND_ABI_VERSION` bumps whenever a semantic change lands there.

pub mod abi;
pub mod error;
pub mod handles;
pub mod scenario;

/// ABI revision advertised by `sb_abi_version()`.
pub const SYNCBOND_ABI_VERSION: u32 = 1;

/// Opaque C handle aliases; their fields stay private.
#[allow(non_camel_case_types)]
pub type sb_identity = handles::Identity;
#[allow(non_camel_case_types)]
pub type sb_pair_result = handles::PairResult;
#[allow(non_camel_case_types)]
pub type sb_session = handles::Session;
#[allow(non_camel_case_types)]
pub type sb_replicator = handles::Replicator;
#[allow(non_camel_case_types)]
pub type sb_keyring = handles::Keyring;
