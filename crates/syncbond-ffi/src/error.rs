//! Error codes and the thread-local last-error slot shared by the ABI.

use syncbond_core::crypto::CryptoError;

pub const SB_ERR_NONE: i32 = 0;
pub const SB_ERR_PROTOCOL: i32 = -1;
pub const SB_ERR_INPUT: i32 = -2;
pub const SB_ERR_VERSION_MISMATCH: i32 = -3;
pub const SB_ERR_CROSS_GROUP: i32 = -4;
pub const SB_ERR_KEY_EPOCH_MISMATCH: i32 = -5;
pub const SB_ERR_REPLAY: i32 = -6;
pub const SB_ERR_AUTH_FAILED: i32 = -7;
pub const SB_ERR_INTERNAL: i32 = -8;
pub const SB_RESULT_ABSENT: i32 = 1;

pub const SB_STRATEGY_LWW_HLC: u32 = 0;
pub const SB_STRATEGY_OR_SET: u32 = 1;
pub const SB_STRATEGY_PN_COUNTER: u32 = 2;

/// A failure with a stable code (see syncbond.h) and a human-readable text.
#[derive(Debug, Clone)]
pub struct FfiError {
    pub code: i32,
    pub message: String,
}

impl FfiError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(SB_ERR_PROTOCOL, message)
    }

    pub fn input(message: impl Into<String>) -> Self {
        Self::new(SB_ERR_INPUT, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(SB_ERR_INTERNAL, message)
    }

    /// Stable code mapping for envelope failures.
    pub fn crypto(error: &CryptoError) -> Self {
        let (code, message) = match error {
            CryptoError::VersionMismatch { .. } => (SB_ERR_VERSION_MISMATCH, error.to_string()),
            CryptoError::CrossGroup { .. } => (SB_ERR_CROSS_GROUP, error.to_string()),
            CryptoError::KeyEpochMismatch { .. } => (SB_ERR_KEY_EPOCH_MISMATCH, error.to_string()),
            CryptoError::Replay(_) => (SB_ERR_REPLAY, error.to_string()),
            CryptoError::AuthenticationFailed => (SB_ERR_AUTH_FAILED, error.to_string()),
        };
        Self { code, message }
    }
}

impl From<syncbond_core::pairing::PairingError> for FfiError {
    fn from(error: syncbond_core::pairing::PairingError) -> Self {
        match error {
            syncbond_core::pairing::PairingError::Crypto(crypto) => Self::crypto(&crypto),
            other => Self::protocol(other.to_string()),
        }
    }
}

impl From<syncbond_core::replication::ReplicationError> for FfiError {
    fn from(error: syncbond_core::replication::ReplicationError) -> Self {
        match error {
            syncbond_core::replication::ReplicationError::Crypto(crypto) => Self::crypto(&crypto),
            other => Self::protocol(other.to_string()),
        }
    }
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    static LAST_CODE: std::cell::Cell<i32> = const { std::cell::Cell::new(SB_ERR_NONE) };
}

/// Record the failure for the calling thread; `None` clears it.
pub fn set_last_error(error: Option<FfiError>) {
    let code = error
        .as_ref()
        .map(|error| error.code)
        .unwrap_or(SB_ERR_NONE);
    LAST_ERROR.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.clear();
        if let Some(error) = error {
            slot.extend_from_slice(error.message.as_bytes());
            slot.push(0);
        }
    });
    LAST_CODE.set(code);
}

/// The `SB_ERR_*` code of the thread-local failure.
pub fn last_error_code() -> i32 {
    LAST_CODE.get()
}

/// Pointer into the thread-local buffer; valid until the next call on this
/// thread (the header documents this).
pub fn last_error_ptr() -> *const std::ffi::c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr() as *const std::ffi::c_char)
}
