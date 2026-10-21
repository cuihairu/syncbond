//! Pairing code issuance and the guess-limiting policy.
//!
//! Codes are 6 characters from a 30-symbol unambiguous alphabet (no 0/O/1/I/L)
//! ≈ 27.3 bits of entropy. Policy defaults: single use, 120 s TTL, at most 3
//! failed attempts per code window. See docs/design/PROTOCOL.md for the
//! online-guessing analysis.

use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::time::Instant;

/// Unambiguous alphabet: 30 symbols ≈ 4.907 bits per character.
pub const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
pub const CODE_LENGTH: usize = 6;
pub const DEFAULT_TTL_MS: u64 = 120_000;
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone)]
pub struct PairingPolicy {
    pub ttl_ms: u64,
    pub max_attempts: u32,
}

impl Default for PairingPolicy {
    fn default() -> Self {
        Self {
            ttl_ms: DEFAULT_TTL_MS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum CodeError {
    #[error("unknown pairing code")]
    Unknown,
    #[error("pairing code expired")]
    Expired,
    #[error("pairing code already used")]
    AlreadyUsed,
    #[error("too many failed attempts; code window locked")]
    TooManyAttempts,
    #[error("pairing code has wrong format")]
    BadFormat,
}

struct IssuedCode {
    expires_at: Instant,
    used: bool,
    failed_attempts: u32,
}

pub fn generate_code() -> String {
    let mut bytes = [0u8; CODE_LENGTH];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| CODE_ALPHABET[*b as usize % CODE_ALPHABET.len()] as char)
        .collect()
}

/// Issues and validates pairing codes on the accepting side.
pub struct PairingCodeBoard {
    policy: PairingPolicy,
    issued: HashMap<String, IssuedCode>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl PairingCodeBoard {
    pub fn new(policy: PairingPolicy) -> Self {
        Self {
            policy,
            issued: HashMap::new(),
            now: Box::new(Instant::now),
        }
    }

    pub fn with_clock(policy: PairingPolicy, now: Box<dyn Fn() -> Instant + Send + Sync>) -> Self {
        Self {
            policy,
            issued: HashMap::new(),
            now,
        }
    }

    /// Issue a fresh code.
    pub fn issue(&mut self) -> String {
        let code = generate_code();
        self.issued.insert(
            code.clone(),
            IssuedCode {
                expires_at: (self.now)() + std::time::Duration::from_millis(self.policy.ttl_ms),
                used: false,
                failed_attempts: 0,
            },
        );
        code
    }

    /// Validate format only (both sides can call this before any exchange).
    pub fn validate_format(code: &str) -> Result<(), CodeError> {
        if code.len() != CODE_LENGTH
            || !code
                .bytes()
                .all(|c| CODE_ALPHABET.contains(&c.to_ascii_uppercase()))
        {
            return Err(CodeError::BadFormat);
        }
        Ok(())
    }

    /// Consume a code for a successful pairing. Single use: a consumed code
    /// can never pair again.
    pub fn consume(&mut self, code: &str) -> Result<(), CodeError> {
        let now = (self.now)();
        let entry = self.issued.get_mut(code).ok_or(CodeError::Unknown)?;
        if entry.used {
            return Err(CodeError::AlreadyUsed);
        }
        if now > entry.expires_at {
            return Err(CodeError::Expired);
        }
        entry.used = true;
        Ok(())
    }

    /// Record a failed pairing attempt against the code; errors once the
    /// attempt limit for this code window is exhausted.
    pub fn register_failure(&mut self, code: &str) -> Result<(), CodeError> {
        let now = (self.now)();
        let entry = self.issued.get_mut(code).ok_or(CodeError::Unknown)?;
        if now > entry.expires_at {
            return Err(CodeError::Expired);
        }
        entry.failed_attempts += 1;
        if entry.failed_attempts > self.policy.max_attempts {
            Err(CodeError::TooManyAttempts)
        } else {
            Ok(())
        }
    }

    pub fn is_accepting(&self, code: &str) -> bool {
        match self.issued.get(code) {
            Some(entry) => !entry.used && (self.now)() <= entry.expires_at,
            None => false,
        }
    }
}
