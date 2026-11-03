//! Pairing code issuance and the guess-limiting policy.
//!
//! Codes are 6 characters from a 31-symbol unambiguous alphabet (no 0/O/1/I/L)
//! ≈ 30.7 bits of entropy (31^6). Policy defaults: single use, 120 s TTL, at most 3
//! failed attempts per code window. See docs/design/PROTOCOL.md for the
//! online-guessing analysis.

use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::time::Instant;

/// Unambiguous alphabet: 31 symbols ≈ 4.954 bits per character.
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
    // Rejection sampling to avoid modulo bias: 256 % 31 != 0, so a plain
    // `% 31` would give the first 8 symbols a slightly higher probability.
    // Drop bytes >= 248 (the largest multiple of 31 below 256) and retry,
    // leaving each of the 31 symbols exactly 1/31.
    let mut out = String::with_capacity(CODE_LENGTH);
    while out.len() < CODE_LENGTH {
        let mut byte = [0u8; 1];
        OsRng.fill_bytes(&mut byte);
        let b = byte[0];
        if b < 248 {
            out.push(CODE_ALPHABET[b as usize % CODE_ALPHABET.len()] as char);
        }
    }
    out
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
        // `validate_format` accepts lower-case letters, so normalize here too:
        // a lower-case entry of a valid code must match the stored upper-case
        // key instead of failing as Unknown.
        let entry = self
            .issued
            .get_mut(&code.to_ascii_uppercase())
            .ok_or(CodeError::Unknown)?;
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
        let entry = self
            .issued
            .get_mut(&code.to_ascii_uppercase())
            .ok_or(CodeError::Unknown)?;
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
        match self.issued.get(&code.to_ascii_uppercase()) {
            Some(entry) => !entry.used && (self.now)() <= entry.expires_at,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The rejection threshold must be an exact multiple of the alphabet size,
    /// otherwise the modulo bias the sampler is meant to remove persists.
    #[test]
    fn rejection_threshold_is_multiple_of_alphabet() {
        // 256 % 31 != 0, so any threshold below 256 must be a multiple of 31
        // to keep every symbol equally likely.
        assert_eq!(248 % CODE_ALPHABET.len(), 0);
        assert!(256 % CODE_ALPHABET.len() != 0);
    }

    /// The alphabet must contain no ambiguous characters (no 0/O/1/I/L).
    #[test]
    fn alphabet_is_unambiguous_and_31_symbols() {
        assert_eq!(CODE_ALPHABET.len(), 31);
        for &c in CODE_ALPHABET {
            assert!(
                !matches!(c, b'0' | b'O' | b'1' | b'I' | b'L'),
                "ambiguous {c}"
            );
        }
        // No duplicates.
        let mut seen = HashMap::new();
        for &c in CODE_ALPHABET {
            assert!(seen.insert(c, ()).is_none(), "duplicate {c}");
        }
    }
}
