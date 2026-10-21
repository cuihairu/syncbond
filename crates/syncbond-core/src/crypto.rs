//! E2EE envelope (XChaCha20-Poly1305) and per-group key epochs.
//!
//! All envelope metadata except the ciphertext is authenticated as AEAD
//! associated data. keyEpoch exists from version 1: rotating the group key
//! immediately locks out devices that only hold an older epoch key.
//!
//! Wire JSON shape: schemas/envelope.schema.json.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Wire protocol version. Bumped only on breaking protocol changes; see
/// docs/design/PROTOCOL.md for the negotiation rules.
pub const PROTOCOL_VERSION: u16 = 1;

pub type SessionKey = [u8; 32];
pub type Nonce = [u8; 24];

/// Encrypted envelope. Serialized to JSON for wire transport (bytes become
/// base64url); in memory the nonce and ciphertext stay raw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub protocol_version: u16,
    pub group_id: String,
    pub sender_device_id: String,
    pub key_epoch: u64,
    pub message_id: String,
    /// 24-byte XChaCha20 nonce.
    #[serde(with = "b64url_nonce")]
    pub nonce: Nonce,
    /// ciphertext || 16-byte Poly1305 tag.
    #[serde(with = "b64url_bytes")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum CryptoError {
    #[error("unsupported envelope protocol version {got} (expected {expected})")]
    VersionMismatch { got: u16, expected: u16 },
    #[error("envelope group {got} does not match session group {expected}")]
    CrossGroup { got: String, expected: String },
    #[error("envelope key epoch {got} does not match current epoch {expected}")]
    KeyEpochMismatch { got: u64, expected: u64 },
    #[error("replayed message id {0}")]
    Replay(String),
    #[error("envelope authentication failed (tampered or wrong key)")]
    AuthenticationFailed,
}

/// Stable associated data: every field except the ciphertext.
fn aad(envelope: &EncryptedEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&envelope.protocol_version.to_be_bytes());
    out.extend_from_slice(envelope.group_id.as_bytes());
    out.push(0);
    out.extend_from_slice(envelope.sender_device_id.as_bytes());
    out.push(0);
    out.extend_from_slice(&envelope.key_epoch.to_be_bytes());
    out.extend_from_slice(envelope.message_id.as_bytes());
    out
}

fn random_nonce() -> Nonce {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn random_message_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    crate::identity::hex(&bytes)
}

/// Seal a payload for a group. One fresh nonce and message id per call.
pub fn seal(
    key: &SessionKey,
    group_id: &str,
    sender_device_id: &str,
    key_epoch: u64,
    plaintext: &[u8],
) -> EncryptedEnvelope {
    let nonce = random_nonce();
    let cipher = XChaCha20Poly1305::new(key.into());
    let envelope = EncryptedEnvelope {
        protocol_version: PROTOCOL_VERSION,
        group_id: group_id.to_string(),
        sender_device_id: sender_device_id.to_string(),
        key_epoch,
        message_id: random_message_id(),
        nonce,
        ciphertext: Vec::new(),
    };
    let payload = Payload {
        msg: plaintext,
        aad: &aad(&envelope),
    };
    let sealed = cipher
        .encrypt(nonce.as_ref().into(), payload)
        .expect("XChaCha20Poly1305 seal is infallible");
    EncryptedEnvelope {
        ciphertext: sealed,
        ..envelope
    }
}

/// Receiving-side checks an open() call enforces.
pub struct EnvelopeContext<'a> {
    pub group_id: &'a str,
    pub current_key_epoch: u64,
    pub seen_message_ids: &'a mut HashSet<String>,
}

/// Open an envelope inside a session context. Rejects, in order:
/// protocol version mismatch, cross-group delivery, wrong key epoch,
/// replayed message id, and finally any AEAD authentication failure.
pub fn open(
    key: &SessionKey,
    envelope: &EncryptedEnvelope,
    ctx: &mut EnvelopeContext<'_>,
) -> Result<Vec<u8>, CryptoError> {
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(CryptoError::VersionMismatch {
            got: envelope.protocol_version,
            expected: PROTOCOL_VERSION,
        });
    }
    if envelope.group_id != ctx.group_id {
        return Err(CryptoError::CrossGroup {
            got: envelope.group_id.clone(),
            expected: ctx.group_id.to_string(),
        });
    }
    if envelope.key_epoch != ctx.current_key_epoch {
        return Err(CryptoError::KeyEpochMismatch {
            got: envelope.key_epoch,
            expected: ctx.current_key_epoch,
        });
    }
    if !ctx.seen_message_ids.insert(envelope.message_id.clone()) {
        return Err(CryptoError::Replay(envelope.message_id.clone()));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let payload = Payload {
        msg: &envelope.ciphertext,
        aad: &aad(envelope),
    };
    cipher
        .decrypt(envelope.nonce.as_ref().into(), payload)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Per-group key material with monotonic epochs.
///
/// `rotate()` mints the next epoch key. Distribution of the new key is the
/// application's job through the surviving members' channels — a revoked
/// device that only holds epoch N keys cannot read epoch N+1 envelopes.
pub struct KeyRing {
    pub group_id: String,
    current_epoch: u64,
    epochs: std::collections::BTreeMap<u64, SessionKey>,
}

impl KeyRing {
    pub fn new(group_id: impl Into<String>) -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self::with_epoch(group_id, 1, key)
    }

    pub fn with_epoch(group_id: impl Into<String>, epoch: u64, key: SessionKey) -> Self {
        Self {
            group_id: group_id.into(),
            current_epoch: epoch,
            epochs: std::collections::BTreeMap::from([(epoch, key)]),
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn current_key(&self) -> &SessionKey {
        &self.epochs[&self.current_epoch]
    }

    pub fn key_for(&self, epoch: u64) -> Option<&SessionKey> {
        self.epochs.get(&epoch)
    }

    /// Mint the next epoch key; returns it for distribution to members that
    /// remain authorized.
    pub fn rotate(&mut self) -> (u64, SessionKey) {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        self.current_epoch += 1;
        self.epochs.insert(self.current_epoch, key);
        (self.current_epoch, key)
    }
}

mod b64url_bytes {
    use super::{b64url_decode, b64url_encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64url_encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        b64url_decode(&text).map_err(serde::de::Error::custom)
    }
}

mod b64url_nonce {
    use super::{b64url_decode, b64url_encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 24], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64url_encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 24], D::Error> {
        let text = String::deserialize(d)?;
        let bytes = b64url_decode(&text).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("nonce must be 24 bytes"))
    }
}

pub fn b64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

pub fn b64url_decode(text: &str) -> Result<Vec<u8>, String> {
    let rev = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    };
    let input: Vec<u8> = text.bytes().collect();
    let rem = input.len() % 4;
    if !matches!(rem, 0 | 2 | 3) {
        return Err("invalid base64url length".into());
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    for chunk in input.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = rev(c).ok_or_else(|| format!("invalid base64url character {}", c as char))?;
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
    }
    if rem == 2 {
        out.truncate(out.len() - 2);
    } else if rem == 3 {
        out.truncate(out.len() - 1);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_roundtrip() {
        for len in 0..40usize {
            let mut data = vec![0u8; len];
            OsRng.fill_bytes(&mut data);
            let encoded = b64url_encode(&data);
            assert_eq!(b64url_decode(&encoded).unwrap(), data, "len={len}");
        }
    }
}
