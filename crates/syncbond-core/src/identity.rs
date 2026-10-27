//! Long-term device identity (Ed25519).
//!
//! Devices keep one stable signing key. During pairing both sides exchange
//! the public key with a signature over the SPAKE2 transcript hash, binding
//! the identity to the authenticated channel.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum IdentityError {
    #[error("identity signature verification failed")]
    BadSignature,
    #[error("malformed identity key material")]
    BadKeyMaterial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    #[serde(with = "hex_bytes")]
    pub public_key: [u8; 32],
    #[serde(with = "hex_bytes64")]
    pub secret_key: [u8; 64],
}

/// Wire-safe subset of an identity (no secret material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub device_id: String,
    #[serde(with = "hex_bytes")]
    pub public_key: [u8; 32],
}

impl From<&DeviceIdentity> for PublicIdentity {
    fn from(identity: &DeviceIdentity) -> Self {
        Self {
            device_id: identity.device_id.clone(),
            public_key: identity.public_key,
        }
    }
}

impl PublicIdentity {
    fn verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        VerifyingKey::from_bytes(&self.public_key).map_err(|_| IdentityError::BadKeyMaterial)
    }

    /// Verify this identity's binding to a pairing session.
    ///
    /// Message: b"syncbond/identity/v1" || role || SHA-256(transcript).
    pub fn verify_transcript(
        &self,
        role: &str,
        transcript: &[u8],
        signature: &Signature,
    ) -> Result<(), IdentityError> {
        let vk = self.verifying_key()?;
        vk.verify(&identity_binding_message(role, transcript), signature)
            .map_err(|_| IdentityError::BadSignature)
    }
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        Self::from_signing_key(signing)
    }

    pub fn from_signing_key(signing: SigningKey) -> Self {
        let public_key = signing.verifying_key().to_bytes();
        Self {
            device_id: device_id_from_public_key(&public_key),
            public_key,
            secret_key: signing.to_keypair_bytes(),
        }
    }

    /// Rebuild an identity from its persisted 64-byte Ed25519 keypair.
    pub fn from_secret_key_bytes(secret_key: &[u8]) -> Result<Self, IdentityError> {
        let bytes: [u8; 64] = secret_key
            .try_into()
            .map_err(|_| IdentityError::BadKeyMaterial)?;
        let signing =
            SigningKey::from_keypair_bytes(&bytes).map_err(|_| IdentityError::BadKeyMaterial)?;
        Ok(Self::from_signing_key(signing))
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        VerifyingKey::from_bytes(&self.public_key).map_err(|_| IdentityError::BadKeyMaterial)
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let signing = SigningKey::from_keypair_bytes(&self.secret_key)
            .expect("identity secret key is valid by construction");
        signing.sign(message)
    }

    /// Verify a signature allegedly produced by this identity.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), IdentityError> {
        self.verifying_key().and_then(|vk| {
            vk.verify(message, signature)
                .map_err(|_| IdentityError::BadSignature)
        })
    }

    /// Sign this device's binding to a pairing session.
    ///
    /// Message: b"syncbond/identity/v1" || role || SHA-256(transcript).
    pub fn sign_transcript(&self, role: &str, transcript: &[u8]) -> Signature {
        self.sign(&identity_binding_message(role, transcript))
    }
}

fn identity_binding_message(role: &str, transcript: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + role.len() + 32);
    msg.extend_from_slice(b"syncbond/identity/v1");
    msg.extend_from_slice(role.as_bytes());
    msg.extend_from_slice(&Sha256::digest(transcript));
    msg
}

/// Deterministic device id: first 16 hex chars of SHA-256 over the public key.
pub fn device_id_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    crate::identity::hex(&digest)[..16].to_string()
}

/// Derive the sync group id for a set of member public keys (order-independent).
pub fn group_id_from_public_keys(keys: &[[u8; 32]]) -> String {
    let mut sorted: Vec<&[u8; 32]> = keys.iter().collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"syncbond/group/v1");
    for key in sorted {
        hasher.update(key);
    }
    let digest = hasher.finalize();
    crate::identity::hex(&digest)[..24].to_string()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) mod hex_bytes {
    use super::{hex, hex_fixed};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        hex_fixed::<32, D>(d)
    }
}

pub(crate) mod hex_bytes64 {
    use super::{hex, hex_fixed};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        hex_fixed::<64, D>(d)
    }
}

fn hex_fixed<'de, const N: usize, D: Deserializer<'de>>(d: D) -> Result<[u8; N], D::Error> {
    let text = <String as Deserialize>::deserialize(d)?;
    let bytes = base16(&text).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("bad key length"))
}

fn base16(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip_and_group_id() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        let sig = a.sign(b"hello");
        a.verify(b"hello", &sig).unwrap();
        b.verify(b"hello", &sig).unwrap_err();

        let gid1 = group_id_from_public_keys(&[a.public_key, b.public_key]);
        let gid2 = group_id_from_public_keys(&[b.public_key, a.public_key]);
        assert_eq!(gid1, gid2);
        assert_eq!(gid1.len(), 24);
    }
}
