//! Member-set bound key rotation and distribution.
//!
//! A rotation is atomic in local state: it removes the named member, mints the
//! next group key, and distributes one source-signed message. The MAC proves
//! knowledge of the pre-rotation group key. Members apply only when identity,
//! epoch, signature, MAC, and target membership all agree.

use crate::crypto::{
    self, CryptoError, EncryptedEnvelope, EnvelopeContext, KeyRing, SessionKey, PROTOCOL_VERSION,
};
use crate::identity::{device_id_from_public_key, DeviceIdentity};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use thiserror::Error;

const MEMBER_KEY_INFO: &[u8] = b"syncbond/v1/member-rotation-key";

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum MemberCryptoError {
    #[error("unknown member {0}")]
    UnknownMember(String),
    #[error("cannot remove the final group member")]
    EmptyMembership,
    #[error("rotation must remove or preserve a member exactly once")]
    MembershipConflict,
    #[error("wrong group id {got} (expected {expected})")]
    CrossGroup { got: String, expected: String },
    #[error("rotation source identity {got} is not authorized")]
    UnauthorizedSource { got: String },
    #[error("rotation source public key does not match source device id")]
    SourceKeyMismatch { got: String },
    #[error("rotation signature verification failed")]
    InvalidSignature,
    #[error("rotation is not the next epoch (got {got}, expected {expected})")]
    EpochNotNext { got: u64, expected: u64 },
    #[error("rotation for {device} was previously applied")]
    RotationReplay { device: String },
    #[error("rotation identity {got} is not in target membership")]
    RotationTargetNotMember { got: String },
    #[error("rotation membership is invalid")]
    InvalidMembership,
    #[error("rotation distribution authentication failed")]
    AuthenticationFailed,
    #[error("rotation envelope: {0}")]
    Crypto(#[from] CryptoError),
    #[error("rotation encoding: {0}")]
    Encoding(String),
}

/// One removal-triggered epoch, distributed to the devices that remain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
    pub protocol_version: u16,
    pub group_id: String,
    pub removed_device_id: String,
    pub epoch: u64,
    pub key: SessionKey,
    /// Stable member set after removal; distinct device ids only.
    pub member_ids: BTreeSet<String>,
    pub source_device_id: String,
    #[serde(with = "crate::identity::hex_bytes")]
    pub source_public_key: [u8; 32],
    #[serde(with = "crate::identity::hex_bytes64")]
    pub signature: [u8; 64],
    #[serde(with = "hex_mac")]
    pub mac: [u8; 32],
}

/// Result handed to the caller for send to every member in `member_ids`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationResult {
    pub epoch: u64,
    pub key: SessionKey,
    pub distribution: Vec<u8>,
    pub removed_device_id: String,
    pub member_ids: Vec<String>,
}

pub struct MemberKeyRing {
    device_id: String,
    group_id: String,
    keyring: KeyRing,
    members: BTreeSet<String>,
    member_keys: BTreeMap<String, [u8; 32]>,
    applied_removals: BTreeSet<String>,
    seen_message_ids: BTreeSet<String>,
}

impl MemberKeyRing {
    pub fn new(
        group_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<Self, MemberCryptoError> {
        let group_id = non_empty(group_id.into())?;
        let device_id = non_empty(device_id.into())?;
        Ok(Self {
            members: BTreeSet::from([device_id.clone()]),
            member_keys: BTreeMap::new(),
            keyring: KeyRing::new(group_id.clone()),
            device_id,
            group_id,
            applied_removals: BTreeSet::new(),
            seen_message_ids: BTreeSet::new(),
        })
    }

    pub fn with_epoch(
        group_id: impl Into<String>,
        device_id: impl Into<String>,
        members: impl IntoIterator<Item = impl Into<String>>,
        member_keys: impl IntoIterator<Item = (impl Into<String>, [u8; 32])>,
        epoch: u64,
        key: SessionKey,
    ) -> Result<Self, MemberCryptoError> {
        let group_id = non_empty(group_id.into())?;
        let device_id = non_empty(device_id.into())?;
        let members = members
            .into_iter()
            .map(Into::<String>::into)
            .collect::<Vec<_>>();
        let member_set = members.iter().cloned().collect::<BTreeSet<_>>();
        let member_keys = member_keys
            .into_iter()
            .map(|(member_id, public_key)| (member_id.into(), public_key))
            .collect::<BTreeMap<_, _>>();
        if members.iter().any(String::is_empty) || member_set.len() != members.len() {
            return Err(MemberCryptoError::InvalidMembership);
        }
        if !member_set.contains(&device_id) {
            return Err(MemberCryptoError::InvalidMembership);
        }
        if member_keys.len() != member_set.len()
            || member_keys
                .keys()
                .any(|member_id| !member_set.contains(member_id))
        {
            return Err(MemberCryptoError::InvalidMembership);
        }
        for (member_id, public_key) in &member_keys {
            if device_id_from_public_key(public_key) != *member_id {
                return Err(MemberCryptoError::SourceKeyMismatch {
                    got: member_id.clone(),
                });
            }
        }
        Ok(Self {
            members: member_set,
            member_keys,
            keyring: KeyRing::with_epoch(group_id.clone(), epoch, key),
            device_id,
            group_id,
            applied_removals: BTreeSet::new(),
            seen_message_ids: BTreeSet::new(),
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn current_epoch(&self) -> u64 {
        self.keyring.current_epoch()
    }

    pub fn current_key(&self) -> &SessionKey {
        self.keyring.current_key()
    }

    pub fn member_ids(&self) -> Vec<&str> {
        self.members.iter().map(String::as_str).collect()
    }

    pub fn is_member(&self, device_id: &str) -> bool {
        self.members.contains(device_id)
    }

    /// Remove `removed_device_id`, rotate, and create one authenticated
    /// distribution message for every remaining member.
    pub fn rotate_for_removal(
        &mut self,
        removed_device_id: impl Into<String>,
        source_identity: &DeviceIdentity,
    ) -> Result<RotationResult, MemberCryptoError> {
        let removed_device_id = non_empty(removed_device_id.into())?;
        if removed_device_id == self.device_id {
            return Err(MemberCryptoError::MembershipConflict);
        }
        if source_identity.device_id != self.device_id
            || self.member_keys.get(&self.device_id).copied() != Some(source_identity.public_key)
        {
            return Err(MemberCryptoError::SourceKeyMismatch {
                got: source_identity.device_id.clone(),
            });
        }
        if !self.members.remove(&removed_device_id) {
            return Err(MemberCryptoError::UnknownMember(removed_device_id));
        }
        let member_ids = self.members.clone();
        let rotation = self.rotation(member_ids, removed_device_id, source_identity)?;
        Ok(self.install_local_rotation(rotation))
    }

    /// Seal an opaque payload under the current member-set epoch.
    pub fn seal(&self, plaintext: &[u8]) -> EncryptedEnvelope {
        crypto::seal(
            self.keyring.current_key(),
            &self.group_id,
            &self.device_id,
            self.keyring.current_epoch(),
            plaintext,
        )
    }

    /// Open a payload only when it belongs to the current member-set epoch.
    pub fn open(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>, MemberCryptoError> {
        let mut seen = self
            .seen_message_ids
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        crypto::open(
            self.keyring.current_key(),
            envelope,
            &mut EnvelopeContext {
                group_id: &self.group_id,
                current_key_epoch: self.keyring.current_epoch(),
                seen_message_ids: &mut seen,
            },
        )
        .map_err(MemberCryptoError::from)
    }

    /// Parse and verify one distribution message; no local state changes.
    pub fn verify_rotation(&self, distribution: &[u8]) -> Result<Rotation, MemberCryptoError> {
        let rotation: Rotation = serde_json::from_slice(distribution)
            .map_err(|error| MemberCryptoError::Encoding(error.to_string()))?;
        if rotation.protocol_version != PROTOCOL_VERSION {
            return Err(MemberCryptoError::EpochNotNext {
                got: u64::from(rotation.protocol_version),
                expected: u64::from(PROTOCOL_VERSION),
            });
        }
        if rotation.group_id != self.group_id {
            return Err(MemberCryptoError::CrossGroup {
                got: rotation.group_id,
                expected: self.group_id.clone(),
            });
        }
        if self.applied_removals.contains(&rotation.removed_device_id) {
            return Err(MemberCryptoError::RotationReplay {
                device: rotation.removed_device_id,
            });
        }
        if !self.members.contains(&rotation.source_device_id) {
            return Err(MemberCryptoError::UnauthorizedSource {
                got: rotation.source_device_id,
            });
        }
        if rotation.epoch != self.keyring.current_epoch() + 1 {
            return Err(MemberCryptoError::EpochNotNext {
                got: rotation.epoch,
                expected: self.keyring.current_epoch() + 1,
            });
        }
        let source_key = self
            .member_keys
            .get(&rotation.source_device_id)
            .ok_or_else(|| MemberCryptoError::UnauthorizedSource {
                got: rotation.source_device_id.clone(),
            })?;
        if *source_key != rotation.source_public_key {
            return Err(MemberCryptoError::SourceKeyMismatch {
                got: rotation.source_device_id,
            });
        }
        let verifying_key =
            VerifyingKey::from_bytes(&rotation.source_public_key).map_err(|_| {
                MemberCryptoError::SourceKeyMismatch {
                    got: rotation.source_device_id.clone(),
                }
            })?;
        verifying_key
            .verify(
                &rotation_bytes_pre_signature(&rotation),
                &Signature::from_bytes(&rotation.signature),
            )
            .map_err(|_| MemberCryptoError::InvalidSignature)?;
        if !rotation.member_ids.contains(&self.device_id) {
            return Err(MemberCryptoError::RotationTargetNotMember {
                got: self.device_id.clone(),
            });
        }
        if rotation.member_ids.contains(&rotation.removed_device_id)
            || rotation.member_ids.is_empty()
            || rotation.removed_device_id.is_empty()
        {
            return Err(MemberCryptoError::InvalidMembership);
        }
        verify_mac(&rotation, self.keyring.current_key())?;
        Ok(rotation)
    }

    /// Verify and atomically advance to the distributed member set and key.
    pub fn apply_rotation(&mut self, distribution: &[u8]) -> Result<(), MemberCryptoError> {
        let rotation = self.verify_rotation(distribution)?;
        self.keyring = KeyRing::with_epoch(self.group_id.clone(), rotation.epoch, rotation.key);
        self.members = rotation.member_ids;
        self.applied_removals.insert(rotation.removed_device_id);
        self.seen_message_ids
            .insert(epoch_message_id(rotation.epoch));
        Ok(())
    }

    fn rotation(
        &mut self,
        member_ids: BTreeSet<String>,
        removed_device_id: String,
        identity: &DeviceIdentity,
    ) -> Result<Rotation, MemberCryptoError> {
        let (epoch, key) = self.keyring.rotate();
        let mut rotation = Rotation {
            protocol_version: PROTOCOL_VERSION,
            group_id: self.group_id.clone(),
            removed_device_id,
            epoch,
            key,
            member_ids,
            source_device_id: self.device_id.clone(),
            source_public_key: identity.public_key,
            signature: [0; 64],
            mac: [0; 32],
        };
        rotation.signature = identity
            .sign(&rotation_bytes_pre_signature(&rotation))
            .to_bytes();
        rotation.mac = mac(
            &rotation,
            self.keyring.key_for(epoch - 1).expect("previous epoch"),
        );
        Ok(rotation)
    }

    fn install_local_rotation(&mut self, rotation: Rotation) -> RotationResult {
        self.applied_removals
            .insert(rotation.removed_device_id.clone());
        self.seen_message_ids
            .insert(epoch_message_id(rotation.epoch));
        let RotationResult {
            epoch,
            key,
            distribution,
            removed_device_id,
            member_ids,
        } = RotationResult {
            epoch: rotation.epoch,
            key: rotation.key,
            distribution: serde_json::to_vec(&rotation)
                .expect("rotation serialization is infallible"),
            removed_device_id: rotation.removed_device_id,
            member_ids: rotation.member_ids.iter().cloned().collect(),
        };
        RotationResult {
            epoch,
            key,
            distribution,
            removed_device_id,
            member_ids,
        }
    }
}

fn non_empty(value: String) -> Result<String, MemberCryptoError> {
    if value.is_empty() {
        Err(MemberCryptoError::InvalidMembership)
    } else {
        Ok(value)
    }
}

fn rotation_bytes(rotation: &Rotation) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&rotation.protocol_version.to_be_bytes());
    bytes.extend_from_slice(rotation.group_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(rotation.removed_device_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&rotation.epoch.to_be_bytes());
    bytes.extend_from_slice(&rotation.key);
    for member in &rotation.member_ids {
        bytes.extend_from_slice(member.as_bytes());
        bytes.push(0);
    }
    bytes.extend_from_slice(rotation.source_device_id.as_bytes());
    bytes.extend_from_slice(&rotation.source_public_key);
    bytes.extend_from_slice(&rotation.signature);
    bytes
}

fn rotation_bytes_pre_signature(rotation: &Rotation) -> Vec<u8> {
    let mut unsigned = rotation.clone();
    unsigned.signature = [0; 64];
    unsigned.mac = [0; 32];
    rotation_bytes(&unsigned)
}

fn mac(rotation: &Rotation, old_key: &SessionKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&rotation.epoch.to_be_bytes()), old_key);
    let mut mac = [0; 32];
    hk.expand(MEMBER_KEY_INFO, &mut mac)
        .expect("32 bytes is a valid HKDF length");
    let mut hasher = Sha256::new();
    hasher.update(mac);
    hasher.update(rotation_bytes(rotation));
    mac = hasher.finalize().into();
    mac
}

fn verify_mac(rotation: &Rotation, old_key: &SessionKey) -> Result<(), MemberCryptoError> {
    let candidate = mac(rotation, old_key);
    if constant_eq(&candidate, &rotation.mac) {
        Ok(())
    } else {
        Err(MemberCryptoError::AuthenticationFailed)
    }
}

fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn epoch_message_id(epoch: u64) -> String {
    format!("member-rotation/{epoch}")
}

mod hex_mac {
    use super::{hex, hex_to_bytes};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex_to_bytes(&text).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("mac must be 32 bytes"))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_to_bytes(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("invalid hex length".into());
    }
    (0..text.len() / 2)
        .map(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                .map_err(|_| format!("invalid hex byte at {index}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 0x0f, 0xff];
        assert_eq!(hex_to_bytes(&hex(&bytes)).unwrap().as_slice(), bytes);
    }
}
