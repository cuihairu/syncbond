//! Envelope security tests: tamper, replay, cross-group, wrong epoch,
//! revocation via key rotation, and the wrong-key case.

use std::collections::HashSet;
use syncbond_core::crypto::{open, seal, CryptoError, EncryptedEnvelope, EnvelopeContext, KeyRing};

const KEY: [u8; 32] = [7; 32];
const GROUP: &str = "group-abc";
const DEVICE: &str = "device-1";

fn open_with(key: &[u8; 32], env: &EncryptedEnvelope, epoch: u64) -> Result<Vec<u8>, CryptoError> {
    let mut seen = HashSet::new();
    open(
        key,
        env,
        &mut EnvelopeContext {
            group_id: GROUP,
            current_key_epoch: epoch,
            seen_message_ids: &mut seen,
        },
    )
}

#[test]
fn seal_open_roundtrip() {
    let env = seal(&KEY, GROUP, DEVICE, 1, b"payload bytes");
    assert_eq!(env.group_id, GROUP);
    assert_eq!(env.sender_device_id, DEVICE);
    assert_eq!(env.key_epoch, 1);
    let plain = open_with(&KEY, &env, 1).expect("roundtrip");
    assert_eq!(plain, b"payload bytes");
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let mut env = seal(&KEY, GROUP, DEVICE, 1, b"payload bytes");
    env.ciphertext[0] ^= 0x01;
    assert_eq!(
        open_with(&KEY, &env, 1),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn tampered_metadata_is_rejected_aad_binding() {
    // sender id, group id and message id are all AEAD-associated data.
    let mut env = seal(&KEY, GROUP, DEVICE, 1, b"payload bytes");
    env.sender_device_id = "impersonator".into();
    assert_eq!(
        open_with(&KEY, &env, 1),
        Err(CryptoError::AuthenticationFailed)
    );

    let mut env = seal(&KEY, GROUP, DEVICE, 1, b"payload bytes");
    env.message_id = "forged".into();
    assert_eq!(
        open_with(&KEY, &env, 1),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn cross_group_delivery_is_rejected() {
    let env = seal(&KEY, "other-group", DEVICE, 1, b"payload bytes");
    let mut seen = HashSet::new();
    let err = open(
        &KEY,
        &env,
        &mut EnvelopeContext {
            group_id: GROUP,
            current_key_epoch: 1,
            seen_message_ids: &mut seen,
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        CryptoError::CrossGroup {
            got: "other-group".into(),
            expected: GROUP.into()
        }
    );
}

#[test]
fn wrong_key_epoch_is_rejected() {
    let env = seal(&KEY, GROUP, DEVICE, 2, b"payload bytes");
    assert_eq!(
        open_with(&KEY, &env, 1),
        Err(CryptoError::KeyEpochMismatch {
            got: 2,
            expected: 1
        })
    );
}

#[test]
fn replayed_message_is_rejected() {
    let env = seal(&KEY, GROUP, DEVICE, 1, b"payload bytes");
    let mut seen = HashSet::new();
    open(
        &KEY,
        &env,
        &mut EnvelopeContext {
            group_id: GROUP,
            current_key_epoch: 1,
            seen_message_ids: &mut seen,
        },
    )
    .expect("first delivery");
    assert_eq!(
        open(
            &KEY,
            &env,
            &mut EnvelopeContext {
                group_id: GROUP,
                current_key_epoch: 1,
                seen_message_ids: &mut seen
            }
        ),
        Err(CryptoError::Replay(env.message_id.clone()))
    );
}

#[test]
fn unsupported_protocol_version_is_rejected() {
    let mut env = seal(&KEY, GROUP, DEVICE, 1, b"payload bytes");
    env.protocol_version = 99;
    assert_eq!(
        open_with(&KEY, &env, 1),
        Err(CryptoError::VersionMismatch {
            got: 99,
            expected: 1
        })
    );
}

#[test]
fn revoked_device_cannot_open_next_key_epoch() {
    let mut ring = KeyRing::new(GROUP);
    let old_epoch = ring.current_epoch();
    let old_key = *ring.current_key();

    // Device is revoked; the group rotates. The new key goes only to
    // surviving members.
    let (new_epoch, new_key) = ring.rotate();
    assert_eq!(new_epoch, old_epoch + 1);

    let env = seal(&new_key, GROUP, "survivor", new_epoch, b"post-revocation");
    // The revoked device still holds only the old epoch key.
    assert_eq!(
        open_with(&old_key, &env, old_epoch),
        Err(CryptoError::KeyEpochMismatch {
            got: new_epoch,
            expected: old_epoch
        })
    );
    // Even ignoring epoch checks, its old key cannot authenticate the new
    // epoch envelope: attempt with the old key AT the new epoch.
    assert_eq!(
        open_with(&old_key, &env, new_epoch),
        Err(CryptoError::AuthenticationFailed)
    );
    // A surviving member with the new key reads it fine.
    assert!(open_with(&new_key, &env, new_epoch).is_ok());
}

#[test]
fn wrong_key_fails_authentication() {
    let env = seal(&KEY, GROUP, DEVICE, 1, b"payload bytes");
    let wrong: [u8; 32] = [9; 32];
    assert_eq!(
        open_with(&wrong, &env, 1),
        Err(CryptoError::AuthenticationFailed)
    );
}
