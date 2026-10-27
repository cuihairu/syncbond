//! Acceptance: removing a member automatically rotates the group key and
//! carries the new key to remaining members; every removed device loses all
//! post-rotation envelopes, and distribution itself resists tampering, replay,
//! and forgery by the removed device.

use std::collections::HashSet;
use syncbond_core::crypto::{open, EnvelopeContext};
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::member_crypto::{MemberCryptoError, MemberKeyRing};

const KEY: [u8; 32] = [0x42; 32];
const GROUP: &str = "group-rotation";

fn identities() -> [DeviceIdentity; 3] {
    [
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
    ]
}

fn member_ids(identities: &[DeviceIdentity; 3]) -> Vec<&str> {
    identities
        .iter()
        .map(|identity| identity.device_id.as_str())
        .collect()
}

fn member_keys(identities: &[DeviceIdentity; 3]) -> Vec<(&str, [u8; 32])> {
    identities
        .iter()
        .map(|identity| (identity.device_id.as_str(), identity.public_key))
        .collect()
}

fn ring(device: &DeviceIdentity, identities: &[DeviceIdentity; 3]) -> MemberKeyRing {
    MemberKeyRing::with_epoch(
        GROUP,
        &device.device_id,
        member_ids(identities),
        member_keys(identities),
        1,
        KEY,
    )
    .expect("shared group state")
}

fn open_under(ring: &MemberKeyRing, envelope: &syncbond_core::EncryptedEnvelope) -> bool {
    let mut seen = HashSet::new();
    open(
        ring.current_key(),
        envelope,
        &mut EnvelopeContext {
            group_id: GROUP,
            current_key_epoch: ring.current_epoch(),
            seen_message_ids: &mut seen,
        },
    )
    .is_ok()
}

#[test]
fn member_removal_rotates_and_distributes_to_survivors_only() {
    let identities = identities();
    let mut leader = ring(&identities[0], &identities);
    let mut survivor = ring(&identities[1], &identities);
    let removed = ring(&identities[2], &identities);

    let result = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .expect("rotate");
    assert_eq!(result.epoch, 2);
    assert_eq!(result.removed_device_id, identities[2].device_id);
    let mut expected_survivors = vec![
        identities[0].device_id.clone(),
        identities[1].device_id.clone(),
    ];
    expected_survivors.sort();
    assert_eq!(result.member_ids, expected_survivors);
    assert_eq!(leader.current_epoch(), 2);
    assert!(!leader.is_member(&identities[2].device_id));

    survivor
        .apply_rotation(&result.distribution)
        .expect("survivor installs");
    assert_eq!(survivor.current_epoch(), result.epoch);
    assert_eq!(survivor.current_key(), &result.key);
    let expected_survivor_refs: Vec<&str> = expected_survivors.iter().map(String::as_str).collect();
    assert_eq!(survivor.member_ids(), expected_survivor_refs);

    let post_rotation = survivor.seal(b"after removal");
    assert!(open_under(&leader, &post_rotation));
    assert!(!open_under(&removed, &post_rotation));
}

#[test]
fn removed_device_cannot_open_any_post_rotation_envelope() {
    let identities = identities();
    let mut leader = ring(&identities[0], &identities);
    let mut survivor = ring(&identities[1], &identities);
    let removed = ring(&identities[2], &identities);
    let result = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .unwrap();
    survivor.apply_rotation(&result.distribution).unwrap();

    let first = survivor.seal(b"first after rotation");
    let second = leader.seal(b"second after rotation");
    for envelope in [first, second] {
        assert_eq!(envelope.key_epoch, 2);
        assert!(!open_under(&removed, &envelope));
        let mut seen = HashSet::new();
        assert_eq!(
            open(
                &KEY,
                &envelope,
                &mut EnvelopeContext {
                    group_id: GROUP,
                    current_key_epoch: 2,
                    seen_message_ids: &mut seen,
                },
            ),
            Err(syncbond_core::CryptoError::AuthenticationFailed),
            "the failure must be AEAD authentication, not only an epoch gate"
        );
    }
}

#[test]
fn pre_rotation_envelopes_cannot_open_after_rotation() {
    let identities = identities();
    let mut leader = ring(&identities[0], &identities);
    let mut survivor = ring(&identities[1], &identities);
    let old_envelope = survivor.seal(b"before removal");

    let result = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .unwrap();
    survivor.apply_rotation(&result.distribution).unwrap();

    assert!(!open_under(&survivor, &old_envelope));
    assert!(!open_under(&leader, &old_envelope));
}

#[test]
fn tampered_distribution_is_rejected_without_state_change() {
    let identities = identities();
    let mut leader = ring(&identities[0], &identities);
    let result = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .unwrap();
    let receiver = ring(&identities[1], &identities);

    let mut rotation: syncbond_core::member_crypto::Rotation =
        serde_json::from_slice(&result.distribution).expect("rotation parses");
    rotation.key[0] ^= 0x01;
    let error = receiver
        .verify_rotation(&serde_json::to_vec(&rotation).unwrap())
        .expect_err("tampered key must not verify");
    assert!(
        matches!(
            error,
            MemberCryptoError::AuthenticationFailed | MemberCryptoError::InvalidSignature
        ),
        "tampering must trip the MAC or source signature: {error:?}"
    );
    assert_eq!(receiver.current_epoch(), 1, "no state advances on failure");
}

#[test]
fn distribution_replay_is_rejected_after_install() {
    let identities = identities();
    let mut leader = ring(&identities[0], &identities);
    let mut receiver = ring(&identities[1], &identities);
    let distribution = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .unwrap()
        .distribution;

    receiver.apply_rotation(&distribution).expect("first apply");
    assert_eq!(
        receiver.apply_rotation(&distribution),
        Err(MemberCryptoError::RotationReplay {
            device: identities[2].device_id.clone()
        })
    );
    assert_eq!(receiver.current_epoch(), 2);
}

#[test]
fn out_of_order_and_wrong_group_rotations_are_rejected() {
    let identities = identities();
    let receiver = ring(&identities[1], &identities);
    let leader_rotation = leader_rotation(&identities);
    let mut stale = leader_rotation.clone();
    stale.epoch = 3;
    assert!(matches!(
        receiver.verify_rotation(&serde_json::to_vec(&stale).unwrap()),
        Err(MemberCryptoError::EpochNotNext {
            got: 3,
            expected: 2
        })
    ));

    let mut cross_group = leader_rotation;
    cross_group.group_id = "other-group".into();
    assert_eq!(
        receiver.verify_rotation(&serde_json::to_vec(&cross_group).unwrap()),
        Err(MemberCryptoError::CrossGroup {
            got: "other-group".into(),
            expected: GROUP.into()
        })
    );
}

#[test]
fn removed_device_cannot_forge_a_fresh_rotation() {
    let identities = identities();
    let mut leader = ring(&identities[0], &identities);
    let mut survivor = ring(&identities[1], &identities);
    let mut removed = ring(&identities[2], &identities);
    let distribution = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .unwrap()
        .distribution;
    survivor.apply_rotation(&distribution).unwrap();

    // The removed device still holds the pre-rotation key and its own signing
    // key. Its stale ring can mint a plausible rotation, but a survivor already
    // applied the real one and must reject the stale source outright.
    let forged = removed
        .rotate_for_removal(identities[1].device_id.clone(), &identities[2])
        .expect("stale ring can still rotate locally");
    let error = survivor
        .verify_rotation(&forged.distribution)
        .expect_err("forged rotation by a removed device must be rejected");
    assert!(matches!(
        error,
        MemberCryptoError::UnauthorizedSource { .. }
            | MemberCryptoError::RotationReplay { .. }
            | MemberCryptoError::EpochNotNext { .. }
    ));
}

#[test]
fn removed_device_cannot_impersonate_the_source() {
    let identities = identities();
    let mut leader = ring(&identities[0], &identities);
    let survivor = ring(&identities[1], &identities);
    let distribution = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .unwrap()
        .distribution;
    let mut forged: syncbond_core::member_crypto::Rotation =
        serde_json::from_slice(&distribution).unwrap();
    forged.source_device_id = identities[2].device_id.clone();
    forged.source_public_key = identities[2].public_key;
    let error = survivor
        .verify_rotation(&serde_json::to_vec(&forged).unwrap())
        .expect_err("a removed device must not impersonate the source identity");
    assert_eq!(
        error,
        MemberCryptoError::InvalidSignature,
        "replacing the source identity must invalidate the Ed25519 signature"
    );
}

fn leader_rotation(identities: &[DeviceIdentity; 3]) -> syncbond_core::member_crypto::Rotation {
    let mut leader = ring(&identities[0], identities);
    let result = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .expect("leader rotation");
    assert_eq!(result.epoch, 2);
    serde_json::from_slice(&result.distribution).expect("rotation parses")
}
