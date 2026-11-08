//! Extra coverage for member-set rotation: constructor validation, accessors,
//! error branches in `verify_rotation`/`apply_rotation`, and encoding edge
//! cases not exercised by the rotation happy path.

use syncbond_core::identity::DeviceIdentity;
use syncbond_core::member_crypto::{MemberCryptoError, MemberKeyRing};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn identities() -> [DeviceIdentity; 3] {
    [
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
    ]
}

fn ring(id: &DeviceIdentity, members: &[DeviceIdentity]) -> MemberKeyRing {
    MemberKeyRing::with_epoch(
        "group",
        &id.device_id,
        members.iter().map(|m| m.device_id.clone()),
        members.iter().map(|m| (m.device_id.clone(), m.public_key)),
        1,
        [0x42; 32],
    )
    .unwrap()
}

fn valid_distribution(leader: &DeviceIdentity, all: &[DeviceIdentity]) -> Vec<u8> {
    let mut leader_ring = ring(leader, all);
    leader_ring
        .rotate_for_removal(all[2].device_id.clone(), leader)
        .unwrap()
        .distribution
}

#[test]
fn constructor_rejects_empty_and_duplicate_membership() {
    let ids = identities();
    assert!(matches!(
        MemberKeyRing::new("", &ids[0].device_id),
        Err(MemberCryptoError::InvalidMembership)
    ));
    assert!(matches!(
        MemberKeyRing::new("group", ""),
        Err(MemberCryptoError::InvalidMembership)
    ));
    assert!(matches!(
        MemberKeyRing::with_epoch(
            "group",
            &ids[0].device_id,
            std::iter::empty::<&str>(),
            std::iter::empty::<(&str, [u8; 32])>(),
            1,
            [0; 32],
        ),
        Err(MemberCryptoError::InvalidMembership)
    ));
    assert!(matches!(
        MemberKeyRing::with_epoch(
            "group",
            "stranger",
            ids.iter().map(|i| i.device_id.clone()),
            ids.iter().map(|i| (i.device_id.clone(), i.public_key)),
            1,
            [0; 32]
        ),
        Err(MemberCryptoError::InvalidMembership)
    ));
    // Duplicate membership must be rejected by the distinct-count check.
    assert!(matches!(
        MemberKeyRing::with_epoch(
            "group",
            &ids[0].device_id,
            [ids[0].device_id.clone(), ids[0].device_id.clone()],
            [(ids[0].device_id.clone(), ids[0].public_key)],
            1,
            [0; 32],
        ),
        Err(MemberCryptoError::InvalidMembership)
    ));
}

#[test]
fn constructor_rejects_mismatched_member_key() {
    let ids = identities();
    let wrong = [0u8; 32];
    let bad = MemberKeyRing::with_epoch(
        "group",
        &ids[0].device_id,
        ids.iter().map(|i| i.device_id.clone()),
        ids.iter().enumerate().map(|(index, i)| {
            if index == 0 {
                (i.device_id.clone(), wrong)
            } else {
                (i.device_id.clone(), i.public_key)
            }
        }),
        1,
        [0; 32],
    );
    assert!(bad.is_err());
}

#[test]
fn accessors_report_current_member_set() {
    let ids = identities();
    let ring = ring(&ids[0], &ids);
    assert_eq!(ring.group_id(), "group");
    assert_eq!(ring.device_id(), ids[0].device_id);
    assert_eq!(ring.current_epoch(), 1);
    assert_eq!(ring.current_key().as_ref(), &[0x42u8; 32]);
    assert_eq!(ring.member_ids().len(), 3);
    assert!(ring.member_ids().contains(&ids[0].device_id.as_str()));
    assert!(ring.member_ids().contains(&ids[1].device_id.as_str()));
    assert!(ring.member_ids().contains(&ids[2].device_id.as_str()));
    assert!(ring.is_member(&ids[1].device_id));
    assert!(!ring.is_member("stranger"));
}

#[test]
fn rotation_rejects_bad_source_and_unknown_member() {
    let ids = identities();
    let mut ring = ring(&ids[0], &ids);
    assert!(matches!(
        ring.rotate_for_removal("", &ids[0]),
        Err(MemberCryptoError::InvalidMembership)
    ));
    assert!(matches!(
        ring.rotate_for_removal(ids[0].device_id.clone(), &ids[0]),
        Err(MemberCryptoError::MembershipConflict)
    ));
    assert!(matches!(
        ring.rotate_for_removal(ids[1].device_id.clone(), &ids[1]),
        Err(MemberCryptoError::SourceKeyMismatch { .. })
    ));
    assert!(matches!(
        ring.rotate_for_removal("ghost".to_string(), &ids[0]),
        Err(MemberCryptoError::UnknownMember(member)) if member == "ghost"
    ));
}

#[test]
fn verify_rejects_wrong_group_and_bad_encoding() {
    let ids = identities();
    let ring = ring(&ids[0], &ids);
    assert!(matches!(
        ring.verify_rotation(b"{bad"),
        Err(MemberCryptoError::Encoding(_))
    ));
    // A valid distribution from a different group must be a cross-group error.
    let mut other = MemberKeyRing::with_epoch(
        "other",
        &ids[0].device_id,
        ids.iter().map(|i| i.device_id.clone()),
        ids.iter().map(|i| (i.device_id.clone(), i.public_key)),
        1,
        [0x42; 32],
    )
    .unwrap();
    let other_dist = other
        .rotate_for_removal(ids[2].device_id.clone(), &ids[0])
        .unwrap()
        .distribution;
    assert!(matches!(
        ring.verify_rotation(&other_dist),
        Err(MemberCryptoError::CrossGroup { .. })
    ));
}

#[test]
fn apply_rotation_rejects_replay_and_unknown_epoch() {
    let ids = identities();
    let mut ring = ring(&ids[0], &ids);
    let dist = valid_distribution(&ids[0], &ids);
    ring.apply_rotation(&dist).unwrap();
    assert_eq!(ring.current_epoch(), 2);
    assert!(matches!(
        ring.apply_rotation(&dist),
        Err(MemberCryptoError::RotationReplay { .. })
    ));
}

#[test]
fn new_starts_a_solo_ring_and_ghost_key_map_is_rejected() {
    let solo = MemberKeyRing::new("group", "solo-device").unwrap();
    assert_eq!(solo.device_id(), "solo-device");
    assert_eq!(solo.group_id(), "group");
    assert_eq!(solo.current_epoch(), 1);
    assert_eq!(solo.member_ids(), vec!["solo-device"]);
    assert!(solo.is_member("solo-device"));

    // Two members, two keys — but one key is registered under a foreign id,
    // so the id/key binding count check must reject the whole ring.
    let ids = identities();
    assert!(matches!(
        MemberKeyRing::with_epoch(
            "group",
            &ids[0].device_id,
            [ids[0].device_id.clone(), ids[1].device_id.clone()],
            [
                (ids[0].device_id.clone(), ids[0].public_key),
                ("ghost".to_string(), ids[1].public_key),
            ],
            1,
            [0x42; 32],
        ),
        Err(MemberCryptoError::InvalidMembership)
    ));
}

#[test]
fn wrong_protocol_version_is_rejected_before_anything_else() {
    let ids = identities();
    let ring = ring(&ids[0], &ids);
    let zeros: Vec<u8> = vec![0; 32];
    let rotation = serde_json::json!({
        "protocol_version": 99u16,
        "group_id": "group",
        "removed_device_id": ids[2].device_id,
        "epoch": 2u64,
        "key": zeros,
        "member_ids": [ids[0].device_id, ids[1].device_id],
        "source_device_id": ids[0].device_id,
        "source_public_key": hex(&ids[0].public_key),
        "signature": "00".repeat(64),
        "mac": "00".repeat(32),
    });
    assert!(matches!(
        ring.verify_rotation(rotation.to_string().as_bytes()),
        Err(MemberCryptoError::EpochNotNext {
            got: 99,
            expected: 1
        })
    ));
}

#[test]
fn key_substitution_is_detected_as_source_key_mismatch() {
    let ids = identities();
    let ring = ring(&ids[0], &ids);
    let mut distribution: serde_json::Value =
        serde_json::from_slice(&valid_distribution(&ids[0], &ids)).unwrap();
    // Swap the claimed source key for another member's real key: the
    // id/key binding must catch the substitution before signature checks.
    distribution["source_public_key"] = serde_json::Value::String(hex(&ids[1].public_key));
    assert!(matches!(
        ring.verify_rotation(distribution.to_string().as_bytes()),
        Err(MemberCryptoError::SourceKeyMismatch { got }) if got == ids[0].device_id
    ));
}

#[test]
fn removed_member_rejects_a_validly_signed_rotation_targeting_it() {
    let ids = identities();
    let mut leader = ring(&ids[0], &ids);
    let distribution = leader
        .rotate_for_removal(ids[1].device_id.clone(), &ids[0])
        .unwrap()
        .distribution;

    // The removed device still holds the pre-rotation membership, so every
    // check up to the target-set test passes: it must refuse to apply a
    // rotation whose new member set no longer contains itself.
    let victim = ring(&ids[1], &ids);
    assert!(matches!(
        victim.verify_rotation(&distribution),
        Err(MemberCryptoError::RotationTargetNotMember { got }) if got == ids[1].device_id
    ));
}

#[test]
fn wrong_pre_rotation_key_fails_distribution_authentication() {
    let ids = identities();
    let mut leader = ring(&ids[0], &ids);
    let distribution = leader
        .rotate_for_removal(ids[2].device_id.clone(), &ids[0])
        .unwrap()
        .distribution;

    // Same membership and keys, but the verifier's pre-rotation group key
    // differs from the leader's: the signature passes, the group-key MAC
    // must not.
    let verifier = MemberKeyRing::with_epoch(
        "group",
        &ids[1].device_id,
        ids.iter().map(|i| i.device_id.clone()),
        ids.iter().map(|i| (i.device_id.clone(), i.public_key)),
        1,
        [0x43; 32],
    )
    .unwrap();
    assert!(matches!(
        verifier.verify_rotation(&distribution),
        Err(MemberCryptoError::AuthenticationFailed)
    ));
}

#[test]
fn odd_length_mac_hex_is_an_encoding_error() {
    let ids = identities();
    let ring = ring(&ids[0], &ids);
    let mut distribution: serde_json::Value =
        serde_json::from_slice(&valid_distribution(&ids[0], &ids)).unwrap();
    distribution["mac"] = serde_json::Value::String("abc".to_string());
    assert!(matches!(
        ring.verify_rotation(distribution.to_string().as_bytes()),
        Err(MemberCryptoError::Encoding(_))
    ));
}
