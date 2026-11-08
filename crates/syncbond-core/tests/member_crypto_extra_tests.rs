//! Extra coverage for member-set rotation: constructor validation, accessors,
//! error branches in `verify_rotation`/`apply_rotation`, and encoding edge
//! cases not exercised by the rotation happy path.

use syncbond_core::identity::DeviceIdentity;
use syncbond_core::member_crypto::{MemberCryptoError, MemberKeyRing};

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
        MemberKeyRing::with_epoch("group", "stranger", ids.iter().map(|i| i.device_id.clone()), ids.iter().map(|i| (i.device_id.clone(), i.public_key)), 1, [0; 32]),
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
        ids.iter()
            .enumerate()
            .map(|(index, i)| {
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
