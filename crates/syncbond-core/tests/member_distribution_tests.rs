//! Acceptance: the rotated key reaches survivors only over each device's
//! own channel, a paired device joins an existing group behind an explicit
//! member-signed admission, and a removed member reading everything the
//! relay carries still cannot obtain the new key.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use syncbond_core::crypto::{open, EnvelopeContext};
use syncbond_core::identity::{DeviceIdentity, PublicIdentity};
use syncbond_core::member_crypto::{Admission, MemberCryptoError, MemberKeyRing, Rotation};
use syncbond_core::member_distribution::{
    deliver_rotation, DeliveryError, MemberChannel, MemberChannelError,
};
use syncbond_core::pairing::{accept, pair};
use syncbond_core::transport::{MemoryTransport, Transport};

const KEY: [u8; 32] = [0x42; 32];
const GROUP: &str = "group-distribution";

fn identities3() -> [DeviceIdentity; 3] {
    [
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
        DeviceIdentity::generate(),
    ]
}

/// A member ring for `device` over the given member identities, epoch 1.
fn ring_of(device: &DeviceIdentity, group: &[&DeviceIdentity]) -> MemberKeyRing {
    MemberKeyRing::with_epoch(
        GROUP,
        &device.device_id,
        group.iter().map(|member| member.device_id.clone()),
        group
            .iter()
            .map(|member| (member.device_id.clone(), member.public_key)),
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

/// The application's routing to per-device pairwise channels. A target
/// with no bound channel is refused — the guard that keeps a record off a
/// channel the removed member can read.
#[derive(Default)]
struct ChannelRouter {
    bound: BTreeSet<String>,
    log: Mutex<Vec<(String, Vec<u8>)>>,
}

impl ChannelRouter {
    fn for_devices(devices: &[&str]) -> Self {
        Self {
            bound: devices.iter().map(|device| (*device).to_owned()).collect(),
            log: Mutex::new(Vec::new()),
        }
    }

    fn logged(&self) -> Vec<(String, Vec<u8>)> {
        self.log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl MemberChannel for ChannelRouter {
    fn deliver(&self, device_id: &str, bytes: &[u8]) -> Result<(), MemberChannelError> {
        if !self.bound.contains(device_id) {
            return Err(MemberChannelError::NotRecipient {
                bound: "no pairwise channel".into(),
                asked: device_id.to_owned(),
            });
        }
        self.log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((device_id.to_owned(), bytes.to_vec()));
        Ok(())
    }
}

#[test]
fn a_rotation_reaches_every_survivor_over_its_own_channel_and_never_the_removed_device() {
    let identities = identities3();
    let mut leader = ring_of(
        &identities[0],
        &[&identities[0], &identities[1], &identities[2]],
    );
    let mut survivor = ring_of(
        &identities[1],
        &[&identities[0], &identities[1], &identities[2]],
    );
    let removed = ring_of(
        &identities[2],
        &[&identities[0], &identities[1], &identities[2]],
    );

    let result = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .expect("rotate");
    assert_eq!(result.epoch, 2);

    // Only the survivors hold a pairwise channel; the removed device does
    // not and is never asked.
    let router = ChannelRouter::for_devices(&[&identities[0].device_id, &identities[1].device_id]);
    let delivered = deliver_rotation(&router, &result).expect("all survivors delivered");
    assert_eq!(delivered, result.member_ids);

    let log = router.logged();
    assert_eq!(log.len(), 2);
    assert!(
        log.iter()
            .all(|(device, bytes)| device != &identities[2].device_id
                && bytes == &result.distribution)
    );

    survivor
        .apply_rotation(&result.distribution)
        .expect("survivor installs");
    let sealed = survivor.seal(b"after removal");
    assert!(open_under(&leader, &sealed));
    assert!(!open_under(&removed, &sealed));
}

#[test]
fn the_new_key_never_rides_the_group_relay_channel() {
    let identities = identities3();
    let mut leader = ring_of(
        &identities[0],
        &[&identities[0], &identities[1], &identities[2]],
    );
    let mut survivor = ring_of(
        &identities[1],
        &[&identities[0], &identities[1], &identities[2]],
    );
    let mut removed = ring_of(
        &identities[2],
        &[&identities[0], &identities[1], &identities[2]],
    );

    // Everything the application appends to the group channel, before and
    // after the rotation. The removed device watches the whole log.
    let mut relay = vec![serde_json::to_vec(&leader.seal(b"before removal")).unwrap()];
    let result = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .unwrap();
    let router = ChannelRouter::for_devices(&[&identities[0].device_id, &identities[1].device_id]);
    deliver_rotation(&router, &result).unwrap();
    survivor.apply_rotation(&result.distribution).unwrap();
    relay.push(serde_json::to_vec(&leader.seal(b"after removal")).unwrap());
    relay.push(serde_json::to_vec(&survivor.seal(b"after removal too")).unwrap());

    for blob in &relay {
        // No relay byte is a rotation record, so nothing on the wire can
        // even be verified as one by the removed device...
        assert!(serde_json::from_slice::<Rotation>(blob).is_err());
        // ...nothing installs on the removed device...
        assert!(removed.apply_rotation(blob).is_err());
        // ...and the new key never appears in the clear on the relay.
        assert!(
            !blob.windows(32).any(|window| window == &result.key[..]),
            "the new key must not ride the group channel"
        );
    }
    // The distribution message itself never rides the group channel either.
    assert!(relay
        .iter()
        .all(|blob| blob.as_slice() != result.distribution.as_slice()));
}

#[test]
fn a_channel_failure_reports_what_was_delivered_and_the_rest_can_retry() {
    let identities = identities3();
    let mut leader = ring_of(
        &identities[0],
        &[&identities[0], &identities[1], &identities[2]],
    );
    let result = leader
        .rotate_for_removal(identities[2].device_id.clone(), &identities[0])
        .unwrap();

    // Only the first recipient has a channel; the next is refused. The
    // recipient order is the sorted member set, so bind by position.
    let first = result.member_ids[0].clone();
    let second = result.member_ids[1].clone();
    let partial = ChannelRouter::for_devices(&[&first]);
    let error = deliver_rotation(&partial, &result).unwrap_err();
    // `Partial` is the only delivery failure shape.
    let DeliveryError::Partial {
        recipient,
        delivered,
        error,
    } = error;
    assert_eq!(recipient, second);
    assert_eq!(delivered, vec![first]);
    assert!(matches!(error, MemberChannelError::NotRecipient { .. }));

    // Retry with every survivor bound: the whole set lands.
    let full = ChannelRouter::for_devices(&[&identities[0].device_id, &identities[1].device_id]);
    let delivered = deliver_rotation(&full, &result).expect("retry delivers the rest");
    assert_eq!(delivered, result.member_ids);
}

#[test]
fn a_paired_device_joins_an_existing_group_behind_the_members_authorization() {
    let leader_identity = DeviceIdentity::generate();
    let member_identity = DeviceIdentity::generate();
    let admittee_identity = DeviceIdentity::generate();
    let group = [&leader_identity, &member_identity];
    let mut leader = ring_of(&leader_identity, &group);
    let mut member = ring_of(&member_identity, &group);

    // The leader and the new device pair for real, over the in-memory
    // transport; the session is the pairwise channel the admission rides.
    let (ta, tb) = MemoryTransport::pair();
    let (li, ai) = (leader_identity.clone(), admittee_identity.clone());
    let (leader_session, admittee_session) = std::thread::scope(|scope| {
        let initiator = scope.spawn({
            let ta = ta.clone();
            move || pair("K7Q2M4", &li, ta as Arc<dyn Transport>)
        });
        let responder = scope.spawn(move || accept("K7Q2M4", &ai, tb as Arc<dyn Transport>));
        (
            initiator
                .join()
                .expect("leader pairing thread")
                .expect("leader paired"),
            responder
                .join()
                .expect("admittee pairing thread")
                .expect("admittee paired"),
        )
    });

    let admission = leader
        .admit_member(&admittee_identity, &leader_identity)
        .expect("a member admits");
    assert_eq!(admission.epoch, 1);
    assert_eq!(admission.key, KEY);
    assert!(leader.is_member(&admittee_identity.device_id));
    let mut expected_recipients = vec![
        member_identity.device_id.clone(),
        admittee_identity.device_id.clone(),
    ];
    expected_recipients.sort();
    assert_eq!(admission.recipient_ids(), expected_recipients);

    // The record reaches the admittee over the session and installs it.
    leader_session
        .seal_and_send(&admission.to_bytes())
        .expect("admission over the session");
    let record = admittee_session
        .recv_and_open()
        .expect("admission arrives and opens");
    let admittee = Admission::from_bytes(&record)
        .expect("the record parses")
        .install_for_self(&admittee_identity, &admittee_session.peer_identity)
        .expect("the paired device installs");
    assert_eq!(admittee.current_epoch(), 1);
    assert_eq!(admittee.current_key(), &KEY);
    for device in [&leader_identity, &member_identity, &admittee_identity] {
        assert!(admittee.is_member(&device.device_id));
    }

    // The existing member adopts the same member set; idempotently.
    member
        .apply_admission(&admission.to_bytes())
        .expect("member adopts");
    member
        .apply_admission(&admission.to_bytes())
        .expect("idempotent");
    assert!(member.is_member(&admittee_identity.device_id));

    // One shared key all round.
    let sealed = admittee.seal(b"from the new device");
    assert!(open_under(&leader, &sealed));
    assert!(open_under(&member, &sealed));

    // The next rotation keeps the admitted device in the member set, and
    // the admittee installs it: membership drift heals through rotations.
    let rotation = leader
        .rotate_for_removal(member_identity.device_id.clone(), &leader_identity)
        .unwrap();
    assert!(rotation.member_ids.contains(&admittee_identity.device_id));
    let mut admittee = admittee;
    admittee.apply_rotation(&rotation.distribution).unwrap();
    assert_eq!(admittee.current_epoch(), 2);
}

#[test]
fn an_admission_only_counts_from_the_paired_peer_that_signed_it() {
    let leader_identity = DeviceIdentity::generate();
    let member_identity = DeviceIdentity::generate();
    let admittee_identity = DeviceIdentity::generate();
    let group = [&leader_identity, &member_identity];
    let mut leader = ring_of(&leader_identity, &group);
    let admission = leader
        .admit_member(&admittee_identity, &leader_identity)
        .unwrap();
    let peer = PublicIdentity {
        device_id: leader_identity.device_id.clone(),
        public_key: leader_identity.public_key,
    };

    // A record from a different session peer is refused outright.
    let stranger = DeviceIdentity::generate();
    let impostor = PublicIdentity {
        device_id: leader_identity.device_id.clone(),
        public_key: stranger.public_key,
    };
    assert!(matches!(
        admission.install_for_self(&admittee_identity, &impostor),
        Err(MemberCryptoError::SourceKeyMismatch { got }) if got == leader_identity.device_id
    ));
    let other_peer = PublicIdentity {
        device_id: stranger.device_id.clone(),
        public_key: stranger.public_key,
    };
    assert!(matches!(
        admission.install_for_self(&admittee_identity, &other_peer),
        Err(MemberCryptoError::UnauthorizedSource { got }) if got == stranger.device_id
    ));

    // A device that the record does not name is not admitted.
    assert!(matches!(
        admission.install_for_self(&stranger, &peer),
        Err(MemberCryptoError::UnknownMember(got)) if got == stranger.device_id
    ));

    // A record whose membership was rewritten after signing fails.
    let mut forged: serde_json::Value = serde_json::from_slice(&admission.to_bytes()).unwrap();
    forged["member_ids"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(stranger.device_id));
    assert!(matches!(
        Admission::from_bytes(&serde_json::to_vec(&forged).unwrap())
            .unwrap()
            .install_for_self(&admittee_identity, &peer),
        Err(MemberCryptoError::InvalidSignature)
    ));
}

#[test]
fn an_admission_that_was_minted_for_another_group_or_epoch_is_refused() {
    let leader_identity = DeviceIdentity::generate();
    let member_identity = DeviceIdentity::generate();
    let admittee_identity = DeviceIdentity::generate();
    let outsider = DeviceIdentity::generate();
    let group = [&leader_identity, &member_identity];
    let mut leader = ring_of(&leader_identity, &group);
    let mut member = ring_of(&member_identity, &group);
    let admission = leader
        .admit_member(&admittee_identity, &leader_identity)
        .unwrap();

    // A source that is not a member cannot authorize anything.
    let mut foreign: serde_json::Value = serde_json::from_slice(&admission.to_bytes()).unwrap();
    foreign["source_device_id"] = serde_json::json!(outsider.device_id);
    assert_eq!(
        member.apply_admission(&serde_json::to_vec(&foreign).unwrap()),
        Err(MemberCryptoError::UnauthorizedSource {
            got: outsider.device_id.clone(),
        })
    );

    // A record for another group does not apply.
    let mut other_group: serde_json::Value = serde_json::from_slice(&admission.to_bytes()).unwrap();
    other_group["group_id"] = serde_json::json!("group-other");
    assert!(matches!(
        member.apply_admission(&serde_json::to_vec(&other_group).unwrap()),
        Err(MemberCryptoError::CrossGroup { .. })
    ));

    // After the group rotates, an old admission is stale.
    let rotation = leader
        .rotate_for_removal(member_identity.device_id.clone(), &leader_identity)
        .unwrap();
    let mut admittee = admission
        .install_for_self(
            &admittee_identity,
            &PublicIdentity {
                device_id: leader_identity.device_id.clone(),
                public_key: leader_identity.public_key,
            },
        )
        .unwrap();
    admittee.apply_rotation(&rotation.distribution).unwrap();
    assert_eq!(
        admittee.apply_admission(&admission.to_bytes()),
        Err(MemberCryptoError::EpochNotCurrent {
            got: 1,
            expected: 2,
        })
    );
}
