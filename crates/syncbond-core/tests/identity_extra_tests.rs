//! Extra identity coverage: transcript binding, malformed key material, and
//! hex serialization paths.

use syncbond_core::identity::{DeviceIdentity, IdentityError};
use syncbond_core::identity::PublicIdentity;

#[test]
fn transcript_binding_rejects_wrong_role_and_tampered() {
    let a = DeviceIdentity::generate();
    let _b = DeviceIdentity::generate();
    let transcript = b"transcript";
    let sig = a.sign_transcript("initiator", transcript);
    let pub_a: PublicIdentity = (&a).into();
    assert_eq!(pub_a.verify_transcript("initiator", transcript, &sig), Ok(()));
    assert!(matches!(
        pub_a.verify_transcript("responder", transcript, &sig),
        Err(IdentityError::BadSignature)
    ));
    assert!(matches!(
        pub_a.verify_transcript("initiator", b"other", &sig),
        Err(IdentityError::BadSignature)
    ));
    let mut tampered = sig.to_bytes();
    tampered[0] ^= 0xff;
    let bad = ed25519_dalek::Signature::from_bytes(&tampered);
    assert!(matches!(
        pub_a.verify_transcript("initiator", transcript, &bad),
        Err(IdentityError::BadSignature)
    ));
}

#[test]
fn identity_rejects_bad_secret_and_verify_failures() {
    assert!(matches!(
        DeviceIdentity::from_secret_key_bytes(&[0u8; 8]),
        Err(IdentityError::BadKeyMaterial)
    ));
    let a = DeviceIdentity::generate();
    let sig = a.sign(b"msg");
    assert_eq!(a.verify(b"msg", &sig), Ok(()));
    assert!(a.verify(b"other", &sig).is_err());
    let bad = ed25519_dalek::Signature::from_bytes(&[0u8; 64]);
    assert!(a.verify(b"msg", &bad).is_err());
    // PublicIdentity with a bad key must reject transcript verification.
    let pub_bad = PublicIdentity { device_id: "x".into(), public_key: [0u8; 32] };
    assert!(pub_bad.verify_transcript("initiator", b"t", &sig).is_err());
}

#[test]
fn identity_serde_round_trip_and_group_id() {
    let a = DeviceIdentity::generate();
    let b = DeviceIdentity::generate();
    let json = serde_json::to_string(&a).unwrap();
    let decoded: DeviceIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.device_id, a.device_id);
    let g1 = syncbond_core::identity::group_id_from_public_keys(&[a.public_key, b.public_key]);
    let g2 = syncbond_core::identity::group_id_from_public_keys(&[b.public_key, a.public_key]);
    assert_eq!(g1, g2);
    assert_eq!(g1.len(), 24);
    assert_eq!(a.device_id.len(), 16);
}
