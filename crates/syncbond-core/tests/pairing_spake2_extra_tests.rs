//! Extra SPAKE2 coverage: the `new_with_scalars` constructor pair and the
//! confirmation failure when the two sides hold different codes.

use syncbond_core::pairing_spake2::{
    scalar_from_hex, Spake2Error, Spake2Initiator, Spake2Responder, TestScalars,
};

/// Fixed nonzero scalars so the handshake is deterministic without pinning
/// the RFC vectors that `rfc9382_vectors.rs` already asserts.
fn test_scalars() -> TestScalars {
    TestScalars {
        w: Some(scalar_from_hex(&"11".repeat(32)).expect("w hex")),
        x: Some(scalar_from_hex(&"22".repeat(32)).expect("x hex")),
        y: Some(scalar_from_hex(&"33".repeat(32)).expect("y hex")),
    }
}

#[test]
fn new_with_scalars_drives_a_full_handshake_on_both_roles() {
    let scalars = test_scalars();
    let code = b"K7Q2M4";
    let mut initiator = Spake2Initiator::new_with_scalars(code, &scalars);
    let mut responder = Spake2Responder::new_with_scalars(code, &scalars);

    let p_a = initiator.generate_message();
    let (p_b, responder_secrets, c_b) = responder
        .process_intro(&p_a)
        .expect("responder processes intro");
    let (initiator_secrets, c_a) = initiator
        .process_response(&p_b)
        .expect("initiator processes response");

    initiator
        .verify_confirmation(&initiator_secrets, &c_b)
        .expect("initiator accepts the responder confirmation");
    responder
        .verify_confirmation(&responder_secrets, &c_a)
        .expect("responder accepts the initiator confirmation");
    assert_eq!(initiator_secrets.ke, responder_secrets.ke);
}

#[test]
fn different_codes_fail_confirmation_on_both_sides() {
    let mut initiator = Spake2Initiator::new(b"code-one");
    let mut responder = Spake2Responder::new(b"code-two");

    let p_a = initiator.generate_message();
    let (p_b, responder_secrets, c_b) = responder
        .process_intro(&p_a)
        .expect("responder derives keys from its own code");
    let (initiator_secrets, c_a) = initiator
        .process_response(&p_b)
        .expect("the exchange still completes structurally");

    assert_ne!(
        initiator_secrets.ke, responder_secrets.ke,
        "different codes must not derive the same shared secret"
    );
    assert_eq!(
        initiator.verify_confirmation(&initiator_secrets, &c_b),
        Err(Spake2Error::ConfirmationFailed)
    );
    assert_eq!(
        responder.verify_confirmation(&responder_secrets, &c_a),
        Err(Spake2Error::ConfirmationFailed)
    );
}
