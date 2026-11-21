//! Externally driven pairing end tests (todo.md DSR-34): two ends started
//! from two existing identities, protocol frames routed by the caller, and
//! the cancel / late-frame / ownership / error semantics of the handle layer.

use syncbond_ffi::error::{
    SB_ERR_INPUT, SB_ERR_PROTOCOL, SB_PAIR_EVENT_COMPLETED, SB_PAIR_EVENT_FAILED,
    SB_PAIR_EVENT_NONE, SB_PAIR_ROLE_INITIATOR, SB_PAIR_ROLE_RESPONDER,
};
use syncbond_ffi::handles::{Identity, PairEnd};

const CODE: &str = "K7Q2M4";
const FRAME_P_A: u8 = 0x01;
const FRAME_ABORT: u8 = 0x07;

/// One wire round: drain both outboxes and hand every frame to the other
/// end unless that end already finished (a finished end refuses frames, so
/// the host stops feeding it — the state a routing loop gates on). Reports
/// whether both ends reached a terminal transition.
fn wire_round(a: &mut PairEnd, b: &mut PairEnd) -> bool {
    let mut to_b = Vec::new();
    let mut to_a = Vec::new();
    while let Some(frame) = a.pop_outgoing() {
        to_b.push(frame);
    }
    while let Some(frame) = b.pop_outgoing() {
        to_a.push(frame);
    }
    for frame in to_b {
        if !b.is_finished() {
            b.push(&frame).expect("a live end accepts frames");
        }
    }
    for frame in to_a {
        if !a.is_finished() {
            a.push(&frame).expect("a live end accepts frames");
        }
    }
    a.is_finished() && b.is_finished()
}

/// Drive both ends to their terminal events, with a hard round bound: the
/// protocol exchanges at most six frames, so six rounds must settle it.
fn drive_to_completion(a: &mut PairEnd, b: &mut PairEnd) {
    let mut rounds = 0;
    while !wire_round(a, b) {
        rounds += 1;
        assert!(rounds <= 6, "the exchange wedged after {rounds} rounds");
    }
}

#[test]
fn two_ends_from_existing_identities_complete_and_sessions_match() {
    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let mut a = PairEnd::new(&id_a, SB_PAIR_ROLE_INITIATOR, CODE).unwrap();
    let mut b = PairEnd::new(&id_b, SB_PAIR_ROLE_RESPONDER, CODE).unwrap();

    // The initiator opens with pA at once; the responder emits nothing
    // before pA arrives.
    let p_a = a.pop_outgoing().expect("pA is queued at once");
    assert_eq!(p_a[0], FRAME_P_A);
    assert!(b.pop_outgoing().is_none());
    b.push(&p_a).unwrap();

    drive_to_completion(&mut a, &mut b);
    assert_eq!(a.poll(), SB_PAIR_EVENT_COMPLETED);
    let session_a = a.take_session().expect("session handed over");
    assert_eq!(b.poll(), SB_PAIR_EVENT_COMPLETED);
    let session_b = b.take_session().expect("session handed over");
    // Polling is one-shot: the event was consumed on the way out.
    assert_eq!(a.poll(), SB_PAIR_EVENT_NONE);
    assert!(a.failure().is_none());

    // The sessions agree on the group and cross-match the peer device ids
    // against the identities that started the ends.
    assert_eq!(session_a.group_id(), session_b.group_id());
    assert_eq!(session_a.peer_device_id(), id_b.device_id());
    assert_eq!(session_b.peer_device_id(), id_a.device_id());

    // Ownership: the session moved to the caller, so it cannot be taken again.
    assert!(a.take_session().is_err());
}

#[test]
fn an_imported_identity_can_drive_an_end() {
    let seed = Identity::generate();
    let imported = Identity::import(&seed.secret_key()).expect("64-byte key");
    assert_eq!(imported.device_id(), seed.device_id());

    let mut a = PairEnd::new(&imported, SB_PAIR_ROLE_INITIATOR, CODE).unwrap();
    let id_b = Identity::generate();
    let mut b = PairEnd::new(&id_b, SB_PAIR_ROLE_RESPONDER, CODE).unwrap();
    drive_to_completion(&mut a, &mut b);
    assert_eq!(a.poll(), SB_PAIR_EVENT_COMPLETED);
    let session_a = a.take_session().expect("session handed over");
    assert_eq!(b.poll(), SB_PAIR_EVENT_COMPLETED);
    assert_eq!(session_a.peer_device_id(), id_b.device_id());
}

#[test]
fn a_wrong_code_fails_both_ends_with_one_abort_each() {
    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let mut a = PairEnd::new(&id_a, SB_PAIR_ROLE_INITIATOR, CODE).unwrap();
    let mut b = PairEnd::new(&id_b, SB_PAIR_ROLE_RESPONDER, "AAAAAA").unwrap();

    // Hand-walked exchange: structurally valid frames (both sides derive
    // secrets from different codes), so the failure surfaces at the key
    // confirmation.
    let p_a = a.pop_outgoing().unwrap();
    b.push(&p_a).unwrap();
    let p_b = b.pop_outgoing().unwrap();
    a.push(&p_b).unwrap();
    let c_a = a.pop_outgoing().unwrap();
    b.push(&c_a).unwrap();
    assert_eq!(b.poll(), SB_PAIR_EVENT_FAILED);
    assert!(b.failure().is_some(), "the responder records why");

    // Exactly one goodbye for the peer.
    let goodbye_b = b.pop_outgoing().expect("one abort frame queued");
    assert_eq!(goodbye_b[0], FRAME_ABORT);
    a.push(&goodbye_b).unwrap();
    assert_eq!(a.poll(), SB_PAIR_EVENT_FAILED);
    let why_a = a.failure().expect("the initiator records why");
    assert!(why_a.contains("peer aborted"), "{why_a}");
    let goodbye_a = a.pop_outgoing().expect("one abort frame queued");
    assert_eq!(goodbye_a[0], FRAME_ABORT);

    // An explicit abort after a failure adds no second goodbye.
    a.abort();
    b.abort();
    assert!(a.pop_outgoing().is_none() && b.pop_outgoing().is_none());

    // A finished end refuses input.
    let error = a.push(&[FRAME_P_A, 1]).err().unwrap();
    assert_eq!(error.code, SB_ERR_PROTOCOL);
    assert!(b.is_finished() && a.is_finished());
}

#[test]
fn an_abort_mid_exchange_sends_the_goodbye_and_the_peer_fails() {
    let mut a = PairEnd::new(&Identity::generate(), SB_PAIR_ROLE_INITIATOR, CODE).unwrap();
    let mut b = PairEnd::new(&Identity::generate(), SB_PAIR_ROLE_RESPONDER, CODE).unwrap();
    b.abort();
    let goodbye_b = b.pop_outgoing().expect("abort queues the goodbye");
    assert_eq!(goodbye_b[0], FRAME_ABORT);
    b.abort();
    assert!(b.pop_outgoing().is_none(), "abort queues it only once");
    a.push(&goodbye_b).unwrap();
    assert_eq!(a.poll(), SB_PAIR_EVENT_FAILED);
    assert!(
        a.failure().unwrap().contains("peer aborted"),
        "the abort is the initiator's recorded reason"
    );
}

#[test]
fn an_out_of_order_frame_fails_and_queues_one_abort() {
    let mut a = PairEnd::new(&Identity::generate(), SB_PAIR_ROLE_INITIATOR, CODE).unwrap();
    assert_eq!(a.pop_outgoing().unwrap()[0], FRAME_P_A);
    // cA cannot be the second frame: pB is owed first.
    let mut c_a = vec![0x03u8, 1];
    c_a.resize(34, 0);
    a.push(&c_a).unwrap();
    assert_eq!(a.poll(), SB_PAIR_EVENT_FAILED);
    let why = a.failure().unwrap();
    assert!(why.contains("expected pB"), "{why}");
    assert_eq!(a.pop_outgoing().unwrap()[0], FRAME_ABORT);
}

#[test]
fn the_session_is_absent_until_the_exchange_completes() {
    let mut a = PairEnd::new(&Identity::generate(), SB_PAIR_ROLE_INITIATOR, CODE).unwrap();
    assert_eq!(a.poll(), SB_PAIR_EVENT_NONE);
    assert!(!a.is_finished());
    assert!(a.failure().is_none());
    let error = a.take_session().err().unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);
    // The exchange is still live, so a well-formed push is accepted.
    a.push(&[0x02, 1]).unwrap();
}

#[test]
fn construction_validates_role_code_and_identity() {
    let identity = Identity::generate();
    let error = PairEnd::new(&identity, 42, CODE).err().unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);
    let error = PairEnd::new(&identity, SB_PAIR_ROLE_INITIATOR, "K7Q2M!")
        .err()
        .unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);
    let error = PairEnd::new(&identity, SB_PAIR_ROLE_RESPONDER, "")
        .err()
        .unwrap();
    assert_eq!(error.code, SB_ERR_INPUT);
}

#[test]
fn an_unwired_exchange_queues_no_goodbye_on_its_own() {
    // Two live ends that are never wired: neither queues a goodbye on its
    // own, and the initiator's pA waits in its own outbox.
    let mut a = PairEnd::new(&Identity::generate(), SB_PAIR_ROLE_INITIATOR, CODE).unwrap();
    let mut b = PairEnd::new(&Identity::generate(), SB_PAIR_ROLE_RESPONDER, CODE).unwrap();
    assert_eq!(a.poll(), SB_PAIR_EVENT_NONE);
    assert!(b.pop_outgoing().is_none());
    assert_eq!(a.pop_outgoing().unwrap()[0], FRAME_P_A);
    assert!(
        a.pop_outgoing().is_none(),
        "the initiator queues exactly one pA"
    );
}
