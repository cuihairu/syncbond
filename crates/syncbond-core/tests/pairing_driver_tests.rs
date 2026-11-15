//! Non-blocking pairing driver tests (todo.md DSR-25): every scenario runs
//! two drivers against each other with an explicit drain-send-poll loop —
//! the shape an external event loop (WebSocket reader, GUI, FFI host) uses
//! — and never calls a blocking `recv` from the driver's side. The
//! completed sessions are then exercised as real sessions to prove the
//! driver reuses (rather than re-implements) the crypto.

use std::sync::Arc;
use syncbond_core::codes::CodeError;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::{accept, pair, PairingError};
use syncbond_core::pairing_driver::{DriverEvent, PairingDriver};
use syncbond_core::transport::{MemoryTransport, Transport};

const CODE: &str = "K7Q2M4";
const FRAME_P_A: u8 = 0x01;
const FRAME_CONFIRM_A: u8 = 0x03;
const FRAME_ABORT: u8 = 0x07;
const FRAME_IDENTITY_A: u8 = 0x05;

/// The event must be a failure carrying `needle` in its message.
fn assert_failed(event: DriverEvent, needle: &str) {
    let DriverEvent::Failed(error) = event else {
        panic!("expected a failed event, got a session");
    };
    let message = error.to_string();
    assert!(
        message.contains(needle),
        "expected the failure to mention {needle:?}, got: {message}"
    );
}

/// Keep the frame as-is.
fn no_tamper(_kind: u8, _frame: &[u8]) -> Option<Vec<u8>> {
    None
}

/// One synchronous wire round: drain both outboxes, hand every frame to
/// the other driver — after `tamper` had its say (`None` keeps the frame)
/// — and report whether both sides have reached a terminal event. A driver
/// that already has its event is fed nothing more: a host stops feeding a
/// finished machine, so a goodbye queued by a failure stays on its own
/// wire unless the peer is still listening.
fn wire_round(
    initiator: &mut PairingDriver,
    responder: &mut PairingDriver,
    mut tamper: impl FnMut(u8, &[u8]) -> Option<Vec<u8>>,
) -> bool {
    let mut to_responder = Vec::new();
    let mut to_initiator = Vec::new();
    while let Some(frame) = initiator.pop_outgoing() {
        to_responder.push(frame);
    }
    while let Some(frame) = responder.pop_outgoing() {
        to_initiator.push(frame);
    }
    for frame in to_responder {
        if !responder.has_event() {
            let frame = tamper(frame[0], &frame).unwrap_or(frame);
            responder
                .push(&frame)
                .expect("a live driver accepts frames");
        }
    }
    for frame in to_initiator {
        if !initiator.has_event() {
            let frame = tamper(frame[0], &frame).unwrap_or(frame);
            initiator
                .push(&frame)
                .expect("a live driver accepts frames");
        }
    }
    initiator.has_event() && responder.has_event()
}

/// Drive both drivers to their terminal events over `wire_round`, with a
/// hard round bound: the protocol exchanges at most six frames, so six
/// rounds must settle any exchange that is not wedged.
fn drive_to_completion(
    initiator: &mut PairingDriver,
    responder: &mut PairingDriver,
) -> (DriverEvent, DriverEvent) {
    let mut rounds = 0;
    while !wire_round(initiator, responder, no_tamper) {
        rounds += 1;
        assert!(rounds <= 6, "the exchange wedged after {rounds} rounds");
    }
    (
        initiator.poll().expect("initiator has a terminal event"),
        responder.poll().expect("responder has a terminal event"),
    )
}

#[test]
fn two_drivers_complete_each_other_and_the_sessions_work() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let mut initiator =
        PairingDriver::initiator(CODE, &ia, ta.clone() as Arc<dyn Transport>).expect("valid code");
    let mut responder =
        PairingDriver::responder(CODE, &ib, tb.clone() as Arc<dyn Transport>).expect("valid code");
    // The initiator opens with pA in the outbox; the responder emits
    // nothing until pA arrives.
    let p_a = initiator.pop_outgoing().expect("pA is queued at once");
    assert_eq!(p_a[0], FRAME_P_A);
    assert!(responder.pop_outgoing().is_none());
    responder.push(&p_a).unwrap();

    let (event_a, event_b) = drive_to_completion(&mut initiator, &mut responder);
    let DriverEvent::Completed(session_a) = event_a else {
        panic!("initiator must complete");
    };
    let DriverEvent::Completed(session_b) = event_b else {
        panic!("responder must complete");
    };
    assert_eq!(session_a.group_id, session_b.group_id);
    assert_eq!(session_a.peer_identity.device_id, ib.device_id);
    assert_eq!(session_b.peer_identity.device_id, ia.device_id);

    // The sessions are the real thing: sealed frames cross the linked
    // transports and open with replay protection intact.
    session_a.seal_and_send(b"hello over the driver").unwrap();
    let opened = session_b.recv_and_open().unwrap();
    assert_eq!(opened, b"hello over the driver");
    session_b.seal_and_send(b"and back").unwrap();
    assert_eq!(session_a.recv_and_open().unwrap(), b"and back");
}

#[test]
fn a_wrong_code_fails_both_sides_with_one_abort_each() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let mut initiator = PairingDriver::initiator(CODE, &ia, ta as Arc<dyn Transport>).unwrap();
    let mut responder = PairingDriver::responder("AAAAAA", &ib, tb as Arc<dyn Transport>).unwrap();
    // Hand-walked exchange: structurally valid frames (both sides derive
    // secrets from different codes), so the failure surfaces at the key
    // confirmation, exactly as the blocking path fails.
    let p_a = initiator.pop_outgoing().unwrap();
    responder.push(&p_a).unwrap();
    let p_b = responder.pop_outgoing().unwrap();
    initiator.push(&p_b).unwrap();
    let c_a = initiator.pop_outgoing().unwrap();
    responder.push(&c_a).unwrap();
    assert!(
        matches!(responder.poll(), Some(DriverEvent::Failed(_))),
        "the responder's key confirmation must fail"
    );
    let goodbye_b = responder.pop_outgoing().unwrap();
    assert_eq!(goodbye_b[0], FRAME_ABORT, "one abort frame for the peer");
    initiator.push(&goodbye_b).unwrap();
    assert!(
        matches!(initiator.poll(), Some(DriverEvent::Failed(_))),
        "the initiator learns of the refusal via the peer's abort"
    );
    let goodbye_a = initiator.pop_outgoing().unwrap();
    assert_eq!(goodbye_a[0], FRAME_ABORT, "one abort frame for the peer");
    // An explicit abort after a failure adds no second goodbye.
    initiator.abort();
    responder.abort();
    assert!(initiator.pop_outgoing().is_none() && responder.pop_outgoing().is_none());
    // A finished driver refuses input and its event is one-shot.
    assert!(initiator.push(&[FRAME_P_A, 1]).is_err());
    assert!(responder.push(&[FRAME_P_A, 1]).is_err());
    assert!(initiator.poll().is_none(), "events are one-shot");
}

#[test]
fn an_out_of_order_frame_fails_the_exchange() {
    let (ta, _tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let mut initiator = PairingDriver::initiator(CODE, &ia, ta as Arc<dyn Transport>).unwrap();
    // The host has drained pA before feeding the next wire frame.
    assert_eq!(initiator.pop_outgoing().unwrap()[0], FRAME_P_A);
    // cA cannot be the second frame: pB is owed first.
    let mut c_a = vec![FRAME_CONFIRM_A, 1];
    c_a.resize(34, 0);
    initiator.push(&c_a).unwrap();
    assert_failed(initiator.poll().expect("a terminal event"), "expected pB");
    assert_eq!(
        initiator.pop_outgoing().unwrap()[0],
        FRAME_ABORT,
        "the refusal queues exactly one abort"
    );
}

#[test]
fn an_abort_frame_from_the_peer_fails_immediately() {
    let (ta, _tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let mut responder = PairingDriver::responder(CODE, &ia, ta as Arc<dyn Transport>).unwrap();
    responder.push(&[FRAME_ABORT, 1]).unwrap();
    assert_failed(
        responder.poll().expect("a terminal event"),
        "peer aborted the pairing",
    );
}

#[test]
fn an_oversized_frame_fails_before_any_parsing() {
    let (ta, _tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let mut responder = PairingDriver::responder(CODE, &ia, ta as Arc<dyn Transport>).unwrap();
    let mut frame = vec![FRAME_P_A, 1];
    frame.resize(16 * 1024 * 1024 + 1, 0);
    responder.push(&frame).unwrap();
    assert_failed(
        responder.poll().expect("a terminal event"),
        "frame too large",
    );
}

#[test]
fn a_wrong_protocol_version_fails_the_exchange() {
    let (ta, _tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let mut responder = PairingDriver::responder(CODE, &ia, ta as Arc<dyn Transport>).unwrap();
    // A syntactically valid pA speaking version 0: refused like the
    // blocking path refuses it.
    responder.push(&[FRAME_P_A, 0]).unwrap();
    assert_failed(
        responder.poll().expect("a terminal event"),
        "protocol version mismatch",
    );
}

#[test]
fn a_garbled_identity_frame_fails_the_exchange() {
    // Drive a genuine exchange, but on the wire swap the initiator's
    // signed identity (0x05) for garbage before the responder sees it:
    // the signature check is what must catch it. The initiator completes
    // before the responder renders its verdict — the last frames cross
    // unsolicited — so the refusal is one-sided by construction.
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let mut initiator =
        PairingDriver::initiator(CODE, &ia, ta.clone() as Arc<dyn Transport>).unwrap();
    let mut responder =
        PairingDriver::responder(CODE, &ib, tb.clone() as Arc<dyn Transport>).unwrap();
    let tamper = |kind: u8, _frame: &[u8]| {
        if kind == FRAME_IDENTITY_A {
            Some(vec![FRAME_IDENTITY_A, 1, b'{', b'"'])
        } else {
            None
        }
    };
    let mut rounds = 0;
    while !wire_round(&mut initiator, &mut responder, tamper) {
        rounds += 1;
        assert!(rounds <= 6, "the exchange wedged after {rounds} rounds");
    }
    let event = responder.poll().expect("a terminal event");
    assert!(
        matches!(event, DriverEvent::Failed(_)),
        "the forged identity must fail the exchange"
    );
    assert_eq!(
        responder.pop_outgoing().unwrap()[0],
        FRAME_ABORT,
        "the responder says goodbye once"
    );
    assert!(
        matches!(initiator.poll(), Some(DriverEvent::Completed(_))),
        "the initiator completed before the forgery was caught"
    );
}

#[test]
fn a_mistyped_code_fails_before_any_frame_exists() {
    let (ta, _tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let error = match PairingDriver::initiator("K7Q2M!", &ia, ta as Arc<dyn Transport>) {
        Err(error) => error,
        Ok(_) => panic!("format validation is the constructor's job"),
    };
    assert!(
        matches!(error, PairingError::Code(CodeError::BadFormat)),
        "{error}"
    );
}

#[test]
fn the_driver_and_a_blocking_peer_complete_over_a_real_transport() {
    // Driver initiator inline; blocking `accept` on a thread. Frames cross
    // through the linked transports: the driver's outgoing frames must be
    // forwarded by the host — which this loop does, the exact job of an
    // event loop. The only blocking point is the host's own recv.
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let mut driver = PairingDriver::initiator(CODE, &ia, ta.clone() as Arc<dyn Transport>).unwrap();
    let peer = std::thread::spawn(move || accept(CODE, &ib, tb as Arc<dyn Transport>));
    let session = loop {
        while let Some(frame) = driver.pop_outgoing() {
            ta.send(&frame).expect("host forwards the frame");
        }
        if let Some(event) = driver.poll() {
            let DriverEvent::Completed(session) = event else {
                panic!("the driver must complete against the blocking peer");
            };
            break session;
        }
        let frame = ta.recv().expect("the peer answers");
        driver.push(&frame).unwrap();
    };
    let peer_session = peer
        .join()
        .expect("blocking peer thread")
        .expect("blocking peer completes");
    assert_eq!(session.group_id, peer_session.group_id);
}

#[test]
fn a_blocking_initiator_and_a_driver_responder_complete() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let initiator_id = ia.device_id.clone();
    let mut driver = PairingDriver::responder(CODE, &ib, tb.clone() as Arc<dyn Transport>).unwrap();
    let peer = std::thread::spawn(move || pair(CODE, &ia, ta as Arc<dyn Transport>));
    let session = loop {
        while let Some(frame) = driver.pop_outgoing() {
            tb.send(&frame).expect("host forwards the frame");
        }
        if let Some(event) = driver.poll() {
            let DriverEvent::Completed(session) = event else {
                panic!("the responder driver must complete");
            };
            break session;
        }
        let frame = tb.recv().expect("the blocking initiator answers");
        driver.push(&frame).unwrap();
    };
    let peer_session = peer
        .join()
        .expect("blocking initiator thread")
        .expect("blocking initiator completes");
    assert_eq!(session.group_id, peer_session.group_id);
    assert_eq!(session.peer_identity.device_id, initiator_id);
}
