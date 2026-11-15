//! Short-code policy wired into the real pairing entries (todo.md DSR-26):
//! the board's gate runs before any frame exists, so expired, consumed, and
//! locked codes cannot establish a session again; a completed pairing
//! consumes the code; a lower-case entry is normalized into the exchange
//! itself, not just into board lookups.

use std::sync::Arc;
use std::time::{Duration, Instant};
use syncbond_core::codes::{CodeError, PairingCodeBoard, PairingPolicy};
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::{accept_gated, pair, PairingError, PairingSession};
use syncbond_core::pairing_driver::{DriverEvent, PairingDriver};
use syncbond_core::transport::{MemoryTransport, Transport};

fn board(max_attempts: u32) -> PairingCodeBoard {
    PairingCodeBoard::new(PairingPolicy {
        ttl_ms: 60_000,
        max_attempts,
    })
}

/// `unwrap_err` needs the success type to be `Debug`, and a session is
/// deliberately not: it holds live keys. Match instead.
fn expect_error(result: Result<PairingSession, PairingError>) -> PairingError {
    match result {
        Ok(_) => panic!("expected the entry to fail"),
        Err(error) => error,
    }
}

#[test]
fn a_lowercased_code_pairs_with_the_issued_one() {
    let mut gate = board(3);
    let code = gate.issue();
    let lower = code.to_ascii_lowercase();
    let (ta, tb) = MemoryTransport::pair();
    let ib = DeviceIdentity::generate();
    // The gated responder normalizes what the user typed; the initiator
    // side normalizes the same way, so the SPAKE2 secrets agree — the
    // exchange completing at all is the proof the case normalization
    // reaches the key derivation, not just the lookup.
    let gate_lower = lower.clone();
    let responder = std::thread::spawn(move || {
        accept_gated(&mut gate, &gate_lower, &ib, tb as Arc<dyn Transport>)
    });
    let ia = DeviceIdentity::generate();
    let session_a = pair(&lower, &ia, ta as Arc<dyn Transport>).expect("initiator completes");
    let session_b = responder.join().unwrap().expect("gated accept completes");
    assert_eq!(session_a.group_id, session_b.group_id);
    assert_eq!(session_b.peer_identity.device_id, ia.device_id);
}

#[test]
fn an_expired_code_never_starts_an_exchange() {
    let start = Instant::now();
    let now = Arc::new(std::sync::Mutex::new(start));
    let clock = now.clone();
    let mut gate = PairingCodeBoard::with_clock(
        PairingPolicy {
            ttl_ms: 1_000,
            max_attempts: 3,
        },
        Box::new(move || *clock.lock().unwrap()),
    );
    let code = gate.issue();
    *now.lock().unwrap() = start + Duration::from_millis(1_500);
    let (ta, _tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    // A CodeError — not a transport error — is the proof the gate refused
    // before the driver existed: any exchange attempt over this idle
    // transport would fail in recv instead.
    let error = expect_error(accept_gated(
        &mut gate,
        &code,
        &ia,
        ta as Arc<dyn Transport>,
    ));
    assert!(
        matches!(error, PairingError::Code(CodeError::Expired)),
        "{error}"
    );
    assert!(matches!(gate.admit(&code), Err(CodeError::Expired)));
}

#[test]
fn a_consumed_code_cannot_pair_again() {
    let mut gate = board(3);
    let code = gate.issue();
    let (ta, tb) = MemoryTransport::pair();
    let ib = DeviceIdentity::generate();
    let gate_code = code.clone();
    let responder = std::thread::spawn(move || {
        let first = accept_gated(&mut gate, &gate_code, &ib, tb as Arc<dyn Transport>)
            .expect("first gated pairing completes");
        // Single use: the same code can never establish another session.
        let (ta2, _tb2) = MemoryTransport::pair();
        let ic = DeviceIdentity::generate();
        let second = accept_gated(&mut gate, &gate_code, &ic, ta2 as Arc<dyn Transport>);
        (first, second)
    });
    let ia = DeviceIdentity::generate();
    let session_a = pair(&code, &ia, ta as Arc<dyn Transport>).expect("initiator completes");
    let (session_b, second) = responder.join().unwrap();
    assert_eq!(session_a.group_id, session_b.group_id);
    assert!(
        matches!(second, Err(PairingError::Code(CodeError::AlreadyUsed))),
        "the spent code must be refused at the gate"
    );
}

#[test]
fn a_locked_code_cannot_start_a_fourth_exchange() {
    let mut gate = board(3);
    let code = gate.issue();
    for _ in 0..3 {
        assert_eq!(gate.register_failure(&code), Ok(()));
    }
    let (ta, _tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let error = expect_error(accept_gated(
        &mut gate,
        &code,
        &ia,
        ta as Arc<dyn Transport>,
    ));
    assert!(
        matches!(error, PairingError::Code(CodeError::TooManyAttempts)),
        "{error}"
    );
    // The lock is per code window: a different live code still admits.
    let other = gate.issue();
    assert!(gate.admit(&other).is_ok());
}

#[test]
fn a_failed_exchange_burns_an_attempt_but_a_transport_error_does_not() {
    let mut gate = board(1);
    let code = gate.issue();
    let (ta, tb) = MemoryTransport::pair();
    let ib = DeviceIdentity::generate();
    // A valid-format code that differs in one symbol: confirmation fails
    // on both sides, and that wire-level failure burns the window's
    // single attempt.
    let mut wrong = code.clone().into_bytes();
    wrong[0] = if wrong[0] == b'A' { b'B' } else { b'A' };
    let wrong = String::from_utf8(wrong).expect("alphabet bytes");
    let responder = std::thread::spawn(move || {
        let error = expect_error(accept_gated(
            &mut gate,
            &code,
            &ib,
            tb as Arc<dyn Transport>,
        ));
        assert!(
            !matches!(error, PairingError::Code(_)),
            "the gate must admit the right code: {error}"
        );
        assert!(
            matches!(gate.admit(&code), Err(CodeError::TooManyAttempts)),
            "one failed exchange at maxAttempts 1 locks the window"
        );
    });
    let ia = DeviceIdentity::generate();
    let error = expect_error(pair(&wrong, &ia, ta as Arc<dyn Transport>));
    assert!(!matches!(error, PairingError::Code(_)), "{error}");
    responder.join().unwrap();
}

#[test]
fn a_transport_error_leaves_the_window_open_for_a_real_pairing() {
    let mut gate = board(1);
    let code = gate.issue();
    let (ta, tb) = MemoryTransport::pair();
    MemoryTransport::close_pair(&ta, &tb);
    let ia = DeviceIdentity::generate();
    let error = expect_error(accept_gated(
        &mut gate,
        &code,
        &ia,
        ta as Arc<dyn Transport>,
    ));
    assert!(
        matches!(error, PairingError::Transport(_)),
        "a closed transport is not a guess: {error}"
    );
    assert!(
        gate.admit(&code).is_ok(),
        "the window must survive a transport hiccup"
    );
    // And the same code really does pair once the transport works.
    let (ta, tb) = MemoryTransport::pair();
    let ib = DeviceIdentity::generate();
    let gate_code = code.clone();
    let responder = std::thread::spawn(move || {
        accept_gated(&mut gate, &gate_code, &ib, tb as Arc<dyn Transport>)
    });
    let session_a =
        pair(&code, &ia, ta as Arc<dyn Transport>).expect("pairing completes after the hiccup");
    let session_b = responder.join().unwrap().expect("gated accept completes");
    assert_eq!(session_a.group_id, session_b.group_id);
}

#[test]
fn the_gate_guards_the_driver_flow_the_same_way() {
    let mut gate = board(3);
    let code = gate.issue();
    let (ta, tb) = MemoryTransport::pair();
    let ib = DeviceIdentity::generate();
    // Non-blocking host shape: admit first, build with the canonical form
    // it hands back, settle after the outcome.
    let normalized = gate.admit(&code.to_ascii_lowercase()).expect("live code");
    assert_eq!(normalized, code, "the gate hands back the canonical form");
    let mut driver =
        PairingDriver::responder(&normalized, &ib, tb.clone() as Arc<dyn Transport>).unwrap();
    let ia = DeviceIdentity::generate();
    let peer_code = code.clone();
    let peer = std::thread::spawn(move || pair(&peer_code, &ia, ta as Arc<dyn Transport>));
    let session = loop {
        while let Some(frame) = driver.pop_outgoing() {
            tb.send(&frame).expect("host forwards the frame");
        }
        if let Some(event) = driver.poll() {
            let DriverEvent::Completed(session) = event else {
                panic!("the gated driver must complete");
            };
            break session;
        }
        let frame = tb.recv().expect("the blocking initiator answers");
        driver.push(&frame).unwrap();
    };
    let peer_session = peer.join().unwrap().expect("peer completes");
    assert_eq!(session.group_id, peer_session.group_id);
    // The host settles success: the code is consumed, the gate refuses
    // everything further on it.
    gate.consume(&normalized).unwrap();
    assert!(matches!(gate.admit(&code), Err(CodeError::AlreadyUsed)));
}
