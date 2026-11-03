//! Pairing flow tests over the in-memory transport: session key agreement,
//! wrong-code rejection, code policy (single use / TTL / attempt limits),
//! and protocol version negotiation.

use std::sync::Arc;
use std::time::{Duration, Instant};
use syncbond_core::codes::{CodeError, PairingCodeBoard, PairingPolicy};
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::{accept, pair, PairingError};
use syncbond_core::transport::{MemoryTransport, Transport};

fn run_pair(code_a: &str, code_b: &str) -> (Result<(), PairingError>, Result<(), PairingError>) {
    let (ta, tb) = MemoryTransport::pair();
    let identity_a = DeviceIdentity::generate();
    let identity_b = DeviceIdentity::generate();
    let (ra, rb) = std::thread::scope(|s| {
        let ha = s.spawn({
            let ta = ta.clone();
            move || {
                let r = pair(code_a, &identity_a, ta as Arc<dyn Transport>);
                r.map(|_| ())
            }
        });
        let hb = s.spawn(move || {
            let r = accept(code_b, &identity_b, tb as Arc<dyn Transport>);
            r.map(|_| ())
        });
        (
            ha.join().expect("initiator thread"),
            hb.join().expect("responder thread"),
        )
    });
    (ra, rb)
}

#[test]
fn matching_codes_establish_a_session() {
    let (ra, rb) = run_pair("K7Q2M4", "K7Q2M4");
    ra.expect("initiator paired");
    rb.expect("responder paired");
}

#[test]
fn mismatched_codes_reject_on_both_sides_without_deadlock() {
    let (ra, rb) = run_pair("K7Q2M4", "AAAAAA");
    assert!(ra.is_err(), "initiator must reject");
    assert!(rb.is_err(), "responder must reject");
}

#[test]
fn oversized_app_frames_are_rejected() {
    let (ta, tb) = MemoryTransport::pair();
    let identity_a = DeviceIdentity::generate();
    let identity_b = DeviceIdentity::generate();
    let (_sa, sb) = std::thread::scope(|s| {
        let ha = s.spawn({
            let ta = ta.clone();
            move || pair("K7Q2M4", &identity_a, ta as Arc<dyn Transport>)
        });
        let hb = s.spawn({
            let tb = tb.clone();
            move || accept("K7Q2M4", &identity_b, tb as Arc<dyn Transport>)
        });
        (
            ha.join()
                .expect("initiator thread")
                .expect("initiator paired"),
            hb.join()
                .expect("responder thread")
                .expect("responder paired"),
        )
    });

    // A hostile (already authenticated) peer sends an app frame above the cap.
    let mut frame = vec![0x08u8, 1u8];
    frame.resize(syncbond_core::pairing::MAX_FRAME_BYTES + 1, 0);
    ta.send(&frame).expect("send oversized frame");

    let error = sb
        .recv_and_open()
        .expect_err("oversized frame must be rejected");
    assert!(
        matches!(error, PairingError::Protocol(ref message) if message.contains("frame too large")),
        "expected frame-too-large protocol error, got {error:?}"
    );
}

#[test]
fn seal_and_send_rejects_oversized_payload_before_sending() {
    let (ta, tb) = MemoryTransport::pair();
    let identity_a = DeviceIdentity::generate();
    let identity_b = DeviceIdentity::generate();
    let (sa, sb) = std::thread::scope(|s| {
        let ha = s.spawn({
            let ta = ta.clone();
            move || pair("K7Q2M4", &identity_a, ta as Arc<dyn Transport>)
        });
        let hb = s.spawn({
            let tb = tb.clone();
            move || accept("K7Q2M4", &identity_b, tb as Arc<dyn Transport>)
        });
        (
            ha.join()
                .expect("initiator thread")
                .expect("initiator paired"),
            hb.join()
                .expect("responder thread")
                .expect("responder paired"),
        )
    });

    // A payload that would push the encoded envelope past the frame cap must
    // be refused locally rather than emitted and rejected by the peer.
    let oversized = vec![0u8; syncbond_core::pairing::MAX_FRAME_BYTES];
    let error = sa
        .seal_and_send(&oversized)
        .expect_err("oversized payload must be refused locally");
    assert!(
        matches!(error, PairingError::Protocol(ref message) if message.contains("frame too large")),
        "expected frame-too-large protocol error, got {error:?}"
    );

    // Nothing must have reached the peer; a normal small message still works.
    sa.seal_and_send(b"ok").expect("small payload sends");
    assert_eq!(sb.recv_and_open().expect("peer opens"), b"ok");
}

#[test]
fn oversized_handshake_frames_are_rejected() {
    let (ta, tb) = MemoryTransport::pair();
    let identity_b = DeviceIdentity::generate();

    let mut frame = vec![0x01u8, 1u8, 4, 0];
    frame.resize(syncbond_core::pairing::MAX_FRAME_BYTES + 1, 0);
    ta.send(&frame).expect("send oversized pA");

    let error = match accept("K7Q2M4", &identity_b, tb as Arc<dyn Transport>) {
        Err(err) => err,
        Ok(_) => panic!("oversized handshake frame must be rejected before parsing"),
    };
    assert!(
        matches!(error, PairingError::Protocol(ref message) if message.contains("frame too large")),
        "expected frame-too-large protocol error, got {error:?}"
    );
}

#[test]
fn protocol_version_mismatch_is_rejected() {
    // A "future" initiator speaking version 99.
    let (ta, tb) = MemoryTransport::pair();
    let identity = DeviceIdentity::generate();
    // pA frame with bogus version byte: [0x01, 99, ...]
    let frame = [0x01u8, 99, 4, 0];
    ta.send(&frame).unwrap();
    let err = match accept("K7Q2M4", &identity, tb as Arc<dyn Transport>) {
        Err(err) => err,
        Ok(_) => panic!("must reject mismatched protocol version"),
    };
    assert!(matches!(err, PairingError::Protocol(ref m) if m.contains("version mismatch")));
}

#[test]
fn session_keys_and_group_ids_match_on_both_sides() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let ib2 = ib.clone();
    std::thread::scope(|s| {
        let h_b = s.spawn({
            let tb = tb.clone();
            move || accept("SYNC77", &ib2, tb as Arc<dyn Transport>)
        });
        let sa = pair("SYNC77", &ia, ta as Arc<dyn Transport>).expect("initiator");
        let sb = h_b.join().expect("responder thread").expect("responder");

        assert_eq!(sa.group_id, sb.group_id);
        assert_eq!(sa.session_key, sb.session_key);
        assert_eq!(sa.peer_identity.public_key, ib.public_key);
        assert_eq!(sb.peer_identity.public_key, ia.public_key);
        assert_eq!(sa.peer_identity.device_id, ib.device_id);
        drop((sa, sb));
    });
}

#[test]
fn invalid_code_format_is_rejected_before_any_exchange() {
    let (ta, tb) = MemoryTransport::pair();
    let identity = DeviceIdentity::generate();
    let err = match pair("00O!1", &identity, ta.clone() as Arc<dyn Transport>) {
        Err(err) => err,
        Ok(_) => panic!("must reject malformed code"),
    };
    assert!(matches!(err, PairingError::Protocol(ref m) if m.contains("format")));
    MemoryTransport::close_pair(&ta, &tb);
}

#[test]
fn code_single_use_is_enforced() {
    let mut board = PairingCodeBoard::new(PairingPolicy::default());
    let code = board.issue();
    board.consume(&code).expect("first consume");
    assert_eq!(board.consume(&code), Err(CodeError::AlreadyUsed));
    assert!(!board.is_accepting(&code));
}

#[test]
fn lowercase_code_matches_stored_uppercase() {
    let mut board = PairingCodeBoard::new(PairingPolicy::default());
    let code = board.issue();
    let lower = code.to_lowercase();
    // validate_format accepts lower case; consume/register_failure must too.
    assert!(PairingCodeBoard::validate_format(&lower).is_ok());
    assert!(board.is_accepting(&lower));
    assert_eq!(board.consume(&lower), Ok(()));
    assert!(!board.is_accepting(&lower));
}

#[test]
fn expired_code_is_rejected() {
    // Clock: calls 1..=2 see t0 (issue + consume within TTL), later calls
    // see t0 + 2s (past the 1s TTL).
    let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let board_clock = {
        let calls = calls.clone();
        move || {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let base = Instant::now();
            // Call 1 is the issue; every later call sees a time past the TTL.
            base + if n > 1 {
                Duration::from_secs(5)
            } else {
                Duration::ZERO
            }
        }
    };
    let mut board = PairingCodeBoard::with_clock(
        PairingPolicy {
            ttl_ms: 1_000,
            max_attempts: 3,
        },
        Box::new(board_clock),
    );
    let code = board.issue(); // call 1: inside TTL
    assert_eq!(board.consume(&code), Err(CodeError::Expired)); // call 2: past TTL
}

#[test]
fn too_many_failed_attempts_locks_the_code_window() {
    let mut board = PairingCodeBoard::new(PairingPolicy {
        ttl_ms: 60_000,
        max_attempts: 2,
    });
    let code = board.issue();
    assert!(board.register_failure(&code).is_ok());
    assert!(board.register_failure(&code).is_ok());
    assert_eq!(
        board.register_failure(&code),
        Err(CodeError::TooManyAttempts)
    );
    assert_eq!(board.register_failure("NOPE12"), Err(CodeError::Unknown));
}

#[test]
fn session_invalidation_blocks_further_traffic() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    std::thread::scope(|s| {
        let h_b = s.spawn({
            let tb = tb.clone();
            move || accept("RQ7Y9K", &ib, tb as Arc<dyn Transport>)
        });
        let sa = pair("RQ7Y9K", &ia, ta as Arc<dyn Transport>).expect("initiator");
        let sb = h_b.join().unwrap().expect("responder");
        sb.invalidate();
        let err = sb.seal_and_send(b"payload").unwrap_err();
        assert!(matches!(err, PairingError::Protocol(ref m) if m.contains("invalidated")));
        drop(sa);
    });
}
