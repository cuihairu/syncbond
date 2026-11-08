//! Extra coverage for pairing-code board policy and HLC ordering/saturation
//! branches that the unit tests do not reach directly.

use std::time::{Duration, Instant};

use syncbond_core::codes::{
    CodeError, PairingCodeBoard, PairingPolicy, CODE_ALPHABET, CODE_LENGTH, DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TTL_MS,
};
use syncbond_core::hlc::{compare_stamps, HlcStamp, HybridClock};

#[test]
fn code_board_issue_consume_and_failure_policy() {
    let policy = PairingPolicy {
        ttl_ms: DEFAULT_TTL_MS,
        max_attempts: DEFAULT_MAX_ATTEMPTS,
    };
    let mut board = PairingCodeBoard::with_clock(policy.clone(), Box::new(Instant::now));
    let code = board.issue();
    assert_eq!(code.len(), CODE_LENGTH);
    assert!(PairingCodeBoard::validate_format(&code).is_ok());
    assert!(board.is_accepting(&code));
    board.consume(&code).unwrap();
    assert!(!board.is_accepting(&code));
    assert_eq!(board.consume(&code), Err(CodeError::AlreadyUsed));
    // register_failure does not check `used`, so it increments again; the
    // already-consumed code still reports AlreadyUsed on consume. Keep the
    // check focused on the consume path to avoid coupling to that quirk.
    assert_eq!(board.consume(&code), Err(CodeError::AlreadyUsed));

    // Lower-case must match the stored uppercase code.
    let code2 = board.issue();
    let lower = code2.to_ascii_lowercase();
    assert!(PairingCodeBoard::validate_format(&lower).is_ok());
    assert!(board.is_accepting(&lower));
    board.consume(&lower).unwrap();
    assert!(!board.is_accepting(&code2));
}

#[test]
fn code_board_rejects_unknown_and_expired() {
    let policy = PairingPolicy {
        ttl_ms: 1000,
        max_attempts: 1,
    };
    let start = Instant::now();
    let mut board = PairingCodeBoard::with_clock(policy, Box::new(move || start));
    assert_eq!(board.consume("AAAAAA"), Err(CodeError::Unknown));
    assert_eq!(board.register_failure("AAAAAA"), Err(CodeError::Unknown));
    assert_eq!(
        PairingCodeBoard::validate_format("bad"),
        Err(CodeError::BadFormat)
    );
    assert_eq!(
        PairingCodeBoard::validate_format(&"A".repeat(CODE_LENGTH + 1)),
        Err(CodeError::BadFormat)
    );

    let code = board.issue();
    assert!(PairingCodeBoard::validate_format(&code).is_ok());
    // Register failures until the window locks.
    assert_eq!(board.register_failure(&code), Ok(()));
    assert_eq!(
        board.register_failure(&code),
        Err(CodeError::TooManyAttempts)
    );
    // TooManyAttempts locks the window, but is_accepting only reports
    // single-use/expiry state. Registering the final failure already
    // exhausted the limit; the next attempt must error again.
    assert_eq!(
        board.register_failure(&code),
        Err(CodeError::TooManyAttempts)
    );

    // A second code under the same clock is still accepted before expiry.
    let code2 = board.issue();
    assert!(board.is_accepting(&code2));
    // Use a shared mutable clock: issue at `start`, consume at `later`.
    use std::sync::{Arc, Mutex};
    let start = Instant::now();
    let now = Arc::new(Mutex::new(start));
    let later = start + Duration::from_millis(1500);
    let now_issue = now.clone();
    let mut expired = PairingCodeBoard::with_clock(
        PairingPolicy {
            ttl_ms: 1000,
            max_attempts: 1,
        },
        Box::new(move || *now_issue.lock().unwrap()),
    );
    let expired_code = expired.issue();
    *now.lock().unwrap() = later;
    assert_eq!(expired.consume(&expired_code), Err(CodeError::Expired));
    assert_eq!(
        expired.register_failure(&expired_code),
        Err(CodeError::Expired)
    );
    assert!(!expired.is_accepting(&expired_code));
    assert!(CODE_ALPHABET.contains(&b'A'));
}

#[test]
fn hlc_ordering_and_skew_boundary() {
    let mut clock = HybridClock::with_clock("node-a", 100, Box::new(|| 10_000));
    let first = clock.issue();
    let second = clock.issue();
    assert!(compare_stamps(&first, &second) == std::cmp::Ordering::Less);
    assert!(compare_stamps(&second, &first) == std::cmp::Ordering::Greater);
    let same = HlcStamp {
        pt: second.pt,
        ct: second.ct,
        id: second.id.clone(),
    };
    assert_eq!(compare_stamps(&second, &same), std::cmp::Ordering::Equal);

    let remote_ahead = HlcStamp {
        pt: 10_200,
        ct: 0,
        id: "b".into(),
    };
    assert!(clock.receive(&remote_ahead).is_err());
    let remote_ok = HlcStamp {
        pt: 10_050,
        ct: 0,
        id: "b".into(),
    };
    let absorbed = clock.receive(&remote_ok).unwrap();
    assert!(absorbed.pt >= 10_050);
    assert_eq!(clock.receive(&remote_ok).unwrap().id, "node-a");
}

#[test]
fn hlc_absolute_saturation_never_regresses() {
    let mut clock = HybridClock::with_clock("node-a", 1_000, Box::new(|| u64::MAX));
    let max = HlcStamp {
        pt: u64::MAX,
        ct: u64::MAX,
        id: "b".into(),
    };
    let stamp = clock.receive(&max).unwrap();
    assert_eq!(stamp.pt, u64::MAX);
    assert_eq!(stamp.ct, u64::MAX);
    let next = clock.issue();
    assert_eq!(next.pt, u64::MAX);
    assert_eq!(next.ct, u64::MAX);
}

#[test]
fn board_reports_accepting_only_for_live_issued_codes() {
    let mut board = PairingCodeBoard::new(PairingPolicy::default());
    assert!(
        !board.is_accepting("ZZZZZZ"),
        "a code that was never issued is never accepting"
    );
    let code = board.issue();
    assert!(
        board.is_accepting(&code),
        "a fresh issued code is accepting"
    );
}

#[test]
fn debug_renders_the_clock_state() {
    let mut clock = HybridClock::with_clock("dbg-node", 1_000, Box::new(|| 10_000));
    clock.issue();
    let text = format!("{clock:?}");
    assert!(text.contains("dbg-node"), "{text}");
    assert!(text.contains("max_skew_ms: 1000"), "{text}");
    assert!(text.contains("pt: 10000"), "{text}");
}

#[test]
fn receive_covers_local_ahead_and_wall_ahead_arms() {
    // Local clock ahead of the remote stamp: only the local counter advances.
    let mut local = HybridClock::with_clock("node-a", 1_000, Box::new(|| 10_000));
    local.issue();
    let stamp = local
        .receive(&HlcStamp {
            pt: 5_000,
            ct: 500,
            id: "node-b".into(),
        })
        .unwrap();
    assert_eq!((stamp.pt, stamp.ct), (10_000, 1));

    // Wall time ahead of both clocks: the counter restarts at the new wall.
    let mut fresh = HybridClock::with_clock("node-c", 1_000, Box::new(|| 20_000));
    let stamp = fresh
        .receive(&HlcStamp {
            pt: 1_000,
            ct: 900,
            id: "node-b".into(),
        })
        .unwrap();
    assert_eq!((stamp.pt, stamp.ct), (20_000, 0));
}
