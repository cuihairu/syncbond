//! Extra handle-layer coverage: direct PairResult with an explicit code,
//! strategy selection, decode_b64url errors, dump helpers, and the error
//! mapping from crypto failures.

use syncbond_ffi::error::FfiError;
use syncbond_ffi::handles::{decode_b64url, dump_node, dump_record, Identity, Keyring, PairResult, Replicator, Session};
use syncbond_core::crypto::CryptoError;
use syncbond_core::replication::Replicator as CoreReplicator;
use syncbond_core::transport::TransportError;

#[test]
fn explicit_pair_code_and_error_mappings() {
    let pair = PairResult::memory(Some("ABCDEF")).unwrap();
    assert_eq!(pair.code, "ABCDEF");
    let initiator = Session(pair.initiator.clone());
    let responder = Session(pair.responder.clone());
    assert!(!initiator.group_id().is_empty());
    assert_eq!(initiator.peer_device_id().len(), 16);
    assert!(!initiator.invalidated());
    initiator.send(b"x").unwrap();
    responder.invalidate();
    assert!(responder.invalidated());
    // After invalidation, the paired in-memory transport blocks on further
    // send/recv, so we deliberately do not issue any more traffic.
    assert!(PairResult::memory(Some("")).is_err());
}

#[test]
fn decode_b64url_round_trip_and_errors() {
    assert_eq!(decode_b64url("YQ").unwrap(), b"a");
    assert!(decode_b64url("!").is_err());
}

#[test]
fn strategy_selector_covers_all_codes() {
    for code in [0, 1, 2] {
        assert!(Replicator::strategy(code).is_ok());
    }
    assert!(Replicator::strategy(99).is_err());
}

#[test]
fn dump_helpers_render_records_and_nodes() {
    let mut rep = CoreReplicator::with_fixed_clock("node", std::sync::Arc::new(syncbond_core::conflict::LwwHlc), 1_000);
    rep.put("k", b"v".to_vec()).unwrap();
    let node = dump_node(&rep);
    assert!(node.get("records").is_some());
    assert!(node.get("live_keys").is_some());
    let record = rep.records_snapshot().into_iter().next().unwrap().1;
    let dumped = dump_record(&record);
    assert!(dumped.get("payload").is_some());
    assert!(dumped.get("conflicts").is_some());
    assert!(dumped.get("witness").is_some());
}

#[test]
fn error_codes_map_from_crypto_and_pairing() {
    let crypto = CryptoError::AuthenticationFailed;
    assert_eq!(FfiError::crypto(&crypto).code, -7);
    let pairing = syncbond_core::pairing::PairingError::Protocol("bad".into());
    let ffi: FfiError = pairing.into();
    assert_eq!(ffi.code, -1);
    let replay = syncbond_core::pairing::PairingError::Crypto(CryptoError::Replay("x".into()));
    let ffi: FfiError = replay.into();
    assert_eq!(ffi.code, -6);
    let rep = syncbond_core::replication::ReplicationError::Crypto(CryptoError::VersionMismatch {
        got: 1,
        expected: 2,
    });
    let ffi: FfiError = rep.into();
    assert_eq!(ffi.code, -3);
    let _ = TransportError::Closed;
    let _ = Identity::generate();
    let _ = Keyring::new("g");
}

#[test]
fn keyring_import_rejects_short_key() {
    let result = Keyring::import("g", 1, &[0u8; 8]);
    assert!(result.is_err());
}
