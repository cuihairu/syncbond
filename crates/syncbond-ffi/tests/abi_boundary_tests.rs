//! Direct ABI boundary tests: every export is exercised from Rust so the C
//! surface's null checks, error codes and buffer ownership are pinned without
//! needing a foreign-language harness.

use std::ffi::{CStr, CString};
use syncbond_ffi::abi::*;
use syncbond_ffi::error::{
    SB_ERR_INPUT, SB_ERR_INTERNAL, SB_ERR_NONE, SB_ERR_PROTOCOL, SB_ERR_VERSION_MISMATCH,
    SB_PAIR_EVENT_COMPLETED, SB_PAIR_EVENT_NONE, SB_PAIR_ROLE_INITIATOR, SB_PAIR_ROLE_RESPONDER,
    SB_RESULT_ABSENT,
};
use syncbond_ffi::sb_pair_end;
use syncbond_ffi::sb_receive_state;
use syncbond_ffi::sb_replicator;

fn string(ptr: *const std::ffi::c_char) -> String {
    if ptr.is_null() {
        panic!("null string returned");
    }
    let owned = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    sb_free_string(ptr);
    owned
}

#[test]
fn version_queries_are_stable() {
    assert_eq!(sb_abi_version(), 1);
    assert_eq!(sb_protocol_version(), 1);
    assert_eq!(sb_last_error_code(), SB_ERR_NONE);
    assert!(sb_last_error().is_null());
    sb_free_string(std::ptr::null());
    unsafe { sb_free_buffer(std::ptr::null()) };
    let zero = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    unsafe { sb_free_buffer(&zero) };
}

#[test]
fn identity_boundary() {
    let identity = sb_identity_generate();
    assert!(!identity.is_null());
    let device_id = string(unsafe { sb_identity_device_id(identity) });
    assert_eq!(device_id.len(), 16);
    let mut public = [0u8; 32];
    assert_eq!(
        unsafe { sb_identity_public_key(identity, public.as_mut_ptr()) },
        SB_ERR_NONE
    );
    let mut secret = [0u8; 64];
    assert_eq!(
        unsafe { sb_identity_secret_key(identity, secret.as_mut_ptr()) },
        SB_ERR_NONE
    );
    let imported = unsafe { sb_identity_import(secret.as_ptr(), 64) };
    assert!(!imported.is_null());
    assert_eq!(
        string(unsafe { sb_identity_device_id(imported) }),
        device_id
    );
    unsafe { sb_identity_free(identity) };
    unsafe { sb_identity_free(imported) };

    assert!(unsafe { sb_identity_import(std::ptr::null(), 0) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert!(unsafe { sb_identity_import(secret.as_ptr(), 8) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert!(unsafe { sb_identity_device_id(std::ptr::null()) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert_eq!(
        unsafe { sb_identity_public_key(std::ptr::null(), public.as_mut_ptr()) },
        SB_ERR_INTERNAL
    );
    assert_eq!(
        unsafe { sb_identity_public_key(identity, std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_identity_secret_key(std::ptr::null(), secret.as_mut_ptr()) },
        SB_ERR_INTERNAL
    );
    assert_eq!(
        unsafe { sb_identity_secret_key(identity, std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    unsafe { sb_identity_free(std::ptr::null_mut()) };
}

#[test]
fn pairing_boundary() {
    let pair = unsafe { sb_pair_memory(std::ptr::null()) };
    assert!(!pair.is_null());
    assert!(!string(unsafe { sb_pair_result_code(pair) }).is_empty());
    let initiator = unsafe { sb_pair_result_initiator(pair) };
    let responder = unsafe { sb_pair_result_responder(pair) };
    assert!(!initiator.is_null() && !responder.is_null());
    assert_eq!(
        string(unsafe { sb_session_group_id(initiator) }),
        string(unsafe { sb_session_group_id(responder) })
    );
    let initiator_peer = string(unsafe { sb_session_peer_device_id(initiator) });
    let responder_peer = string(unsafe { sb_session_peer_device_id(responder) });
    assert_eq!(initiator_peer.len(), 16);
    assert_eq!(responder_peer.len(), 16);
    assert_ne!(initiator_peer, responder_peer);
    assert_eq!(
        string(unsafe { sb_session_group_id(initiator) }),
        string(unsafe { sb_session_group_id(responder) })
    );
    assert_eq!(
        string(unsafe { sb_session_group_id(initiator) }),
        string(unsafe { sb_session_group_id(responder) })
    );
    assert_eq!(unsafe { sb_session_invalidated(initiator) }, 0);
    let payload = b"hello";
    assert_eq!(
        unsafe { sb_session_send(initiator, payload.as_ptr(), payload.len()) },
        SB_ERR_NONE
    );
    let mut out = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(unsafe { sb_session_recv(responder, &mut out) }, SB_ERR_NONE);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(out.data, out.len) },
        b"hello"
    );
    unsafe { sb_free_buffer(&out) };
    assert_eq!(unsafe { sb_session_invalidate(initiator) }, SB_ERR_NONE);
    assert_eq!(unsafe { sb_session_invalidated(initiator) }, 1);
    unsafe { sb_session_free(initiator) };
    unsafe { sb_session_free(responder) };
    unsafe { sb_pair_result_free(pair) };

    let empty = CString::new("").unwrap();
    assert!(unsafe { sb_pair_memory(empty.as_ptr()) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert_eq!(
        unsafe { sb_session_send(std::ptr::null(), payload.as_ptr(), payload.len()) },
        SB_ERR_INTERNAL
    );
    assert_eq!(
        unsafe { sb_session_send(initiator, std::ptr::null(), 1) },
        SB_ERR_INTERNAL
    );
    assert_eq!(
        unsafe { sb_session_recv(std::ptr::null(), &mut out) },
        SB_ERR_INTERNAL
    );
    let out2 = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe { sb_session_recv(responder, std::ptr::null_mut()) },
        SB_ERR_INTERNAL
    );
    unsafe { sb_free_buffer(&out2) };
    assert!(unsafe { sb_session_group_id(std::ptr::null()) }.is_null());
    assert!(unsafe { sb_session_peer_device_id(std::ptr::null()) }.is_null());
    assert_eq!(
        unsafe { sb_session_invalidated(std::ptr::null()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_session_invalidate(std::ptr::null()) },
        SB_ERR_INPUT
    );
    unsafe { sb_session_free(std::ptr::null_mut()) };
    unsafe { sb_pair_result_free(std::ptr::null_mut()) };
}

/// One wire round over raw handles: drain both outboxes, hand every frame to
/// the other end unless that end already finished (a finished end refuses
/// frames, so the host stops feeding it), and report whether both ends
/// reached a terminal transition.
fn pair_end_round(a: *mut sb_pair_end, b: *mut sb_pair_end) -> bool {
    let mut out = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let mut to_b = Vec::new();
    let mut to_a = Vec::new();
    while unsafe { sb_pair_end_pop_outgoing(a, &mut out) } == SB_ERR_NONE {
        to_b.push(unsafe { std::slice::from_raw_parts(out.data, out.len) }.to_vec());
        unsafe { sb_free_buffer(&out) };
    }
    while unsafe { sb_pair_end_pop_outgoing(b, &mut out) } == SB_ERR_NONE {
        to_a.push(unsafe { std::slice::from_raw_parts(out.data, out.len) }.to_vec());
        unsafe { sb_free_buffer(&out) };
    }
    for frame in to_b {
        if unsafe { sb_pair_end_is_finished(b) } == 0 {
            assert_eq!(
                unsafe { sb_pair_end_push(b, frame.as_ptr(), frame.len()) },
                SB_ERR_NONE,
                "a live end accepts frames"
            );
        }
    }
    for frame in to_a {
        if unsafe { sb_pair_end_is_finished(a) } == 0 {
            assert_eq!(
                unsafe { sb_pair_end_push(a, frame.as_ptr(), frame.len()) },
                SB_ERR_NONE,
                "a live end accepts frames"
            );
        }
    }
    unsafe { sb_pair_end_is_finished(a) == 1 && sb_pair_end_is_finished(b) == 1 }
}

#[test]
fn pair_end_boundary() {
    let code = CString::new("K7Q2M4").unwrap();
    let ia = sb_identity_generate();
    let ib = sb_identity_generate();
    let initiator = unsafe { sb_pair_end_new(ia, SB_PAIR_ROLE_INITIATOR, code.as_ptr()) };
    let responder = unsafe { sb_pair_end_new(ib, SB_PAIR_ROLE_RESPONDER, code.as_ptr()) };
    assert!(!initiator.is_null() && !responder.is_null());

    // The initiator opens with pA at once; the responder is silent until it.
    let mut out = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe { sb_pair_end_pop_outgoing(initiator, &mut out) },
        SB_ERR_NONE
    );
    assert_eq!(unsafe { *out.data }, 0x01, "pA is the first frame");
    assert_eq!(
        unsafe { sb_pair_end_pop_outgoing(responder, &mut out) },
        SB_RESULT_ABSENT,
        "the responder emits nothing before pA"
    );
    assert_eq!(
        unsafe { sb_pair_end_push(responder, out.data, out.len) },
        SB_ERR_NONE
    );
    unsafe { sb_free_buffer(&out) };

    // Drive to the terminal transition: at most six protocol frames.
    let mut rounds = 0;
    while !pair_end_round(initiator, responder) {
        rounds += 1;
        assert!(rounds <= 6, "the exchange wedged after {rounds} rounds");
    }
    assert_eq!(
        unsafe { sb_pair_end_poll(initiator) },
        SB_PAIR_EVENT_COMPLETED
    );
    assert_eq!(
        unsafe { sb_pair_end_poll(responder) },
        SB_PAIR_EVENT_COMPLETED
    );
    assert_eq!(
        unsafe { sb_pair_end_poll(initiator) },
        SB_PAIR_EVENT_NONE,
        "polling is one-shot"
    );
    assert!(unsafe { sb_pair_end_failure(initiator) }.is_null());

    // The sessions hand over, agree on the group and cross-match the peers.
    let session_a = unsafe { sb_pair_end_take_session(initiator) };
    let session_b = unsafe { sb_pair_end_take_session(responder) };
    assert!(!session_a.is_null() && !session_b.is_null());
    assert_eq!(
        string(unsafe { sb_session_group_id(session_a) }),
        string(unsafe { sb_session_group_id(session_b) })
    );
    let ida = string(unsafe { sb_identity_device_id(ia) });
    let idb = string(unsafe { sb_identity_device_id(ib) });
    assert_eq!(string(unsafe { sb_session_peer_device_id(session_a) }), idb);
    assert_eq!(string(unsafe { sb_session_peer_device_id(session_b) }), ida);
    assert!(
        unsafe { sb_pair_end_take_session(initiator) }.is_null(),
        "the session hands over once"
    );

    // A finished end refuses a late frame: a host bug, mapped to the
    // protocol code rather than a peer violation.
    let late = [0x01u8, 1];
    assert_eq!(
        unsafe { sb_pair_end_push(initiator, late.as_ptr(), late.len()) },
        SB_ERR_PROTOCOL
    );

    // Argument and null handling: every entry point fails closed with the
    // input code before any frame exists. (Kept before the frees below: the
    // handles are still live here.)
    let mistyped = CString::new("K7Q2M!").unwrap();
    assert!(unsafe { sb_pair_end_new(ia, 42, code.as_ptr()) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert!(unsafe { sb_pair_end_new(ia, SB_PAIR_ROLE_INITIATOR, mistyped.as_ptr()) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert!(
        unsafe { sb_pair_end_new(std::ptr::null(), SB_PAIR_ROLE_INITIATOR, code.as_ptr()) }
            .is_null()
    );
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert_eq!(
        unsafe { sb_pair_end_pop_outgoing(std::ptr::null_mut(), &mut out) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_pair_end_pop_outgoing(initiator, std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    // A null frame is a caller error: the return carries the entry point's
    // fallback code, the precise SB_ERR_INPUT lands in the error slot.
    assert_eq!(
        unsafe { sb_pair_end_push(initiator, std::ptr::null(), 1) },
        SB_ERR_PROTOCOL
    );
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert_eq!(
        unsafe { sb_pair_end_poll(std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_pair_end_abort(std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_pair_end_is_finished(std::ptr::null()) },
        SB_ERR_INPUT
    );
    assert!(unsafe { sb_pair_end_failure(std::ptr::null()) }.is_null());
    assert!(unsafe { sb_pair_end_take_session(std::ptr::null_mut()) }.is_null());
    unsafe { sb_pair_end_free(std::ptr::null_mut()) };

    unsafe { sb_session_free(session_a) };
    unsafe { sb_session_free(session_b) };
    unsafe { sb_pair_end_free(initiator) };
    unsafe { sb_pair_end_free(responder) };
    unsafe { sb_identity_free(ia) };
    unsafe { sb_identity_free(ib) };
}

#[test]
fn replicator_boundary() {
    let id = CString::new("node-a").unwrap();
    let replicator = unsafe { sb_replicator_new_fixed_clock(id.as_ptr(), 0, 1_000) };
    assert!(!replicator.is_null());
    assert_eq!(
        string(unsafe { sb_replicator_node_id(replicator) }),
        "node-a"
    );
    assert_eq!(unsafe { sb_replicator_record_count(replicator) }, 0);
    assert_eq!(unsafe { sb_replicator_oplog_len(replicator) }, 0);
    let key = CString::new("k").unwrap();
    let payload = b"value";
    assert_eq!(
        unsafe { sb_replicator_put(replicator, key.as_ptr(), payload.as_ptr(), payload.len()) },
        SB_ERR_NONE
    );
    assert_eq!(unsafe { sb_replicator_record_count(replicator) }, 1);
    assert_eq!(unsafe { sb_replicator_oplog_len(replicator) }, 1);
    let mut out = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe { sb_replicator_get(replicator, key.as_ptr(), &mut out) },
        SB_ERR_NONE
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(out.data, out.len) },
        b"value"
    );
    unsafe { sb_free_buffer(&out) };
    let missing = CString::new("missing").unwrap();
    let mut absent = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe { sb_replicator_get(replicator, missing.as_ptr(), &mut absent) },
        SB_RESULT_ABSENT
    );
    unsafe { sb_free_buffer(&absent) };
    assert!(string(unsafe { sb_replicator_live_keys_json(replicator) }).contains("k"));
    assert!(string(unsafe { sb_replicator_op_json(replicator, 0) }).contains("k"));
    assert!(string(unsafe { sb_replicator_records_json(replicator) }).contains("k"));
    assert!(string(unsafe { sb_replicator_gc_barriers_json(replicator) }).contains('{'));
    assert_eq!(
        unsafe { sb_replicator_delete(replicator, key.as_ptr()) },
        SB_ERR_NONE
    );
    let mut absent2 = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe { sb_replicator_get(replicator, key.as_ptr(), &mut absent2) },
        SB_RESULT_ABSENT
    );
    unsafe { sb_free_buffer(&absent2) };
    assert!(unsafe { sb_replicator_gc_tombstones(replicator, 2000, 500) } >= 0);
    let op = string(unsafe { sb_replicator_op_json(replicator, 0) });
    let op_c = CString::new(op).unwrap();
    assert_eq!(
        unsafe { sb_replicator_apply_remote_json(replicator, op_c.as_ptr()) },
        0
    );
    unsafe { sb_replicator_free(replicator) };

    let empty = CString::new("").unwrap();
    assert!(unsafe { sb_replicator_new(empty.as_ptr(), 0) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert!(unsafe { sb_replicator_new(id.as_ptr(), 99) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert!(unsafe { sb_replicator_new(std::ptr::null(), 0) }.is_null());
    assert!(unsafe { sb_replicator_node_id(std::ptr::null()) }.is_null());
    assert_eq!(unsafe { sb_replicator_record_count(std::ptr::null()) }, 0);
    assert_eq!(unsafe { sb_replicator_oplog_len(std::ptr::null()) }, 0);
    assert_eq!(
        unsafe {
            sb_replicator_put(
                std::ptr::null_mut(),
                key.as_ptr(),
                payload.as_ptr(),
                payload.len(),
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_replicator_delete(std::ptr::null_mut(), key.as_ptr()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_replicator_get(std::ptr::null(), key.as_ptr(), &mut out) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_replicator_get(replicator, key.as_ptr(), std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert!(unsafe { sb_replicator_live_keys_json(std::ptr::null()) }.is_null());
    assert!(unsafe { sb_replicator_op_json(std::ptr::null(), 0) }.is_null());
    assert_eq!(
        unsafe { sb_replicator_apply_remote_json(std::ptr::null_mut(), op_c.as_ptr()) },
        SB_ERR_INTERNAL
    );
    let mut sent = 0u32;
    assert_eq!(
        unsafe { sb_replicator_sync(std::ptr::null_mut(), std::ptr::null_mut(), 0, &mut sent) },
        SB_ERR_INTERNAL
    );
    assert!(unsafe { sb_replicator_records_json(std::ptr::null()) }.is_null());
    assert!(unsafe { sb_replicator_gc_barriers_json(std::ptr::null()) }.is_null());
    assert_eq!(
        unsafe { sb_replicator_gc_tombstones(std::ptr::null_mut(), 1, 1) },
        SB_ERR_INTERNAL
    );
    unsafe { sb_replicator_free(std::ptr::null_mut()) };
}

#[test]
fn keyring_and_conformance_boundary() {
    let group = CString::new("group").unwrap();
    let keyring = unsafe { sb_keyring_new(group.as_ptr()) };
    assert!(!keyring.is_null());
    assert_eq!(unsafe { sb_keyring_epoch(keyring) }, 1);
    let mut epoch = 0u64;
    let mut key = [0u8; 32];
    assert_eq!(
        unsafe { sb_keyring_rotate(keyring, &mut epoch, key.as_mut_ptr()) },
        SB_ERR_NONE
    );
    assert_eq!(epoch, 2);
    let sender = CString::new("device").unwrap();
    let plaintext = b"secret";
    let envelope = string(unsafe {
        sb_keyring_seal_json(
            keyring,
            sender.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
        )
    });
    let envelope_c = CString::new(envelope).unwrap();
    let mut out = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe { sb_keyring_open_json(keyring, envelope_c.as_ptr(), &mut out) },
        SB_ERR_NONE
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(out.data, out.len) },
        b"secret"
    );
    unsafe { sb_free_buffer(&out) };
    assert_eq!(
        unsafe { sb_keyring_open_json(keyring, envelope_c.as_ptr(), &mut out) },
        SB_ERR_INTERNAL
    );
    assert_eq!(sb_last_error_code(), -6);
    let bad = CString::new("{bad").unwrap();
    assert_eq!(
        unsafe { sb_keyring_open_json(keyring, bad.as_ptr(), &mut out) },
        SB_ERR_INTERNAL
    );
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert_eq!(
        unsafe { sb_keyring_rotate(keyring, std::ptr::null_mut(), key.as_mut_ptr()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_keyring_rotate(keyring, &mut epoch, std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert!(unsafe {
        sb_keyring_seal_json(
            std::ptr::null(),
            sender.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
        )
    }
    .is_null());
    assert_eq!(
        unsafe { sb_keyring_open_json(std::ptr::null(), envelope_c.as_ptr(), &mut out) },
        SB_ERR_INTERNAL
    );
    assert_eq!(
        unsafe { sb_keyring_open_json(keyring, std::ptr::null(), &mut out) },
        SB_ERR_INTERNAL
    );
    assert_eq!(
        unsafe { sb_keyring_open_json(keyring, envelope_c.as_ptr(), std::ptr::null_mut()) },
        SB_ERR_INTERNAL
    );
    unsafe { sb_keyring_free(keyring) };

    let imported = unsafe { sb_keyring_import(group.as_ptr(), 3, key.as_ptr()) };
    assert!(!imported.is_null());
    assert_eq!(unsafe { sb_keyring_epoch(imported) }, 3);
    assert!(unsafe { sb_keyring_import(group.as_ptr(), 1, std::ptr::null()) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    let short = [0u8; 8];
    let short_keyring = unsafe { sb_keyring_import(group.as_ptr(), 1, short.as_ptr()) };
    assert!(!short_keyring.is_null());
    unsafe { sb_keyring_free(short_keyring) };
    let second = unsafe { sb_keyring_import(group.as_ptr(), 1, key.as_ptr()) };
    assert!(!second.is_null());
    assert_eq!(unsafe { sb_keyring_epoch(second) }, 1);
    unsafe { sb_keyring_free(imported) };
    unsafe { sb_keyring_free(second) };
    assert!(unsafe { sb_keyring_new(std::ptr::null()) }.is_null());
    assert_eq!(unsafe { sb_keyring_epoch(std::ptr::null()) }, 0);

    let fixture = CString::new(r#"{"version":1,"scenarios":[]}"#).unwrap();
    let report = string(unsafe { sb_conformance_run(fixture.as_ptr()) });
    assert!(report.contains("\"ok\":true"));
    let bad = CString::new("{bad").unwrap();
    assert!(unsafe { sb_conformance_run(bad.as_ptr()) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    assert!(unsafe { sb_conformance_run(std::ptr::null()) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    unsafe { sb_keyring_free(std::ptr::null_mut()) };
}

#[test]
fn state_snapshot_boundary() {
    let node = CString::new("node-a").unwrap();
    let group = CString::new("group-9").unwrap();
    let replicator = unsafe { sb_replicator_new(node.as_ptr(), 0) };
    assert!(!replicator.is_null());
    let identity = sb_identity_generate();
    let receive = sb_receive_state_new();
    assert!(!receive.is_null());
    let server = CString::new("relay-1").unwrap();
    let channel = CString::new("channel-a").unwrap();
    let source = CString::new("node-b").unwrap();
    let seen = CString::new("msg-1").unwrap();
    assert_eq!(
        unsafe { sb_receive_state_server_cursor(receive, server.as_ptr(), channel.as_ptr(), 9) },
        SB_ERR_NONE
    );
    assert_eq!(
        unsafe { sb_receive_state_source_cursor(receive, source.as_ptr(), 12) },
        SB_ERR_NONE
    );
    assert_eq!(
        unsafe { sb_receive_state_seen(receive, seen.as_ptr()) },
        SB_ERR_NONE
    );

    // Export the snapshot, then import it back into two fresh handles.
    let mut snapshot = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe {
            sb_state_export(
                replicator,
                identity,
                group.as_ptr(),
                2,
                receive,
                &mut snapshot,
            )
        },
        SB_ERR_NONE
    );
    assert!(snapshot.len > 0);
    let mut restored: *mut sb_replicator = std::ptr::null_mut();
    let mut restored_receive: *mut sb_receive_state = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            sb_state_import(
                snapshot.data,
                snapshot.len,
                0,
                &mut restored,
                &mut restored_receive,
            )
        },
        SB_ERR_NONE
    );
    assert!(!restored.is_null() && !restored_receive.is_null());
    assert_eq!(string(unsafe { sb_replicator_node_id(restored) }), "node-a");
    let mut seq = 0u64;
    assert_eq!(
        unsafe {
            sb_receive_state_server_seq(
                restored_receive,
                server.as_ptr(),
                channel.as_ptr(),
                &mut seq,
            )
        },
        SB_ERR_NONE
    );
    assert_eq!(seq, 9);
    let receive_json = string(unsafe { sb_receive_state_json(restored_receive) });
    assert!(receive_json.contains("relay-1"), "{receive_json}");

    // A wrong version is refused, and the precise code rides the error slot.
    let wrong = CString::new(r#"{"version":999,"state":{},"receive":{}}"#).unwrap();
    let mut bad_rep: *mut sb_replicator = std::ptr::null_mut();
    let mut bad_recv: *mut sb_receive_state = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            sb_state_import(
                wrong.as_ptr() as *const u8,
                wrong.as_bytes().len(),
                0,
                &mut bad_rep,
                &mut bad_recv,
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(sb_last_error_code(), SB_ERR_VERSION_MISMATCH);
    assert!(bad_rep.is_null() && bad_recv.is_null());

    // Truncated and unreadable blobs fail closed with SB_ERR_INPUT.
    assert_eq!(
        unsafe { sb_state_import(std::ptr::null(), 0, 0, &mut bad_rep, &mut bad_recv) },
        SB_ERR_INPUT
    );
    let garbage = CString::new("not a snapshot").unwrap();
    assert_eq!(
        unsafe {
            sb_state_import(
                garbage.as_ptr() as *const u8,
                garbage.as_bytes().len(),
                0,
                &mut bad_rep,
                &mut bad_recv,
            )
        },
        SB_ERR_INPUT
    );

    // Null arguments fail closed without touching the out handles.
    assert_eq!(
        unsafe {
            sb_state_export(
                std::ptr::null(),
                identity,
                group.as_ptr(),
                0,
                receive,
                &mut snapshot,
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_state_export(
                replicator,
                std::ptr::null(),
                group.as_ptr(),
                0,
                receive,
                &mut snapshot,
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_state_export(
                replicator,
                identity,
                group.as_ptr(),
                0,
                std::ptr::null(),
                &mut snapshot,
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_state_export(
                replicator,
                identity,
                std::ptr::null(),
                0,
                receive,
                &mut snapshot,
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_state_export(
                replicator,
                identity,
                group.as_ptr(),
                0,
                receive,
                std::ptr::null_mut(),
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_state_import(
                snapshot.data,
                snapshot.len,
                0,
                std::ptr::null_mut(),
                &mut restored_receive,
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_state_import(
                snapshot.data,
                snapshot.len,
                0,
                &mut restored,
                std::ptr::null_mut(),
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_receive_state_server_cursor(
                std::ptr::null_mut(),
                server.as_ptr(),
                channel.as_ptr(),
                1,
            )
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_receive_state_server_seq(receive, std::ptr::null(), channel.as_ptr(), &mut seq)
        },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe {
            sb_receive_state_server_seq(
                receive,
                server.as_ptr(),
                channel.as_ptr(),
                std::ptr::null_mut(),
            )
        },
        SB_ERR_INPUT
    );
    assert!(unsafe { sb_receive_state_json(std::ptr::null()) }.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);
    // A live handle still answers (it was filled by the earlier export).
    let live_json = unsafe { sb_receive_state_json(receive) };
    assert!(!live_json.is_null());
    sb_free_string(live_json);

    unsafe { sb_free_buffer(&snapshot) };
    unsafe { sb_receive_state_free(receive) };
    unsafe { sb_receive_state_free(restored_receive) };
    unsafe { sb_replicator_free(replicator) };
    unsafe { sb_replicator_free(restored) };
    unsafe { sb_identity_free(identity) };
    unsafe { sb_receive_state_free(std::ptr::null_mut()) };
}

#[cfg(feature = "relay")]
#[test]
fn relay_driver_boundary() {
    use syncbond_ffi::error::{
        SB_DRIVER_STOP_CANCELLED, SB_DRIVER_STOP_NONE, SB_TLS_VALIDATE, SB_TLS_VALIDATE_CA,
    };

    let url = CString::new("http://127.0.0.1:1").unwrap();
    let channel = CString::new("ch").unwrap();
    let token = CString::new("token").unwrap();
    let server = CString::new("relay-1").unwrap();
    let cursor = CString::new("c").unwrap();
    let group = CString::new("g").unwrap();
    let key = CString::new("note/1").unwrap();

    // Failures before ownership transfer keep the handles alive.
    let identity = sb_identity_generate();
    let keyring = unsafe { sb_keyring_new(group.as_ptr()) };
    let replicator = unsafe { sb_replicator_new(CString::new("n").unwrap().as_ptr(), 0) };
    let receive = sb_receive_state_new();
    assert_eq!(
        unsafe {
            sb_relay_driver_new(
                std::ptr::null(),
                channel.as_ptr(),
                token.as_ptr(),
                server.as_ptr(),
                cursor.as_ptr(),
                group.as_ptr(),
                0,
                identity,
                keyring,
                replicator,
                receive,
                100,
                SB_TLS_VALIDATE,
                std::ptr::null(),
                0,
            )
        },
        std::ptr::null_mut()
    );
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);

    // Failures after ownership transfer consume the handles: fresh ones are
    // passed below and never freed by the caller.
    let consumed = unsafe {
        sb_relay_driver_new(
            url.as_ptr(),
            CString::new("").unwrap().as_ptr(),
            token.as_ptr(),
            server.as_ptr(),
            cursor.as_ptr(),
            group.as_ptr(),
            0,
            sb_identity_generate(),
            sb_keyring_new(group.as_ptr()),
            sb_replicator_new(CString::new("n").unwrap().as_ptr(), 0),
            sb_receive_state_new(),
            100,
            SB_TLS_VALIDATE,
            std::ptr::null(),
            0,
        )
    };
    assert!(consumed.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);

    let zero_config = unsafe {
        sb_relay_driver_new(
            url.as_ptr(),
            channel.as_ptr(),
            token.as_ptr(),
            server.as_ptr(),
            cursor.as_ptr(),
            group.as_ptr(),
            0,
            sb_identity_generate(),
            sb_keyring_new(group.as_ptr()),
            sb_replicator_new(CString::new("n").unwrap().as_ptr(), 0),
            sb_receive_state_new(),
            0,
            SB_TLS_VALIDATE,
            std::ptr::null(),
            0,
        )
    };
    assert!(zero_config.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);

    let bad_tls = unsafe {
        sb_relay_driver_new(
            url.as_ptr(),
            channel.as_ptr(),
            token.as_ptr(),
            server.as_ptr(),
            cursor.as_ptr(),
            group.as_ptr(),
            0,
            sb_identity_generate(),
            sb_keyring_new(group.as_ptr()),
            sb_replicator_new(CString::new("n").unwrap().as_ptr(), 0),
            sb_receive_state_new(),
            100,
            9,
            std::ptr::null(),
            0,
        )
    };
    assert!(bad_tls.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);

    let no_ca = unsafe {
        sb_relay_driver_new(
            url.as_ptr(),
            channel.as_ptr(),
            token.as_ptr(),
            server.as_ptr(),
            cursor.as_ptr(),
            group.as_ptr(),
            0,
            sb_identity_generate(),
            sb_keyring_new(group.as_ptr()),
            sb_replicator_new(CString::new("n").unwrap().as_ptr(), 0),
            sb_receive_state_new(),
            100,
            SB_TLS_VALIDATE_CA,
            std::ptr::null(),
            0,
        )
    };
    assert!(no_ca.is_null());
    assert_eq!(sb_last_error_code(), SB_ERR_INPUT);

    unsafe {
        sb_receive_state_free(receive);
        sb_replicator_free(replicator);
        sb_keyring_free(keyring);
        sb_identity_free(identity);
    }

    // A live driver over a dead port: construction succeeds, the queries
    // answer, and the lifecycle is start / stop / free.
    let driver = unsafe {
        sb_relay_driver_new(
            url.as_ptr(),
            channel.as_ptr(),
            token.as_ptr(),
            server.as_ptr(),
            cursor.as_ptr(),
            group.as_ptr(),
            1,
            sb_identity_generate(),
            sb_keyring_new(group.as_ptr()),
            sb_replicator_new(CString::new("local").unwrap().as_ptr(), 0),
            sb_receive_state_new(),
            100,
            SB_TLS_VALIDATE,
            std::ptr::null(),
            0,
        )
    };
    assert!(!driver.is_null());

    // Null handle arguments are input errors.
    assert_eq!(
        unsafe { sb_relay_driver_start(std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_stop(std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_running(std::ptr::null()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_stop_reason(std::ptr::null()) },
        SB_DRIVER_STOP_NONE,
        "the null fallback of stop_reason is NONE"
    );
    assert!(unsafe { sb_relay_driver_error(std::ptr::null()) }.is_null());
    let mut progress = sb_relay_progress_t {
        running: 9,
        cycles: 9,
        sent_batches: 9,
        sent_envelopes: 9,
        pages_pulled: 9,
        applied: 9,
    };
    assert_eq!(
        unsafe { sb_relay_driver_progress(std::ptr::null(), &mut progress) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_progress(driver, std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_get(driver, key.as_ptr(), std::ptr::null_mut()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_export_state(driver, std::ptr::null_mut()) },
        SB_ERR_INPUT
    );

    // Before the first start: no progress, no stop reason, no error text.
    assert_eq!(unsafe { sb_relay_driver_running(driver) }, 0);
    assert_eq!(
        unsafe { sb_relay_driver_stop_reason(driver) },
        SB_DRIVER_STOP_NONE
    );
    assert!(unsafe { sb_relay_driver_error(driver) }.is_null());
    assert_eq!(
        unsafe { sb_relay_driver_progress(driver, &mut progress) },
        SB_ERR_NONE
    );
    assert_eq!(
        (
            progress.running,
            progress.cycles,
            progress.sent_batches,
            progress.sent_envelopes,
            progress.pages_pulled,
            progress.applied
        ),
        (0, 0, 0, 0, 0, 0)
    );

    // Config bounds are validated.
    assert_eq!(
        unsafe { sb_relay_driver_config(driver, 0, 8, 1, 2, 5, 1) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_config(driver, 2, 8, 2, 1, 5, 1) },
        SB_ERR_INPUT,
        "max_backoff below the initial backoff is refused"
    );
    assert_eq!(
        unsafe { sb_relay_driver_config(driver, 2, 8, 1, 2, 1000, 1) },
        SB_ERR_NONE
    );

    // Local writes stage and read back; the key lifecycle is absent-get ->
    // write -> get -> delete -> absent.
    let mut payload = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe { sb_relay_driver_get(driver, key.as_ptr(), &mut payload) },
        SB_RESULT_ABSENT
    );
    assert_eq!(
        unsafe { sb_relay_driver_write(driver, key.as_ptr(), b"one".as_ptr(), 3) },
        SB_ERR_NONE
    );
    assert_eq!(
        unsafe { sb_relay_driver_write(driver, std::ptr::null(), b"one".as_ptr(), 3) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_write(driver, key.as_ptr(), std::ptr::null(), 0) },
        SB_ERR_NONE,
        "an empty payload is a valid write"
    );
    assert_eq!(
        unsafe { sb_relay_driver_get(driver, key.as_ptr(), &mut payload) },
        SB_ERR_NONE
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(payload.data, payload.len) },
        b""
    );
    unsafe { sb_free_buffer(&payload) };
    assert_eq!(
        unsafe { sb_relay_driver_delete(driver, key.as_ptr()) },
        SB_ERR_NONE
    );
    assert_eq!(
        unsafe { sb_relay_driver_delete(driver, std::ptr::null()) },
        SB_ERR_INPUT
    );
    assert_eq!(
        unsafe { sb_relay_driver_get(driver, key.as_ptr(), &mut payload) },
        SB_RESULT_ABSENT,
        "the tombstone wins"
    );

    // The state export is the same snapshot blob sb_state_export writes.
    let mut snapshot = sb_buffer_t {
        data: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(
        unsafe { sb_relay_driver_export_state(driver, &mut snapshot) },
        SB_ERR_NONE
    );
    assert!(snapshot.len > 0);
    let mut restored: *mut sb_replicator = std::ptr::null_mut();
    let mut restored_receive: *mut sb_receive_state = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            sb_state_import(
                snapshot.data,
                snapshot.len,
                0,
                &mut restored,
                &mut restored_receive,
            )
        },
        SB_ERR_NONE
    );
    assert_eq!(string(unsafe { sb_replicator_node_id(restored) }), "local");
    unsafe {
        sb_free_buffer(&snapshot);
        sb_replicator_free(restored);
        sb_receive_state_free(restored_receive);
    }

    // Start: running immediately, a second start is refused, and stop joins.
    assert_eq!(unsafe { sb_relay_driver_start(driver) }, SB_ERR_NONE);
    assert_eq!(unsafe { sb_relay_driver_running(driver) }, 1);
    assert_eq!(unsafe { sb_relay_driver_start(driver) }, SB_ERR_INPUT);
    assert_eq!(unsafe { sb_relay_driver_stop(driver) }, SB_ERR_NONE);
    assert_eq!(unsafe { sb_relay_driver_running(driver) }, 0);
    assert_eq!(
        unsafe { sb_relay_driver_stop_reason(driver) },
        SB_DRIVER_STOP_CANCELLED
    );
    assert!(
        unsafe { sb_relay_driver_error(driver) }.is_null(),
        "a deliberate stop is clean: no error text"
    );
    // Stop is idempotent.
    assert_eq!(unsafe { sb_relay_driver_stop(driver) }, SB_ERR_NONE);

    // A driver may start again after a stop, and freeing a running one
    // stops the worker first (the join must not hang).
    assert_eq!(unsafe { sb_relay_driver_start(driver) }, SB_ERR_NONE);
    assert_eq!(unsafe { sb_relay_driver_running(driver) }, 1);
    unsafe { sb_relay_driver_free(driver) };
    unsafe { sb_relay_driver_free(std::ptr::null_mut()) };
}
