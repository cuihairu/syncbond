//! Direct ABI boundary tests: every export is exercised from Rust so the C
//! surface's null checks, error codes and buffer ownership are pinned without
//! needing a foreign-language harness.

use std::ffi::{CStr, CString};
use syncbond_ffi::abi::*;
use syncbond_ffi::error::{SB_ERR_INPUT, SB_ERR_INTERNAL, SB_ERR_NONE, SB_RESULT_ABSENT};

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
