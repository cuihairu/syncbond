//! The extern "C" surface.
//!
//! Every export funnels through `call()` so that a panic can never unwind
//! into C, records its failure in the thread-local slot behind
//! `sb_last_error()`, and never lets a Rust type cross the boundary. The
//! signatures mirror `include/syncbond.h` one for one.

use std::ffi::{c_char, c_int, CStr, CString};
use std::mem::ManuallyDrop;

use crate::error::{
    set_last_error, FfiError, SB_ERR_INPUT, SB_ERR_INTERNAL, SB_ERR_NONE, SB_RESULT_ABSENT,
};
use crate::handles as h;
use crate::{
    sb_identity, sb_keyring, sb_pair_result, sb_replicator, sb_session, SYNCBOND_ABI_VERSION,
};

/// Byte buffer handed back to the caller; layout matches `sb_buffer_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sb_buffer_t {
    pub data: *mut u8,
    pub len: usize,
    pub cap: usize,
}

/// Run one call with a panic guard and a recorded error.
fn call<T>(fallback: T, body: impl FnOnce() -> Result<T, FfiError>) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(Ok(value)) => {
            set_last_error(None);
            value
        }
        Ok(Err(error)) => {
            set_last_error(Some(error));
            fallback
        }
        Err(_) => {
            set_last_error(Some(FfiError::internal(
                "panic contained at the ffi boundary",
            )));
            fallback
        }
    }
}

/// Borrow a const handle argument.
unsafe fn const_handle<'a, T>(handle: *const T, name: &str) -> Result<&'a T, FfiError> {
    unsafe {
        handle
            .as_ref()
            .ok_or_else(|| FfiError::input(format!("{name} handle must not be null")))
    }
}

/// Borrow a mutable handle argument.
unsafe fn mut_handle<'a, T>(handle: *mut T, name: &str) -> Result<&'a mut T, FfiError> {
    unsafe {
        handle
            .as_mut()
            .ok_or_else(|| FfiError::input(format!("{name} handle must not be null")))
    }
}

/// Read one NUL-terminated argument.
unsafe fn string_arg<'a>(text: *const c_char, name: &str) -> Result<&'a str, FfiError> {
    if text.is_null() {
        return Err(FfiError::input(format!("{name} must not be null")));
    }
    CStr::from_ptr(text)
        .to_str()
        .map_err(|_| FfiError::input(format!("{name} must be utf-8")))
}

/// Borrow one byte slice argument.
unsafe fn bytes_arg<'a>(bytes: *const u8, len: usize, name: &str) -> Result<&'a [u8], FfiError> {
    if len == 0 {
        return Ok(&[][..]);
    }
    if bytes.is_null() {
        return Err(FfiError::input(format!("{name} must not be null")));
    }
    Ok(unsafe { std::slice::from_raw_parts(bytes, len) })
}

/// Hand an owned string to the caller.
fn into_string(text: String) -> *mut c_char {
    match CString::new(text) {
        Ok(text) => text.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Hand an owned allocation to the caller through a buffer out-param.
unsafe fn into_buffer(out: *mut sb_buffer_t, data: Vec<u8>) -> c_int {
    let mut data = ManuallyDrop::new(data);
    unsafe {
        *out = sb_buffer_t {
            data: data.as_mut_ptr(),
            len: data.len(),
            cap: data.capacity(),
        };
    }
    SB_ERR_NONE
}

/// Copy `bytes` into the caller's buffer.
unsafe fn into_fixed(out: *mut u8, bytes: &[u8]) -> c_int {
    if out.is_null() {
        return SB_ERR_INPUT;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    SB_ERR_NONE
}

/// Run a fallible body whose result is discarded.
fn run(body: impl FnOnce() -> Result<(), FfiError>) {
    call((), body)
}

/* ------------------------------------------------------- versions and errors */

/// # Safety
///
/// pure query.
#[no_mangle]
pub extern "C" fn sb_abi_version() -> u32 {
    SYNCBOND_ABI_VERSION
}

/// # Safety
///
/// pure query.
#[no_mangle]
pub extern "C" fn sb_protocol_version() -> u32 {
    syncbond_core::PROTOCOL_VERSION as u32
}

/// # Safety
///
/// valid until the next call from this thread.
#[no_mangle]
pub extern "C" fn sb_last_error() -> *const c_char {
    crate::error::last_error_ptr()
}

/// Last `SB_ERR_*` code of this thread, mirroring `sb_last_error()`.
#[no_mangle]
pub extern "C" fn sb_last_error_code() -> c_int {
    crate::error::last_error_code()
}

/// # Safety
///
/// only free text returned by this library.
#[no_mangle]
pub extern "C" fn sb_free_string(text: *const c_char) {
    if !text.is_null() {
        unsafe {
            drop(CString::from_raw(text as *mut c_char));
        }
    }
}

/// # Safety
///
/// only free buffers returned by this library.
#[no_mangle]
pub unsafe extern "C" fn sb_free_buffer(buffer: *const sb_buffer_t) {
    if buffer.is_null() {
        return;
    }
    let value = unsafe { *buffer };
    if value.data.is_null() || value.cap == 0 {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(value.data, value.len, value.cap));
    }
}

/* ------------------------------------------------------------ identity */

/// # Safety
///
/// allocation failure is reported through `sb_last_error()`.
#[no_mangle]
pub extern "C" fn sb_identity_generate() -> *mut sb_identity {
    call(std::ptr::null_mut(), || {
        Ok(Box::into_raw(Box::new(h::Identity::generate())))
    })
}

/// # Safety
///
/// the buffer must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sb_identity_import(secret_key: *const u8, len: usize) -> *mut sb_identity {
    call(std::ptr::null_mut(), || {
        let key = unsafe { bytes_arg(secret_key, len, "secret key")? };
        Ok(Box::into_raw(Box::new(h::Identity::import(key)?)))
    })
}

/// # Safety
///
/// accepts a handle this library returned.
#[no_mangle]
pub unsafe extern "C" fn sb_identity_free(identity: *mut sb_identity) {
    run(|| {
        if identity.is_null() {
            return Ok(());
        }
        unsafe {
            drop(Box::from_raw(identity));
        }
        Ok(())
    })
}

/// # Safety
///
/// `identity` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_identity_device_id(identity: *const sb_identity) -> *const c_char {
    call(std::ptr::null(), || {
        let identity = unsafe { const_handle(identity, "identity")? };
        Ok(into_string(identity.device_id()))
    })
}

/// # Safety
///
/// `out` must be writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn sb_identity_public_key(
    identity: *const sb_identity,
    out: *mut u8,
) -> c_int {
    call(SB_ERR_INTERNAL, || {
        let identity = unsafe { const_handle(identity, "identity")? };
        let key = identity.public_key();
        Ok(unsafe { into_fixed(out, &key) })
    })
}

/// # Safety
///
/// `out` must be writable for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn sb_identity_secret_key(
    identity: *const sb_identity,
    out: *mut u8,
) -> c_int {
    call(SB_ERR_INTERNAL, || {
        let identity = unsafe { const_handle(identity, "identity")? };
        let key = identity.secret_key();
        Ok(unsafe { into_fixed(out, &key) })
    })
}

/* -------------------------------------------------------------- pairing */

/// # Safety
///
/// `code` is NULL for a generated code, else a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sb_pair_memory(code: *const c_char) -> *mut sb_pair_result {
    call(std::ptr::null_mut(), || {
        let owned = if code.is_null() {
            None
        } else {
            Some(unsafe { string_arg(code, "pairing code")? }.to_string())
        };
        Ok(Box::into_raw(Box::new(h::PairResult::memory(
            owned.as_deref(),
        )?)))
    })
}

/// # Safety
///
/// accepts a handle this library returned.
#[no_mangle]
pub unsafe extern "C" fn sb_pair_result_free(result: *mut sb_pair_result) {
    run(|| {
        if result.is_null() {
            return Ok(());
        }
        unsafe {
            drop(Box::from_raw(result));
        }
        Ok(())
    })
}

/// # Safety
///
/// `result` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_pair_result_code(result: *const sb_pair_result) -> *const c_char {
    call(std::ptr::null(), || {
        let result = unsafe { const_handle(result, "pair result")? };
        Ok(into_string(result.code.clone()))
    })
}

/// # Safety
///
/// `result` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_pair_result_initiator(
    result: *const sb_pair_result,
) -> *mut sb_session {
    call(std::ptr::null_mut(), || {
        let result = unsafe { const_handle(result, "pair result")? };
        Ok(Box::into_raw(Box::new(h::Session(
            result.initiator.clone(),
        ))))
    })
}

/// # Safety
///
/// `result` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_pair_result_responder(
    result: *const sb_pair_result,
) -> *mut sb_session {
    call(std::ptr::null_mut(), || {
        let result = unsafe { const_handle(result, "pair result")? };
        Ok(Box::into_raw(Box::new(h::Session(
            result.responder.clone(),
        ))))
    })
}

/* -------------------------------------------------------------- session */

/// # Safety
///
/// accepts a handle this library returned.
#[no_mangle]
pub unsafe extern "C" fn sb_session_free(session: *mut sb_session) {
    run(|| {
        if session.is_null() {
            return Ok(());
        }
        unsafe {
            drop(Box::from_raw(session));
        }
        Ok(())
    })
}

/// # Safety
///
/// `session` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_session_group_id(session: *const sb_session) -> *const c_char {
    call(std::ptr::null(), || {
        let session = unsafe { const_handle(session, "session")? };
        Ok(into_string(session.group_id()))
    })
}

/// # Safety
///
/// `session` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_session_peer_device_id(session: *const sb_session) -> *const c_char {
    call(std::ptr::null(), || {
        let session = unsafe { const_handle(session, "session")? };
        Ok(into_string(session.peer_device_id()))
    })
}

/// # Safety
///
/// `session` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_session_invalidated(session: *const sb_session) -> c_int {
    call(SB_ERR_INPUT, || {
        let session = unsafe { const_handle(session, "session")? };
        Ok(if session.invalidated() { 1 } else { 0 })
    })
}

/// # Safety
///
/// `payload` must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sb_session_send(
    session: *const sb_session,
    payload: *const u8,
    len: usize,
) -> c_int {
    call(SB_ERR_INTERNAL, || {
        let session = unsafe { const_handle(session, "session")? };
        let payload = unsafe { bytes_arg(payload, len, "payload")? };
        session.send(payload)?;
        Ok(SB_ERR_NONE)
    })
}

/// # Safety
///
/// `out` must not be NULL; the call blocks until a payload arrives.
#[no_mangle]
pub unsafe extern "C" fn sb_session_recv(
    session: *const sb_session,
    out: *mut sb_buffer_t,
) -> c_int {
    call(SB_ERR_INTERNAL, || {
        let session = unsafe { const_handle(session, "session")? };
        if out.is_null() {
            return Err(FfiError::input("output buffer must not be null"));
        }
        let payload = session.recv()?;
        Ok(unsafe { into_buffer(out, payload) })
    })
}

/// # Safety
///
/// `session` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_session_invalidate(session: *const sb_session) -> c_int {
    call(SB_ERR_INPUT, || {
        let session = unsafe { const_handle(session, "session")? };
        session.invalidate();
        Ok(SB_ERR_NONE)
    })
}

/* ----------------------------------------------------------- replication */

/// # Safety
///
/// `node_id` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_new(
    node_id: *const c_char,
    strategy: u32,
) -> *mut sb_replicator {
    call(std::ptr::null_mut(), || {
        let node_id = unsafe { string_arg(node_id, "node id")? };
        Ok(Box::into_raw(Box::new(h::Replicator::new(
            node_id, strategy,
        )?)))
    })
}

/// # Safety
///
/// `node_id` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_new_fixed_clock(
    node_id: *const c_char,
    strategy: u32,
    now_ms: u64,
) -> *mut sb_replicator {
    call(std::ptr::null_mut(), || {
        let node_id = unsafe { string_arg(node_id, "node id")? };
        Ok(Box::into_raw(Box::new(h::Replicator::new_clock(
            node_id, strategy, now_ms,
        )?)))
    })
}

/// # Safety
///
/// accepts a handle this library returned.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_free(replicator: *mut sb_replicator) {
    run(|| {
        if replicator.is_null() {
            return Ok(());
        }
        unsafe {
            drop(Box::from_raw(replicator));
        }
        Ok(())
    })
}

/// # Safety
///
/// `replicator` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_node_id(replicator: *const sb_replicator) -> *const c_char {
    call(std::ptr::null(), || {
        let replicator = unsafe { const_handle(replicator, "replicator")? };
        Ok(into_string(replicator.node_id()))
    })
}

/// # Safety
///
/// `replicator` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_record_count(replicator: *const sb_replicator) -> u32 {
    call(0, || {
        Ok(unsafe { const_handle(replicator, "replicator")? }.record_count())
    })
}

/// # Safety
///
/// `replicator` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_oplog_len(replicator: *const sb_replicator) -> u32 {
    call(0, || {
        Ok(unsafe { const_handle(replicator, "replicator")? }.oplog_len())
    })
}

/// # Safety
///
/// `key` must be NUL-terminated, `payload` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_put(
    replicator: *mut sb_replicator,
    key: *const c_char,
    payload: *const u8,
    len: usize,
) -> c_int {
    call(SB_ERR_INPUT, || {
        let replicator = unsafe { mut_handle(replicator, "replicator")? };
        let key = unsafe { string_arg(key, "key")? };
        let payload = unsafe { bytes_arg(payload, len, "payload")? };
        replicator.put(key, payload)?;
        Ok(SB_ERR_NONE)
    })
}

/// # Safety
///
/// `key` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_delete(
    replicator: *mut sb_replicator,
    key: *const c_char,
) -> c_int {
    call(SB_ERR_INPUT, || {
        let replicator = unsafe { mut_handle(replicator, "replicator")? };
        let key = unsafe { string_arg(key, "key")? };
        replicator.delete(key)?;
        Ok(SB_ERR_NONE)
    })
}

/// # Safety
///
/// `out` must not be NULL; `key` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_get(
    replicator: *const sb_replicator,
    key: *const c_char,
    out: *mut sb_buffer_t,
) -> c_int {
    call(SB_ERR_INPUT, || {
        let replicator = unsafe { const_handle(replicator, "replicator")? };
        let key = unsafe { string_arg(key, "key")? };
        if out.is_null() {
            return Err(FfiError::input("output buffer must not be null"));
        }
        match replicator.get(key) {
            Some(payload) => Ok(unsafe { into_buffer(out, payload) }),
            None => Ok(SB_RESULT_ABSENT),
        }
    })
}

/// # Safety
///
/// `replicator` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_live_keys_json(
    replicator: *const sb_replicator,
) -> *const c_char {
    call(std::ptr::null(), || {
        let replicator = unsafe { const_handle(replicator, "replicator")? };
        Ok(into_string(replicator.live_keys_json()))
    })
}

/// # Safety
///
/// `replicator` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_op_json(
    replicator: *const sb_replicator,
    index: u32,
) -> *const c_char {
    call(std::ptr::null(), || {
        let replicator = unsafe { const_handle(replicator, "replicator")? };
        Ok(into_string(replicator.op_json(index)?))
    })
}

/// # Safety
///
/// `replicator` must be a live handle, `op_json` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_apply_remote_json(
    replicator: *mut sb_replicator,
    op_json: *const c_char,
) -> c_int {
    call(SB_ERR_INTERNAL, || {
        let replicator = unsafe { mut_handle(replicator, "replicator")? };
        let op_json = unsafe { string_arg(op_json, "op json")? };
        Ok(if replicator.apply_remote_json(op_json)? {
            1
        } else {
            0
        })
    })
}

/// # Safety
///
/// both handles must be live and used by one thread at a time.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_sync(
    replicator: *mut sb_replicator,
    session: *mut sb_session,
    send_first: c_int,
    out_sent_ops: *mut u32,
) -> c_int {
    call(SB_ERR_INTERNAL, || {
        let replicator = unsafe { mut_handle(replicator, "replicator")? };
        let session = unsafe { const_handle(session, "session")? };
        let stats = replicator.sync(session, send_first != 0)?;
        if !out_sent_ops.is_null() {
            unsafe {
                *out_sent_ops = stats.sent_ops as u32;
            }
        }
        Ok(SB_ERR_NONE)
    })
}

/// # Safety
///
/// `replicator` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_records_json(
    replicator: *const sb_replicator,
) -> *const c_char {
    call(std::ptr::null(), || {
        let replicator = unsafe { const_handle(replicator, "replicator")? };
        Ok(into_string(replicator.records_json()))
    })
}

/// # Safety
///
/// `replicator` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_gc_barriers_json(
    replicator: *const sb_replicator,
) -> *const c_char {
    call(std::ptr::null(), || {
        let replicator = unsafe { const_handle(replicator, "replicator")? };
        Ok(into_string(replicator.gc_barriers_json()))
    })
}

/// # Safety
///
/// `replicator` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_replicator_gc_tombstones(
    replicator: *mut sb_replicator,
    now_ms: u64,
    older_than_ms: u64,
) -> c_int {
    call(SB_ERR_INTERNAL, || {
        let replicator = unsafe { mut_handle(replicator, "replicator")? };
        Ok(replicator.gc_tombstones(now_ms, older_than_ms)? as c_int)
    })
}

/* ------------------------------------------------------------- key material */

/// # Safety
///
/// `group_id` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn sb_keyring_new(group_id: *const c_char) -> *mut sb_keyring {
    call(std::ptr::null_mut(), || {
        let group_id = unsafe { string_arg(group_id, "group id")? };
        Ok(Box::into_raw(Box::new(h::Keyring::new(group_id))))
    })
}

/// # Safety
///
/// `key` must be readable for 32 bytes, `group_id` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn sb_keyring_import(
    group_id: *const c_char,
    epoch: u64,
    key: *const u8,
) -> *mut sb_keyring {
    call(std::ptr::null_mut(), || {
        let group_id = unsafe { string_arg(group_id, "group id")? };
        let key = unsafe { bytes_arg(key, 32, "group key")? };
        Ok(Box::into_raw(Box::new(h::Keyring::import(
            group_id, epoch, key,
        )?)))
    })
}

/// # Safety
///
/// accepts a handle this library returned.
#[no_mangle]
pub unsafe extern "C" fn sb_keyring_free(keyring: *mut sb_keyring) {
    run(|| {
        if keyring.is_null() {
            return Ok(());
        }
        unsafe {
            drop(Box::from_raw(keyring));
        }
        Ok(())
    })
}

/// # Safety
///
/// `keyring` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn sb_keyring_epoch(keyring: *const sb_keyring) -> u64 {
    call(0, || {
        Ok(unsafe { const_handle(keyring, "keyring")? }.epoch())
    })
}

/// # Safety
///
/// both outputs must be writable; no rotation happens on failure.
#[no_mangle]
pub unsafe extern "C" fn sb_keyring_rotate(
    keyring: *mut sb_keyring,
    out_epoch: *mut u64,
    out_key: *mut u8,
) -> c_int {
    call(SB_ERR_INPUT, || {
        if out_epoch.is_null() || out_key.is_null() {
            return Err(FfiError::input("output arguments must not be null"));
        }
        let keyring = unsafe { mut_handle(keyring, "keyring")? };
        let (epoch, key) = keyring.rotate();
        unsafe {
            *out_epoch = epoch;
            std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, 32);
        }
        Ok(SB_ERR_NONE)
    })
}

/// # Safety
///
/// `sender` must be NUL-terminated, `plaintext` readable for `len`.
#[no_mangle]
pub unsafe extern "C" fn sb_keyring_seal_json(
    keyring: *const sb_keyring,
    sender_device_id: *const c_char,
    plaintext: *const u8,
    len: usize,
) -> *const c_char {
    call(std::ptr::null(), || {
        let keyring = unsafe { const_handle(keyring, "keyring")? };
        let sender = unsafe { string_arg(sender_device_id, "sender device id")? };
        let plaintext = unsafe { bytes_arg(plaintext, len, "plaintext")? };
        Ok(into_string(keyring.seal_json(sender, plaintext)))
    })
}

/// # Safety
///
/// `envelope_json` NUL-terminated, `out` must not be NULL.
#[no_mangle]
pub unsafe extern "C" fn sb_keyring_open_json(
    keyring: *const sb_keyring,
    envelope_json: *const c_char,
    out: *mut sb_buffer_t,
) -> c_int {
    call(SB_ERR_INTERNAL, || {
        let keyring = unsafe { const_handle(keyring, "keyring")? };
        let envelope = unsafe { string_arg(envelope_json, "envelope json")? };
        if out.is_null() {
            return Err(FfiError::input("output buffer must not be null"));
        }
        let payload = keyring.open_json(envelope)?;
        Ok(unsafe { into_buffer(out, payload) })
    })
}

/* --------------------------------------------------------- conformance runs */

/// # Safety
///
/// `fixture_json` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sb_conformance_run(fixture_json: *const c_char) -> *const c_char {
    call(std::ptr::null(), || {
        let fixture = unsafe { string_arg(fixture_json, "fixture json")? };
        Ok(into_string(crate::scenario::run(fixture)?))
    })
}
