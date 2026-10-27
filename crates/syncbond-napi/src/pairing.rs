//! Pairing and sessions over the syncbond C ABI. `pair_memory` runs the
//! SPAKE2 handshake inside the library and hands back two authenticated
//! session ends; a session end is an opaque handle whose lifetime the
//! binding manages (Drop → `sb_session_free`). No protocol logic lives here.

use crate::{cstr, last_error, take_string};
use napi::Result;
use napi_derive::napi;
use std::ffi::c_char;
use std::sync::Arc;
use syncbond_ffi::abi;

/// One owned session end; released when the last reference drops.
pub(crate) struct SessionHandle(*mut syncbond_ffi::sb_session);
unsafe impl Send for SessionHandle {}
unsafe impl Sync for SessionHandle {}
impl SessionHandle {
    pub(crate) fn get(&self) -> *mut syncbond_ffi::sb_session {
        self.0
    }
}
impl Drop for SessionHandle {
    fn drop(&mut self) {
        unsafe { abi::sb_session_free(self.0) };
    }
}

/// One owned pairing result; freed once both sessions are taken out.
struct PairResultHandle(*mut syncbond_ffi::sb_pair_result);
unsafe impl Send for PairResultHandle {}
unsafe impl Sync for PairResultHandle {}
impl Drop for PairResultHandle {
    fn drop(&mut self) {
        unsafe { abi::sb_pair_result_free(self.0) };
    }
}

/// Both authenticated sessions produced by one pairing handshake.
#[napi]
pub struct NativePairingResult {
    handle: PairResultHandle,
    code: String,
}

#[napi]
impl NativePairingResult {
    #[napi]
    pub fn initiator_session(&self) -> Result<NativePairingSession> {
        let session = unsafe { abi::sb_pair_result_initiator(self.handle.0) };
        if session.is_null() {
            return Err(last_error());
        }
        Ok(NativePairingSession {
            inner: Arc::new(SessionHandle(session)),
        })
    }

    #[napi]
    pub fn responder_session(&self) -> Result<NativePairingSession> {
        let session = unsafe { abi::sb_pair_result_responder(self.handle.0) };
        if session.is_null() {
            return Err(last_error());
        }
        Ok(NativePairingSession {
            inner: Arc::new(SessionHandle(session)),
        })
    }

    #[napi(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }
}

/// One authenticated, encrypted session end. Holds its handle behind an
/// `Arc` so a sync exchange can keep using it across thread boundaries
/// without aliasing tricks.
#[napi]
pub struct NativePairingSession {
    inner: Arc<SessionHandle>,
}

impl NativePairingSession {
    pub(crate) fn arc_clone(&self) -> Arc<SessionHandle> {
        Arc::clone(&self.inner)
    }
}

#[napi]
impl NativePairingSession {
    #[napi(getter)]
    pub fn group_id(&self) -> Result<String> {
        unsafe { take_string(abi::sb_session_group_id(self.inner.get())) }
    }

    #[napi(getter)]
    pub fn peer_device_id(&self) -> Result<String> {
        unsafe { take_string(abi::sb_session_peer_device_id(self.inner.get())) }
    }

    #[napi]
    pub fn invalidate(&self) {
        let _ = unsafe { abi::sb_session_invalidate(self.inner.get()) };
    }

    #[napi(getter)]
    pub fn invalidated(&self) -> bool {
        unsafe { abi::sb_session_invalidated(self.inner.get()) != 0 }
    }
}

/// Run the SPAKE2 pairing handshake over an in-memory loopback between two
/// freshly generated device identities. A NULL or empty `code` asks the
/// library to generate one (matching the other bindings); otherwise the
/// given code must be at least 6 characters.
#[napi]
#[allow(dead_code)] // reached through the generated N-API module export
pub fn pair_memory(code: Option<String>) -> Result<NativePairingResult> {
    // The library owns code generation; pass NULL for empty so the ABI
    // produces one and reports it back.
    let code_text = code.as_deref().filter(|code| !code.is_empty());
    let code_c = code_text.map(cstr);
    let code_ptr: *const c_char = code_c
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr());

    let handle = unsafe { abi::sb_pair_memory(code_ptr) };
    if handle.is_null() {
        return Err(last_error());
    }

    // Read the (possibly library-generated) code out of the result.
    let generated = unsafe { take_string(abi::sb_pair_result_code(handle))? };
    Ok(NativePairingResult {
        handle: PairResultHandle(handle),
        code: generated,
    })
}
