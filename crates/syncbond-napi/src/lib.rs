//! napi-rs bindings consuming the syncbond C ABI: pairing, encrypted
//! sessions, and oplog replication exposed to Node.js. Every call forwards
//! to the same `sb_*` functions the C/C++/Python/Go/Java/C# bindings use, so
//! the Node semantics cannot drift from the other languages. This layer only
//! marshals data; it contains no protocol logic.

use napi::bindgen_prelude::{AsyncTask, Buffer, Uint8Array};
use napi::{Env, Result, Task};
use napi_derive::napi;
use std::ffi::{c_char, CString};
use std::sync::{Arc, Mutex};
use syncbond_ffi::abi;
use syncbond_ffi::error::SB_STRATEGY_LWW_HLC;

mod pairing;

pub use pairing::{NativePairingResult, NativePairingSession};

// --------------------------------------------------------------- helpers

/// The thread-local last error of the C ABI, copied before anything else on
/// this thread can overwrite it.
pub(crate) fn last_error() -> napi::Error {
    unsafe {
        let code = abi::sb_last_error_code();
        let text = abi::sb_last_error();
        let message = if text.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(text)
                .to_string_lossy()
                .into_owned()
        };
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("{message} (code {code})"),
        )
    }
}

/// Copy an owned C string into a Rust string, then release it with the ABI.
pub(crate) unsafe fn take_string(owned: *const c_char) -> Result<String> {
    if owned.is_null() {
        return Err(last_error());
    }
    let text = unsafe {
        std::ffi::CStr::from_ptr(owned)
            .to_string_lossy()
            .into_owned()
    };
    abi::sb_free_string(owned);
    Ok(text)
}

/// A NUL-terminated copy of a Rust string for an ABI call.
pub(crate) fn cstr(value: &str) -> CString {
    CString::new(value).unwrap_or_default()
}

/// Throw on a negative result code (the ABI's error convention).
pub(crate) fn check(code: i32) -> Result<()> {
    if code < 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

// ----------------------------------------------------------- native types

/// One owned replicator handle; released when the last reference drops.
struct ReplicatorHandle(*mut syncbond_ffi::sb_replicator);
unsafe impl Send for ReplicatorHandle {}
unsafe impl Sync for ReplicatorHandle {}
impl ReplicatorHandle {
    fn get(&self) -> *mut syncbond_ffi::sb_replicator {
        self.0
    }
}
impl Drop for ReplicatorHandle {
    fn drop(&mut self) {
        unsafe { abi::sb_replicator_free(self.0) };
    }
}

/// One owned identity handle; released when the wrapper is GC'd.
struct IdentityHandle(*mut syncbond_ffi::sb_identity);
unsafe impl Send for IdentityHandle {}
unsafe impl Sync for IdentityHandle {}
impl Drop for IdentityHandle {
    fn drop(&mut self) {
        unsafe { abi::sb_identity_free(self.0) };
    }
}

#[napi(object)]
pub struct NativeStats {
    pub sent_ops: u32,
}

#[napi]
pub struct NativeIdentity {
    handle: IdentityHandle,
}

#[napi]
impl NativeIdentity {
    #[napi(factory)]
    pub fn generate() -> Result<Self> {
        let handle = abi::sb_identity_generate();
        if handle.is_null() {
            return Err(last_error());
        }
        Ok(Self {
            handle: IdentityHandle(handle),
        })
    }

    #[napi(getter)]
    pub fn device_id(&self) -> Result<String> {
        unsafe { take_string(abi::sb_identity_device_id(self.handle.0)) }
    }

    #[napi(getter)]
    pub fn public_key(&self) -> Result<Uint8Array> {
        let mut key = [0u8; 32];
        unsafe {
            check(abi::sb_identity_public_key(self.handle.0, key.as_mut_ptr()))?;
        }
        Ok(Uint8Array::new(key.to_vec()))
    }
}

#[napi]
pub struct NativeReplicator {
    inner: Arc<Mutex<ReplicatorHandle>>,
}

#[napi]
impl NativeReplicator {
    #[napi(constructor)]
    pub fn new(node_id: String) -> Result<Self> {
        let c_node_id = cstr(&node_id);
        let handle = unsafe { abi::sb_replicator_new(c_node_id.as_ptr(), SB_STRATEGY_LWW_HLC) };
        if handle.is_null() {
            return Err(last_error());
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(ReplicatorHandle(handle))),
        })
    }

    #[napi]
    pub fn put(&self, key: String, payload: Buffer) -> Result<()> {
        let c_key = cstr(&key);
        let handle = self.inner.lock().unwrap();
        unsafe {
            check(abi::sb_replicator_put(
                handle.get(),
                c_key.as_ptr(),
                payload.as_ptr().cast(),
                payload.len(),
            ))
        }
    }

    #[napi]
    pub fn delete(&self, key: String) -> Result<()> {
        let c_key = cstr(&key);
        let handle = self.inner.lock().unwrap();
        unsafe { check(abi::sb_replicator_delete(handle.get(), c_key.as_ptr())) }
    }

    /// Payload of a live record; tombstoned (deleted) keys read as null.
    #[napi]
    pub fn get(&self, key: String) -> Result<Option<Uint8Array>> {
        let c_key = cstr(&key);
        let handle = self.inner.lock().unwrap();
        unsafe {
            let mut buffer: abi::sb_buffer_t = abi::sb_buffer_t {
                data: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            let code = abi::sb_replicator_get(handle.get(), c_key.as_ptr(), &mut buffer);
            if code == syncbond_ffi::error::SB_RESULT_ABSENT {
                return Ok(None);
            }
            check(code)?;
            let bytes = std::slice::from_raw_parts(buffer.data, buffer.len).to_vec();
            abi::sb_free_buffer(&buffer);
            Ok(Some(Uint8Array::new(bytes)))
        }
    }

    /// Keys with a live (non-tombstoned) value, sorted.
    #[napi]
    pub fn keys(&self) -> Result<Vec<String>> {
        let handle = self.inner.lock().unwrap();
        let json = unsafe { take_string(abi::sb_replicator_live_keys_json(handle.get()))? };
        serde_json::from_str(&json)
            .map_err(|error| napi::Error::new(napi::Status::GenericFailure, error.to_string()))
    }

    #[napi(getter)]
    pub fn record_count(&self) -> u32 {
        let handle = self.inner.lock().unwrap();
        unsafe { abi::sb_replicator_record_count(handle.get()) }
    }

    #[napi(getter)]
    pub fn node_id(&self) -> Result<String> {
        let handle = self.inner.lock().unwrap();
        unsafe { take_string(abi::sb_replicator_node_id(handle.get())) }
    }

    /// Full-duplex oplog exchange over a paired session: `send_first` sends
    /// the local oplog then applies the peer's response; otherwise the order
    /// is reversed. Returns a promise; the receiving half blocks until the
    /// peer's frame arrives, so the exchange runs on the libuv thread pool
    /// and both sides can call it concurrently with `Promise.all`.
    #[napi]
    pub fn sync(
        &self,
        _env: Env,
        session: &NativePairingSession,
        send_first: bool,
    ) -> AsyncTask<SyncOverTask> {
        AsyncTask::new(SyncOverTask {
            replicator: Arc::clone(&self.inner),
            session: session.arc_clone(),
            send_first,
        })
    }
}

pub struct SyncOverTask {
    replicator: Arc<Mutex<ReplicatorHandle>>,
    session: Arc<pairing::SessionHandle>,
    send_first: bool,
}

impl Task for SyncOverTask {
    type Output = u32;
    type JsValue = NativeStats;

    fn compute(&mut self) -> Result<Self::Output> {
        let handle = self.replicator.lock().unwrap();
        unsafe {
            let mut sent: u32 = 0;
            let code = abi::sb_replicator_sync(
                handle.get(),
                self.session.get(),
                if self.send_first { 1 } else { 0 },
                &mut sent,
            );
            check(code)?;
            Ok(sent)
        }
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(NativeStats { sent_ops: output })
    }
}

#[napi]
pub fn protocol_version() -> u32 {
    abi::sb_protocol_version()
}

#[napi]
pub fn abi_version() -> u32 {
    abi::sb_abi_version()
}

/// Runs a cross-language conformance fixture over the same public APIs the
/// other bindings drive, returning canonical JSON.
#[napi]
pub fn conformance_run(fixture_json: String) -> Result<String> {
    let c_fixture = cstr(&fixture_json);
    unsafe { take_string(abi::sb_conformance_run(c_fixture.as_ptr())) }
}
