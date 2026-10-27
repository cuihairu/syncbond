//! Browser WASM bindings for syncbond.
//!
//! The library runs an in-memory pairing/sync handshake on worker threads,
//! which `wasm32-unknown-unknown` (built without the `atomics` feature)
//! cannot provide. This crate therefore exposes the single-thread-safe
//! surface and nothing more: identity generation, replicator CRUD with a
//! byte-level save/load (so a host can persist state in IndexedDB), the
//! tombstone GC entry point, and the cross-language conformance runner
//! (thread-free). Pairing and sync over a real remote transport — WebRTC or
//! WebSocket, where each side lives in its own realm — are the application's
//! job; this binding contains no protocol logic.
//!
//! When the host has no IndexedDB the wrapper degrades to an in-memory
//! store and reports the limitation explicitly (see `packages/ts-bindings`
//! `src/wasm/wrapper.js`).

use std::sync::Arc;

use syncbond_core::conflict::LwwHlc;
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::replication::{decode_state, encode_state, Replicator};
use wasm_bindgen::prelude::*;

// ----------------------------------------------------------- identity

/// A freshly generated device identity (Ed25519 keypair + device id).
#[wasm_bindgen]
pub struct WasmIdentity {
    inner: DeviceIdentity,
}

#[wasm_bindgen]
impl WasmIdentity {
    #[wasm_bindgen(constructor)]
    pub fn generate() -> WasmIdentity {
        WasmIdentity {
            inner: DeviceIdentity::generate(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn device_id(&self) -> String {
        self.inner.device_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key.to_vec()
    }
}

// --------------------------------------------------------- replicator

/// An LWW/HLC replicator. Writes go to the local oplog; `sync` (over a
/// transport the application owns) propagates them. `save`/`load` round-trip
/// the full local replication state as bytes for host-side persistence.
#[wasm_bindgen]
pub struct WasmReplicator {
    inner: Replicator,
}

#[wasm_bindgen]
impl WasmReplicator {
    #[wasm_bindgen(constructor)]
    pub fn new(node_id: String) -> WasmReplicator {
        WasmReplicator {
            inner: Replicator::with_wall_clock(node_id, Arc::new(LwwHlc), wall_clock()),
        }
    }

    #[wasm_bindgen]
    pub fn put(&mut self, key: String, payload: Vec<u8>) {
        self.inner.put(key, payload);
    }

    #[wasm_bindgen]
    pub fn delete(&mut self, key: String) {
        self.inner.delete(key);
    }

    /// Payload of a live record; tombstoned (deleted) or absent keys read as
    /// `undefined` (wasm-bindgen's `Option::None` mapping; the napi path
    /// returns `null` — both are falsy).
    #[wasm_bindgen]
    pub fn get(&self, key: String) -> Option<Vec<u8>> {
        self.inner
            .get(&key)
            .filter(|record| !record.deleted)
            .map(|record| record.payload.clone())
    }

    /// Keys with a live (non-tombstoned) value, sorted.
    #[wasm_bindgen(getter)]
    pub fn keys(&self) -> Vec<String> {
        self.inner.live_keys()
    }

    #[wasm_bindgen(getter)]
    pub fn record_count(&self) -> u32 {
        self.inner.record_count() as u32
    }

    #[wasm_bindgen(getter)]
    pub fn node_id(&self) -> String {
        self.inner.node_id.clone()
    }

    /// Serialize the full local replication state. The identity/group/epoch
    /// fields of the snapshot are placeholders; only oplog, cursor and GC
    /// barriers round-trip (which is what replication needs to resume).
    #[wasm_bindgen]
    pub fn save(&self) -> Result<Vec<u8>, JsValue> {
        let placeholder = DeviceIdentity {
            device_id: self.inner.node_id.clone(),
            public_key: [0u8; 32],
            secret_key: [0u8; 64],
        };
        let state = self.inner.snapshot_state(&placeholder, "", 0);
        encode_state(&state).map_err(js_error)
    }

    /// Rebuild a replicator from `save()` output (crash-restart path).
    #[wasm_bindgen]
    pub fn load(bytes: Vec<u8>) -> Result<WasmReplicator, JsValue> {
        let state = decode_state(&bytes).map_err(js_error)?;
        Ok(WasmReplicator {
            inner: Replicator::from_state_with_clock(&state, Arc::new(LwwHlc), wall_clock()),
        })
    }

    /// Drop tombstones older than `older_than_ms` relative to `now_ms`.
    /// Returns the number of oplog entries removed by collapsing collected
    /// histories down to their single tombstone op.
    #[wasm_bindgen]
    pub fn gc_tombstones(&mut self, now_ms: f64, older_than_ms: f64) -> u32 {
        let report = self
            .inner
            .gc_tombstones(now_ms as u64, older_than_ms as u64);
        report.oplog_entries_removed as u32
    }
}

// ------------------------------------------------------ conformance / versions

/// Runs a cross-language conformance fixture through the same canonical
/// runner the C ABI exposes, returning the report JSON. Thread-free; safe on
/// wasm32.
#[wasm_bindgen]
pub fn conformance_run(fixture_json: &str) -> Result<String, JsValue> {
    let fixture = std::ffi::CString::new(fixture_json).map_err(js_error)?;
    let report = unsafe { syncbond_ffi::abi::sb_conformance_run(fixture.as_ptr()) };
    if report.is_null() {
        return Err(js_error(format!(
            "conformance runner failed: {}",
            last_error_message()
        )));
    }
    let text = unsafe {
        std::ffi::CStr::from_ptr(report)
            .to_string_lossy()
            .into_owned()
    };
    syncbond_ffi::abi::sb_free_string(report);
    Ok(text)
}

#[wasm_bindgen]
pub fn protocol_version() -> u32 {
    syncbond_ffi::abi::sb_protocol_version()
}

#[wasm_bindgen]
pub fn abi_version() -> u32 {
    syncbond_ffi::abi::sb_abi_version()
}

// --------------------------------------------------------------- helpers

fn js_error(message: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

/// A wall clock the replicator can actually call on this target. wasm32 does
/// not implement `SystemTime`; js-sys reads `Date.now()` instead.
fn wall_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| {
        #[cfg(target_arch = "wasm32")]
        {
            js_sys::Date::now() as u64
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0)
        }
    })
}

fn last_error_message() -> String {
    unsafe {
        let text = syncbond_ffi::abi::sb_last_error();
        if text.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(text)
                .to_string_lossy()
                .into_owned()
        }
    }
}
