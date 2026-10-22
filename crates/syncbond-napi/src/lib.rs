//! napi-rs bindings for syncbond-core: pairing, encrypted sessions, and
//! oplog replication exposed to Node.js. All cryptography lives in
//! syncbond-core; this layer only marshals data across the FFI boundary.

use napi::bindgen_prelude::{AsyncTask, Buffer, Uint8Array};
use napi::{Env, Result, Task};
use napi_derive::napi;
use std::sync::{Arc, Mutex};
use syncbond_core::{
    identity::DeviceIdentity,
    replication::{Operation, Replicator, SyncStats},
};

mod pairing;

pub use pairing::{NativePairingResult, NativePairingSession};

#[napi(object)]
pub struct NativeStats {
    pub sent_ops: u32,
    pub received_ops: u32,
    pub applied_ops: u32,
}

impl From<SyncStats> for NativeStats {
    fn from(stats: SyncStats) -> Self {
        Self {
            sent_ops: stats.sent_ops as u32,
            received_ops: stats.received_ops as u32,
            applied_ops: stats.applied_ops as u32,
        }
    }
}

#[napi]
pub struct NativeIdentity {
    inner: DeviceIdentity,
}

#[napi]
impl NativeIdentity {
    #[napi(factory)]
    pub fn generate() -> Self {
        Self {
            inner: DeviceIdentity::generate(),
        }
    }

    #[napi(getter)]
    pub fn device_id(&self) -> String {
        self.inner.device_id.clone()
    }

    #[napi(getter)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::new(self.inner.public_key.to_vec())
    }
}

#[napi]
pub struct NativeReplicator {
    inner: Arc<Mutex<Replicator>>,
}

#[napi]
impl NativeReplicator {
    #[napi(constructor)]
    pub fn new(node_id: String) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Replicator::new(node_id))),
        }
    }

    #[napi]
    pub fn put(&self, key: String, payload: Buffer) {
        self.inner.lock().unwrap().put(key, payload.to_vec());
    }

    #[napi]
    pub fn delete(&self, key: String) {
        self.inner.lock().unwrap().delete(key);
    }

    /// Payload of a live record; tombstoned (deleted) keys read as undefined.
    #[napi]
    pub fn get(&self, key: String) -> Option<Uint8Array> {
        self.inner
            .lock()
            .unwrap()
            .get(&key)
            .filter(|record| !record.deleted)
            .map(|record| Uint8Array::new(record.payload.clone()))
    }

    /// Keys with a live (non-tombstoned) value, sorted.
    #[napi]
    pub fn keys(&self) -> Vec<String> {
        self.inner.lock().unwrap().live_keys()
    }

    #[napi(getter)]
    pub fn record_count(&self) -> u32 {
        self.inner.lock().unwrap().record_count() as u32
    }

    #[napi(getter)]
    pub fn node_id(&self) -> String {
        self.inner.lock().unwrap().node_id.clone()
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
    replicator: Arc<Mutex<Replicator>>,
    session: Arc<syncbond_core::pairing::PairingSession>,
    send_first: bool,
}

impl Task for SyncOverTask {
    type Output = SyncStats;
    type JsValue = NativeStats;

    fn compute(&mut self) -> Result<Self::Output> {
        let mut replicator = self.replicator.lock().unwrap();
        run_sync_over(&mut replicator, &self.session, self.send_first)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

/// Exchange the full oplog in both directions over an established session.
/// Ops are deduplicated by op id on apply, so re-sending the whole log is
/// idempotent and both sides converge.
fn run_sync_over(
    replicator: &mut Replicator,
    session: &syncbond_core::pairing::PairingSession,
    send_first: bool,
) -> Result<SyncStats> {
    let encode = |ops: &[Operation]| -> Result<Vec<u8>> {
        serde_json::to_vec(ops).map_err(|error| napi_error(format!("serialize oplog: {error}")))
    };
    let decode = |bytes: &[u8]| -> Result<Vec<Operation>> {
        serde_json::from_slice(bytes)
            .map_err(|error| napi_error(format!("deserialize oplog: {error}")))
    };

    let mut stats = SyncStats {
        sent_ops: 0,
        received_ops: 0,
        applied_ops: 0,
    };
    let send = |replicator: &Replicator, stats: &mut SyncStats| -> Result<()> {
        let outbound: Vec<Operation> = replicator.oplog().to_vec();
        session
            .seal_and_send(&encode(&outbound)?)
            .map_err(napi_error)?;
        stats.sent_ops = outbound.len();
        Ok(())
    };
    let receive = |replicator: &mut Replicator, stats: &mut SyncStats| -> Result<()> {
        let payload = session.recv_and_open().map_err(napi_error)?;
        let ops = decode(&payload)?;
        stats.received_ops = ops.len();
        for operation in &ops {
            if replicator.apply_remote(operation) {
                stats.applied_ops += 1;
            }
        }
        Ok(())
    };

    if send_first {
        send(replicator, &mut stats)?;
        receive(replicator, &mut stats)?;
    } else {
        receive(replicator, &mut stats)?;
        send(replicator, &mut stats)?;
    }
    Ok(stats)
}

#[napi]
pub fn protocol_version() -> u32 {
    u32::from(syncbond_core::PROTOCOL_VERSION)
}

pub(crate) fn napi_error(error: impl std::fmt::Display) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, error.to_string())
}
