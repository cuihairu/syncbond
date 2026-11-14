//! Python bindings for syncbond.
//!
//! The semantic surface is `syncbond-ffi`'s handle layer; this module only
//! adds Python types, byte conversions and a threading wrapper for the
//! full-duplex oplog exchange. It contains no protocol logic.

use std::sync::{Arc, Mutex};

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use syncbond_ffi::error::{FfiError, SB_ERR_NONE};
use syncbond_ffi::handles;

create_exception!(syncbond, Error, PyException, "syncbond failure");

/// Map a handle-layer failure onto `syncbond.Error`. The `SB_ERR_*` code is
/// also recorded in the thread-local slot, so `last_error_code()` mirrors the
/// C ABI instead of depending on how the exception message is parsed.
fn to_pyerr(what: &str) -> impl Fn(FfiError) -> PyErr + '_ {
    move |error| {
        syncbond_ffi::error::set_last_error(Some(error.clone()));
        Error::new_err(format!("{what}: {}", error.message))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Identity of one device.
#[pyclass]
pub struct Identity {
    inner: handles::Identity,
}

#[pymethods]
impl Identity {
    /// Generate a fresh Ed25519 identity.
    #[new]
    fn new() -> Self {
        Self {
            inner: handles::Identity::generate(),
        }
    }

    /// Rebuild an identity from a persisted 64-byte keypair.
    #[staticmethod]
    fn import(secret_key: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: handles::Identity::import(secret_key).map_err(to_pyerr("identity import"))?,
        })
    }

    #[getter]
    fn device_id(&self) -> String {
        self.inner.device_id()
    }

    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_key())
    }

    fn secret_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.secret_key())
    }
}

/// One authenticated, encrypted session end.
#[pyclass]
pub struct Session {
    inner: handles::Session,
}

#[pymethods]
impl Session {
    #[getter]
    fn group_id(&self) -> String {
        self.inner.group_id()
    }

    #[getter]
    fn peer_device_id(&self) -> String {
        self.inner.peer_device_id()
    }

    #[getter]
    fn invalidated(&self) -> bool {
        self.inner.invalidated()
    }

    /// Encrypt and enqueue one application payload.
    fn send(&self, payload: &[u8]) -> PyResult<()> {
        self.inner.send(payload).map_err(to_pyerr("session send"))
    }

    /// Blocking: decrypt and return the next application payload.
    fn recv(&self) -> PyResult<Vec<u8>> {
        self.inner.recv().map_err(to_pyerr("session recv"))
    }

    fn invalidate(&self) {
        self.inner.invalidate();
    }
}

/// One synchronizing device.
#[pyclass]
pub struct Replicator {
    inner: Arc<Mutex<handles::Replicator>>,
}

#[pymethods]
impl Replicator {
    /// `now_ms == 0` uses the wall clock; a frozen clock makes runs reproducible.
    #[new]
    #[pyo3(signature = (node_id, strategy = 0, now_ms = 0))]
    fn new(node_id: &str, strategy: u32, now_ms: u64) -> PyResult<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(
                handles::Replicator::new_clock(node_id, strategy, now_ms)
                    .map_err(to_pyerr("replicator create"))?,
            )),
        })
    }

    #[getter]
    fn node_id(&self) -> String {
        lock(&self.inner).node_id()
    }

    #[getter]
    fn record_count(&self) -> u32 {
        lock(&self.inner).record_count()
    }

    #[getter]
    fn oplog_len(&self) -> u32 {
        lock(&self.inner).oplog_len()
    }

    fn put(&self, key: &str, payload: &[u8]) -> PyResult<()> {
        lock(&self.inner)
            .put(key, payload)
            .map_err(to_pyerr("replicator put"))
    }

    fn delete(&self, key: &str) -> PyResult<()> {
        lock(&self.inner)
            .delete(key)
            .map_err(to_pyerr("replicator delete"))
    }

    /// Payload bytes of a live record, or `None` when absent or tombstoned.
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        lock(&self.inner).get(key)
    }

    fn live_keys_json(&self) -> String {
        lock(&self.inner).live_keys_json()
    }

    fn op_json(&self, index: u32) -> PyResult<String> {
        lock(&self.inner)
            .op_json(index)
            .map_err(to_pyerr("replicator op"))
    }

    /// Apply one wire op; `False` when it was a duplicate or a resurrected delete.
    fn apply_remote_json(&self, op_json: &str) -> PyResult<bool> {
        lock(&self.inner)
            .apply_remote_json(op_json)
            .map_err(to_pyerr("replicator apply"))
    }

    /// Blocking one-directional oplog exchange; prefer `sync_pair`.
    fn sync(&self, session: &Session, send_first: bool) -> PyResult<u32> {
        lock(&self.inner)
            .sync(&session.inner, send_first)
            .map(|stats| stats.sent_ops as u32)
            .map_err(to_pyerr("replicator sync"))
    }

    fn records_json(&self) -> String {
        lock(&self.inner).records_json()
    }

    fn gc_barriers_json(&self) -> String {
        lock(&self.inner).gc_barriers_json()
    }

    fn gc_tombstones(&self, now_ms: u64, older_than_ms: u64) -> PyResult<u32> {
        lock(&self.inner)
            .gc_tombstones(now_ms, older_than_ms)
            .map(|count| count as u32)
            .map_err(to_pyerr("replicator gc"))
    }
}

/// Both sessions produced by one pairing handshake.
#[pyclass]
pub struct Pair {
    initiator: Session,
    responder: Session,
    code: String,
}

#[pymethods]
impl Pair {
    #[getter]
    fn initiator(&self) -> Session {
        Session {
            inner: handles::Session(self.initiator.inner.0.clone()),
        }
    }

    #[getter]
    fn responder(&self) -> Session {
        Session {
            inner: handles::Session(self.responder.inner.0.clone()),
        }
    }

    #[getter]
    fn code(&self) -> String {
        self.code.clone()
    }
}

/// Group key material with replay tracking for one device.
#[pyclass]
pub struct Keyring {
    inner: Arc<Mutex<handles::Keyring>>,
}

#[pymethods]
impl Keyring {
    /// `epoch` defaults to 1 when omitted.
    #[new]
    #[pyo3(signature = (group_id, epoch = None, key = None))]
    fn new(group_id: &str, epoch: Option<u64>, key: Option<&[u8]>) -> PyResult<Self> {
        let inner = match (epoch, key) {
            (None, None) => handles::Keyring::new(group_id),
            (Some(epoch), Some(key)) => handles::Keyring::import(group_id, epoch, key)
                .map_err(to_pyerr("keyring import"))?,
            _ => {
                return Err(Error::new_err(
                    "keyring needs both epoch and key, or neither",
                ))
            }
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[getter]
    fn epoch(&self) -> u64 {
        lock(&self.inner).epoch()
    }

    /// Mint the next epoch and hand back the new key for distribution.
    fn rotate(&self) -> (u64, Vec<u8>) {
        let mut inner = lock(&self.inner);
        let (epoch, key) = inner.rotate();
        (epoch, key.to_vec())
    }

    fn seal(&self, sender_device_id: &str, plaintext: &[u8]) -> String {
        lock(&self.inner).seal_json(sender_device_id, plaintext)
    }

    fn open(&self, envelope_json: &str) -> PyResult<Vec<u8>> {
        lock(&self.inner)
            .open_json(envelope_json)
            .map_err(to_pyerr("keyring open"))
    }
}

/// Run both directions of one oplog exchange. `sync` blocks in one direction,
/// so the responder half runs on a worker thread; the two halves use distinct
/// handles, and the GIL is released while they work.
#[pyfunction]
fn sync_pair(
    py: Python<'_>,
    left: &Replicator,
    initiator: &Session,
    right: &Replicator,
    responder: &Session,
) -> PyResult<(u32, u32)> {
    let left = left.inner.clone();
    let right = right.inner.clone();
    let initiator = initiator.inner.0.clone();
    let responder = responder.inner.0.clone();
    py.detach(|| {
        let worker =
            std::thread::spawn(move || lock(&right).sync(&handles::Session(responder), false));
        let left_stats = lock(&left).sync(&handles::Session(initiator), true);
        let right_stats = worker
            .join()
            .map_err(|_| Error::new_err("responder sync thread panicked"))?;
        let left_ops = left_stats
            .map(|stats| stats.sent_ops as u32)
            .map_err(to_pyerr("initiator sync"))?;
        let right_ops = right_stats
            .map(|stats| stats.sent_ops as u32)
            .map_err(to_pyerr("responder sync"))?;
        Ok((left_ops, right_ops))
    })
}

/// Pair two freshly generated devices over an in-memory loopback.
#[pyfunction]
#[pyo3(signature = (code = None))]
fn pair_memory(code: Option<&str>) -> PyResult<Pair> {
    let result = handles::PairResult::memory(code).map_err(to_pyerr("pair"))?;
    Ok(Pair {
        initiator: Session {
            inner: handles::Session(result.initiator),
        },
        responder: Session {
            inner: handles::Session(result.responder),
        },
        code: result.code,
    })
}

/// Run a cross-language conformance fixture; returns a canonical JSON report.
#[pyfunction]
fn conformance_run(fixture_json: &str) -> PyResult<String> {
    syncbond_ffi::scenario::run(fixture_json).map_err(to_pyerr("conformance"))
}

/// Last `SB_ERR_*` code of this thread, mirroring the C ABI.
#[pyfunction]
fn last_error_code() -> i32 {
    syncbond_ffi::error::last_error_code()
}

/// Last error text of this thread, mirroring the C ABI.
#[pyfunction]
fn last_error() -> Option<String> {
    let text = syncbond_ffi::error::last_error_ptr();
    if text.is_null() {
        return None;
    }
    let text = unsafe { std::ffi::CStr::from_ptr(text) };
    let text = text.to_string_lossy().into_owned();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// `SB_ERR_NONE`, for callers that compare against the header constants.
#[pyfunction]
fn err_none() -> i32 {
    SB_ERR_NONE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trip_and_rejects_bad_key() {
        Python::initialize();
        Python::attach(|py| {
            let identity = Identity::new();
            assert!(!identity.device_id().is_empty());
            let secret = identity.secret_key(py);
            assert_eq!(secret.len().unwrap(), 64);

            let restored = Identity::import(secret.as_bytes()).unwrap();
            assert_eq!(restored.device_id(), identity.device_id());
            assert_eq!(restored.public_key(py).len().unwrap(), 32);

            if let Err(err) = Identity::import(&[0u8; 10]) {
                assert!(err.to_string().contains("identity import"));
            } else {
                panic!("short key import must fail");
            }
        });
    }

    #[test]
    fn pair_memory_exposes_sessions_and_explicit_code() {
        Python::initialize();
        let generated = pair_memory(None).unwrap();
        assert!(generated.code().len() >= 6);
        assert!(!generated.initiator().group_id().is_empty());
        assert_eq!(
            generated.initiator().group_id(),
            generated.responder().group_id()
        );
        assert!(!generated.initiator().peer_device_id().is_empty());
        assert!(!generated.initiator().invalidated());

        let explicit = pair_memory(Some("K7Q2M4")).unwrap();
        assert_eq!(explicit.code(), "K7Q2M4");
    }

    #[test]
    fn session_send_recv_round_trip_and_invalidate() {
        Python::initialize();
        let pair = pair_memory(None).unwrap();
        let initiator = pair.initiator();
        let responder = pair.responder();

        let worker = std::thread::spawn(move || responder.recv().unwrap());
        initiator.send(b"ping").unwrap();
        assert_eq!(worker.join().unwrap(), b"ping");

        assert!(!initiator.invalidated());
        initiator.invalidate();
        assert!(initiator.invalidated());
    }

    #[test]
    fn replicator_put_get_delete_and_json_views() {
        Python::initialize();
        let replicator = Replicator::new("py-node", 0, 0).unwrap();
        assert_eq!(replicator.node_id(), "py-node");
        assert_eq!(replicator.record_count(), 0);

        replicator.put("key-a", &[1, 2, 3]).unwrap();
        replicator.put("key-b", &[4]).unwrap();
        assert_eq!(replicator.record_count(), 2);
        assert_eq!(replicator.oplog_len(), 2);
        assert_eq!(replicator.get("key-a"), Some(vec![1, 2, 3]));
        assert_eq!(replicator.get("missing"), None);

        let keys = replicator.live_keys_json();
        assert!(keys.contains("key-a") && keys.contains("key-b"), "{keys}");

        let op = replicator.op_json(0).unwrap();
        assert!(op.contains("key-a"), "{op}");
        assert!(replicator.op_json(99).is_err());

        // Re-applying the wire form of our own op is a duplicate.
        let wire_op = replicator.op_json(0).unwrap();
        assert!(
            !replicator.apply_remote_json(&wire_op).unwrap(),
            "{wire_op}"
        );
        assert!(replicator.apply_remote_json("not json").is_err());
        assert!(replicator.records_json().contains("key-a"));
        assert!(replicator.gc_barriers_json().contains('{'));

        replicator.delete("key-a").unwrap();
        assert_eq!(replicator.get("key-a"), None);
        assert_eq!(
            replicator.gc_tombstones(u64::MAX, 0).unwrap(),
            1,
            "gc now clears the fresh tombstone"
        );
    }

    #[test]
    fn sync_pair_exchanges_oplogs_both_directions() {
        Python::initialize();
        let pair = pair_memory(None).unwrap();
        let left = Replicator::new("left", 0, 0).unwrap();
        let right = Replicator::new("right", 0, 0).unwrap();
        left.put("shared", &[7]).unwrap();

        let (left_ops, right_ops) =
            Python::attach(|py| sync_pair(py, &left, &pair.initiator(), &right, &pair.responder()))
                .unwrap();
        // The initiator pushes its one op; the responder starts with an
        // empty oplog, but the forwarding contract makes it reply with the
        // op it just received (original op id preserved, so left's dedup
        // absorbs the echo).
        assert_eq!((left_ops, right_ops), (1, 1));
        assert_eq!(right.get("shared"), Some(vec![7]));
    }

    #[test]
    fn keyring_seal_open_rotate_and_validation() {
        Python::initialize();
        let keyring = Keyring::new("group", None, None).unwrap();
        assert_eq!(keyring.epoch(), 1);

        let envelope = keyring.seal("device", b"hello");
        assert_eq!(
            keyring.open(&envelope).unwrap(),
            b"hello".to_vec(),
            "first open succeeds"
        );
        assert!(keyring.open(&envelope).is_err(), "replay is rejected");

        let (next_epoch, key) = keyring.rotate();
        assert_eq!(next_epoch, 2);
        assert_eq!(key.len(), 32);
        assert_eq!(
            Keyring::new("group", Some(next_epoch), Some(&key))
                .unwrap()
                .epoch(),
            2
        );

        if let Err(err) = Keyring::new("group", Some(1), None) {
            assert!(err.to_string().contains("both epoch and key"));
        } else {
            panic!("half-specified keyring must fail");
        }
        assert!(
            Python::attach(|_| Keyring::new("group", Some(1), Some(&[0u8; 5])).is_err()),
            "short key import must be rejected"
        );
    }

    #[test]
    fn conformance_and_error_helpers() {
        Python::initialize();
        assert_eq!(err_none(), 0);
        assert_eq!(last_error_code(), 0);
        assert_eq!(last_error(), None);

        assert!(conformance_run("not json").is_err());
        assert_ne!(last_error_code(), 0, "failure records an ABI error code");
        assert!(last_error().is_some());
    }

    #[test]
    fn empty_error_text_reads_as_none() {
        syncbond_ffi::error::set_last_error(Some(syncbond_ffi::error::FfiError::new(-1, "")));
        assert_eq!(last_error(), None, "an empty error text is no error text");
        syncbond_ffi::error::set_last_error(None);
    }

    /// `sync` blocks in one direction, so the responder half runs on a
    /// worker thread, exactly like `sync_pair` does internally.
    #[test]
    fn direct_sync_blocks_until_both_halves_finish() {
        Python::initialize();
        let pair = pair_memory(None).unwrap();
        let left = Replicator::new("direct-left", 0, 0).unwrap();
        let right = Replicator::new("direct-right", 0, 0).unwrap();
        left.put("k", &[1]).unwrap();

        let right_view = Replicator {
            inner: Arc::clone(&right.inner),
        };
        let responder = pair.responder();
        let worker = std::thread::spawn(move || right_view.sync(&responder, false).unwrap());

        let initiator = pair.initiator();
        let left_sent = left.sync(&initiator, true).unwrap();
        let right_sent = worker.join().unwrap();

        // Forwarding contract: the responder replies with the received op.
        assert_eq!((left_sent, right_sent), (1, 1));
        assert_eq!(right.get("k"), Some(vec![1]));
    }

    #[test]
    fn module_registration_exposes_the_public_surface() {
        Python::initialize();
        Python::attach(|py| {
            let module = pyo3::types::PyModule::new(py, "syncbond").expect("module");
            syncbond(&module).expect("registration");
            for name in [
                "Identity",
                "Session",
                "Replicator",
                "Pair",
                "Keyring",
                "Error",
                "sync_pair",
                "pair_memory",
                "conformance_run",
                "last_error_code",
                "last_error",
                "err_none",
                "LWW_HLC",
                "OR_SET",
                "PN_COUNTER",
            ] {
                assert!(module.getattr(name).is_ok(), "{name} must be registered");
            }
            assert_eq!(
                module.getattr("OR_SET").unwrap().extract::<u32>().unwrap(),
                syncbond_ffi::error::SB_STRATEGY_OR_SET
            );
        });
    }
}

#[pymodule]
fn syncbond(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Identity>()?;
    module.add_class::<Session>()?;
    module.add_class::<Replicator>()?;
    module.add_class::<Pair>()?;
    module.add_class::<Keyring>()?;
    module.add_function(wrap_pyfunction!(sync_pair, module)?)?;
    module.add_function(wrap_pyfunction!(pair_memory, module)?)?;
    module.add_function(wrap_pyfunction!(conformance_run, module)?)?;
    module.add_function(wrap_pyfunction!(last_error_code, module)?)?;
    module.add_function(wrap_pyfunction!(last_error, module)?)?;
    module.add_function(wrap_pyfunction!(err_none, module)?)?;
    module.add("Error", module.py().get_type::<Error>())?;
    module.add("LWW_HLC", syncbond_ffi::error::SB_STRATEGY_LWW_HLC)?;
    module.add("OR_SET", syncbond_ffi::error::SB_STRATEGY_OR_SET)?;
    module.add("PN_COUNTER", syncbond_ffi::error::SB_STRATEGY_PN_COUNTER)?;
    Ok(())
}
