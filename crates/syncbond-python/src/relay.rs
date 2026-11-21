//! Relay driver over the syncbond-ffi handle layer (todo.md DSR-38): one
//! native driver owns the whole network session — the relay client, the
//! tokio runtime and one worker thread that runs the core driver loop —
//! plus the device state. Blocking work (`start`, `stop`, `write`, `delete`,
//! `get`, `export_state`) runs with the GIL released (`Python::detach`), so
//! network waits never block other Python threads. This layer only marshals;
//! the driver logic lives in syncbond-core via the handle layer, so the
//! Python semantics cannot drift from the other language bindings.

use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use syncbond_core::sync_driver::DriverConfig;
use syncbond_ffi::error::{FfiError, SB_STRATEGY_LWW_HLC};
use syncbond_ffi::handles::{self, import_snapshot, ReceiveState, RelayDriver as HandleDriver};

use crate::{to_pyerr, Error};

/// Monotonic counters the host polls; a running driver keeps them growing.
#[pyclass]
pub struct RelayProgress {
    running: bool,
    cycles: u64,
    sent_batches: u64,
    sent_envelopes: u64,
    pages_pulled: u64,
    applied: u64,
}

#[pymethods]
impl RelayProgress {
    #[getter]
    fn running(&self) -> bool {
        self.running
    }

    #[getter]
    fn cycles(&self) -> u64 {
        self.cycles
    }

    #[getter]
    fn sent_batches(&self) -> u64 {
        self.sent_batches
    }

    #[getter]
    fn sent_envelopes(&self) -> u64 {
        self.sent_envelopes
    }

    #[getter]
    fn pages_pulled(&self) -> u64 {
        self.pages_pulled
    }

    #[getter]
    fn applied(&self) -> u64 {
        self.applied
    }
}

/// One device's session against one relay channel, driven from Python.
///
/// Construction owns the device: it generates the identity, imports the
/// group key, and either creates a fresh replicator under `node_id` or
/// restores one from an exported state snapshot (`state`). From then on the
/// host only configures, starts, stops and interleaves writes; the worker
/// syncs in the background and never blocks the interpreter.
#[pyclass]
pub struct RelayDriver {
    inner: Arc<HandleDriver>,
}

#[pymethods]
impl RelayDriver {
    /// Build a driver over one live relay channel. `group_key` is the shared
    /// 32-byte group key material (two devices in one group import the same
    /// bytes); `node_id` names a fresh replicator and is ignored when
    /// `state` restores one. `ca_der` pins a CA when `tls_mode` is
    /// `TLS_VALIDATE_CA`. `state` is an exported snapshot to resume from.
    // The argument list mirrors `RelayDriver::new` (and the C ABI) one-to-one;
    // the handle layer is the contract every binding follows, so the count is
    // fixed.
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        relay_url, channel_id, channel_token, server_id, cursor_channel, group_id, key_epoch,
        group_key, node_id, timeout_ms, tls_mode = 0, ca_der = None, state = None
    ))]
    fn new(
        relay_url: &str,
        channel_id: &str,
        channel_token: &str,
        server_id: &str,
        cursor_channel: &str,
        group_id: &str,
        key_epoch: u64,
        group_key: &[u8],
        node_id: &str,
        timeout_ms: u64,
        tls_mode: u32,
        ca_der: Option<&[u8]>,
        state: Option<&[u8]>,
    ) -> PyResult<Self> {
        if group_key.len() != 32 {
            return Err(Error::new_err("group key must be exactly 32 bytes"));
        }
        let identity = handles::Identity::generate();
        let keyring = handles::Keyring::import(group_id, key_epoch, group_key)
            .map_err(to_pyerr("keyring import"))?;
        // The replicator and receive position come back fresh or restored.
        let (replicator, receive) = match &state {
            Some(blob) => {
                import_snapshot(blob, SB_STRATEGY_LWW_HLC).map_err(to_pyerr("state import"))?
            }
            None => (
                handles::Replicator::new_clock(node_id, SB_STRATEGY_LWW_HLC, 0)
                    .map_err(to_pyerr("replicator create"))?,
                ReceiveState::new(),
            ),
        };
        let driver = HandleDriver::new(
            relay_url,
            channel_id,
            channel_token,
            server_id,
            cursor_channel,
            group_id,
            key_epoch,
            identity,
            keyring,
            replicator,
            receive,
            timeout_ms,
            tls_mode,
            ca_der.unwrap_or_default(),
        )
        .map_err(to_pyerr("relay driver create"))?;
        Ok(Self {
            inner: Arc::new(driver),
        })
    }

    /// Replace the loop's pacing knobs; only effective before `start`.
    fn config(
        &self,
        page_limit: u16,
        max_pages_per_cycle: usize,
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
        max_attempts: u32,
        idle_interval_ms: u64,
    ) {
        self.inner.set_config(DriverConfig {
            page_limit,
            max_pages_per_cycle,
            initial_backoff: Duration::from_millis(initial_backoff_ms),
            max_backoff: Duration::from_millis(max_backoff_ms),
            max_attempts,
            idle_interval: Duration::from_millis(idle_interval_ms),
        });
    }

    /// Spawn the worker thread. Runs off the GIL; a second call while
    /// running is an error, and a driver can be started again after `stop`.
    fn start(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.start_core().map_err(to_pyerr("driver start")))
    }

    /// Cancel the loop and join the worker. Idempotent and safe to call
    /// again; this is also the resource-close path (the final `drop` does
    /// the same join). The stop reason and any error text remain queryable.
    fn stop(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.stop_core().map_err(to_pyerr("driver stop")))
    }

    /// Stage a local write; the worker sends it on its next cycle. Blocks
    /// only until the current cycle finishes, and runs off the GIL.
    fn write<'py>(&self, py: Python<'py>, key: &str, payload: &'py [u8]) -> PyResult<()> {
        py.detach(|| {
            self.write_core(key, payload)
                .map_err(to_pyerr("driver write"))
        })
    }

    /// Stage a local delete (a causal tombstone).
    fn delete(&self, py: Python<'_>, key: &str) -> PyResult<()> {
        py.detach(|| self.delete_core(key).map_err(to_pyerr("driver delete")))
    }

    /// Payload bytes of a live record from the device's committed state, or
    /// `None` when the key is absent or tombstoned. Off the GIL: a running
    /// worker may hold the device state for a cycle.
    fn get<'py>(&self, py: Python<'py>, key: &str) -> Option<Bound<'py, PyBytes>> {
        let payload = py.detach(|| self.get_core(key));
        payload.map(|bytes| PyBytes::new(py, &bytes))
    }

    /// Export the committed state and receive cursors as one snapshot, the
    /// blob a later `state` restores from.
    fn export_state<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let blob = py.detach(|| self.export_state_core().map_err(to_pyerr("state export")))?;
        Ok(PyBytes::new(py, &blob))
    }

    /// The counters the worker has accumulated so far.
    fn progress(&self) -> RelayProgress {
        let (cycles, sent_batches, sent_envelopes, pages_pulled, applied) = self.inner.counters();
        RelayProgress {
            running: self.inner.running(),
            cycles,
            sent_batches,
            sent_envelopes,
            pages_pulled,
            applied,
        }
    }

    #[getter]
    fn running(&self) -> bool {
        self.inner.running()
    }

    /// One of the `DRIVER_STOP_*` constants; `DRIVER_STOP_NONE` while
    /// running or never started.
    #[getter]
    fn stop_reason(&self) -> i32 {
        self.inner.stop_reason()
    }

    /// Why the loop ended, if it ended with an error; `None` when it ended
    /// cleanly (or is still running).
    #[getter]
    fn error(&self) -> Option<String> {
        self.inner.stop_error()
    }
}

/// The blocking half of the surface, with no Python token: the `#[pymethods]`
/// wrappers release the GIL and call these, and the Rust tests drive them
/// directly, so the GIL-release decision lives in exactly one place.
impl RelayDriver {
    fn start_core(&self) -> Result<(), FfiError> {
        self.inner.start()
    }

    fn stop_core(&self) -> Result<(), FfiError> {
        self.inner.stop()
    }

    fn write_core(&self, key: &str, payload: &[u8]) -> Result<(), FfiError> {
        self.inner.write(key, payload)
    }

    fn delete_core(&self, key: &str) -> Result<(), FfiError> {
        self.inner.delete(key)
    }

    fn get_core(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    fn export_state_core(&self) -> Result<Vec<u8>, FfiError> {
        self.inner.export_state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use syncbond_ffi::error::{SB_DRIVER_STOP_CANCELLED, SB_DRIVER_STOP_NONE};

    fn group_key() -> &'static [u8] {
        &[7u8; 32]
    }

    fn fast_config(driver: &RelayDriver) {
        driver.config(2, 8, 1, 2, 1000, 1);
    }

    fn wait_until(mut predicate: impl FnMut() -> bool, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        predicate()
    }

    fn fresh(relay_url: &str, channel_id: &str, token: &str, node: &str) -> RelayDriver {
        RelayDriver::new(
            relay_url,
            channel_id,
            token,
            "relay-1",
            "ch",
            "group-1",
            1,
            group_key(),
            node,
            5_000,
            0,
            None,
            None,
        )
        .expect("driver")
    }

    fn restored(
        relay_url: &str,
        channel_id: &str,
        token: &str,
        node: &str,
        state: &[u8],
    ) -> RelayDriver {
        RelayDriver::new(
            relay_url,
            channel_id,
            token,
            "relay-1",
            "ch",
            "group-1",
            1,
            group_key(),
            node,
            5_000,
            0,
            None,
            Some(state),
        )
        .expect("restored driver")
    }

    #[test]
    fn constructor_rejects_bad_arguments() {
        let err = RelayDriver::new(
            "http://127.0.0.1:1",
            "",
            "tok",
            "s",
            "c",
            "g",
            1,
            group_key(),
            "n",
            100,
            0,
            None,
            None,
        )
        .err()
        .expect("empty channel id is refused");
        assert!(
            err.to_string().contains("must not be empty"),
            "empty channel id surfaces the handle error: {err}"
        );

        let err = RelayDriver::new(
            "http://127.0.0.1:1",
            "ch",
            "tok",
            "s",
            "c",
            "g",
            1,
            &[1, 2, 3],
            "n",
            100,
            0,
            None,
            None,
        )
        .err()
        .expect("a short group key is refused");
        assert!(
            err.to_string().contains("32"),
            "a short group key is refused: {err}"
        );

        let err = RelayDriver::new(
            "http://127.0.0.1:1",
            "ch",
            "tok",
            "s",
            "c",
            "g",
            1,
            group_key(),
            "n",
            100,
            7,
            None,
            None,
        )
        .err()
        .expect("an unknown tls mode is refused");
        assert!(
            err.to_string().contains("tls mode"),
            "an unknown tls mode is refused: {err}"
        );

        let err = RelayDriver::new(
            "http://127.0.0.1:1",
            "ch",
            "tok",
            "s",
            "c",
            "g",
            1,
            group_key(),
            "n",
            0,
            0,
            None,
            None,
        )
        .err()
        .expect("a zero timeout is refused");
        assert!(
            err.to_string().contains("timeout"),
            "a zero timeout is refused: {err}"
        );
    }

    #[test]
    fn dead_endpoint_driver_lifecycle_and_state() {
        let driver = fresh("http://127.0.0.1:1", "ch", "tok", "py-dead");
        fast_config(&driver);
        assert!(!driver.running(), "not running yet");
        assert_eq!(driver.stop_reason(), SB_DRIVER_STOP_NONE);
        assert!(driver.error().is_none(), "no error text yet");
        assert!(!driver.progress().running);

        // Start spawns the worker, which retries the dead endpoint in a loop.
        driver.start_core().expect("start");
        assert!(driver.running(), "the worker is up");

        // The host writes and reads through the marshaling layer.
        driver.write_core("k", b"v").expect("write");
        assert_eq!(driver.get_core("k"), Some(b"v".to_vec()));

        // The committed state exports and re-imports with the write intact.
        let blob = driver.export_state_core().expect("export");
        assert!(!blob.is_empty(), "the snapshot is not empty");
        let (rep, recv) = import_snapshot(&blob, SB_STRATEGY_LWW_HLC).expect("snapshot imports");
        drop((rep, recv));

        // A delete stages a tombstone that survives the snapshot too.
        driver.delete_core("k").expect("delete");
        assert_eq!(driver.get_core("k"), None);
        let blob = driver.export_state_core().expect("tombstoned export");
        import_snapshot(&blob, SB_STRATEGY_LWW_HLC).expect("tombstoned snapshot imports");

        // Stop cancels and joins; the reason is cancellation, not an error.
        driver.stop_core().expect("stop");
        assert!(!driver.running(), "the worker joined");
        assert_eq!(driver.stop_reason(), SB_DRIVER_STOP_CANCELLED);
        assert!(driver.error().is_none(), "a clean stop has no error");
    }

    #[test]
    fn restore_constructor_resumes_from_an_exported_state() {
        let driver = fresh("http://127.0.0.1:1", "ch", "tok", "py-first");
        fast_config(&driver);
        driver.write_core("persist", b"p").expect("write");
        let blob = driver.export_state_core().expect("export");

        // A second driver rebuilt from the snapshot alone (a fresh node id,
        // which the state overrides) sees the committed write.
        let restored = restored("http://127.0.0.1:1", "ch", "tok", "different-node", &blob);
        assert_eq!(
            restored.get_core("persist"),
            Some(b"p".to_vec()),
            "the restored device sees the committed write"
        );
    }

    #[test]
    fn stop_is_idempotent_and_drop_joins_the_worker() {
        let driver = fresh("http://127.0.0.1:1", "ch", "tok", "py-idle");
        fast_config(&driver);
        driver.start_core().expect("start");
        // A second stop after a clean one is a no-op, and dropping a live
        // driver joins its worker instead of leaking the thread.
        driver.stop_core().expect("first stop");
        driver.stop_core().expect("second stop");
        assert_eq!(driver.stop_reason(), SB_DRIVER_STOP_CANCELLED);

        let driver = fresh("http://127.0.0.1:1", "ch", "tok", "py-drop");
        fast_config(&driver);
        driver.start_core().expect("start");
        drop(driver);
    }

    #[test]
    fn two_drivers_sync_through_a_real_relay_and_recover() {
        use syncbond_relay_client::{RelayClient, TlsPolicy};
        use syncbond_relay_protocol::dto::CredentialScope;
        use syncbond_server::test_support::boot_relay;

        let relay = boot_relay();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let client = RelayClient::new(
            &format!("http://{}", relay.address),
            TlsPolicy::Validate,
            Duration::from_secs(5),
        )
        .expect("client");

        let channel = runtime
            .block_on(client.create_channel(&relay.admin, "py-create-01"))
            .expect("channel");
        let token_a = runtime
            .block_on(client.issue_credential(
                &relay.admin,
                &channel.channel_id,
                &[CredentialScope::Append, CredentialScope::Pull],
                Some("py-a"),
                "py-issue-01",
            ))
            .expect("credential a")
            .token;
        let token_b = runtime
            .block_on(client.issue_credential(
                &relay.admin,
                &channel.channel_id,
                &[CredentialScope::Append, CredentialScope::Pull],
                Some("py-b"),
                "py-issue-02",
            ))
            .expect("credential b")
            .token;

        let relay_url = format!("http://{}", relay.address);
        let a = fresh(&relay_url, &channel.channel_id, &token_a, "py-a");
        let b = fresh(&relay_url, &channel.channel_id, &token_b, "py-b");
        fast_config(&a);
        fast_config(&b);
        a.start_core().expect("start a");
        b.start_core().expect("start b");

        a.write_core("a/0", b"a0").expect("write a/0");
        b.write_core("b/0", b"b0").expect("write b/0");
        b.write_core("b/1", b"b1").expect("write b/1");

        // Both directions converge through the relay.
        let converged = wait_until(
            || a.get_core("b/1").is_some() && b.get_core("a/0").is_some(),
            Duration::from_secs(15),
        );
        assert!(
            converged,
            "both devices converged: a={:?} b={:?}",
            a.progress().cycles,
            b.progress().cycles
        );
        assert_eq!(a.get_core("b/0"), Some(b"b0".to_vec()));
        assert_eq!(b.get_core("a/0"), Some(b"a0".to_vec()));

        // A stops cleanly and exports; B keeps writing while A is down.
        a.stop_core().expect("stop a");
        assert_eq!(a.stop_reason(), SB_DRIVER_STOP_CANCELLED);
        let blob = a.export_state_core().expect("export a");
        b.write_core("b/2", b"b2").expect("write b/2");

        // A resumes from the snapshot and catches exactly what it missed.
        let restored = restored(&relay_url, &channel.channel_id, &token_a, "py-a", &blob);
        fast_config(&restored);
        restored.start_core().expect("start restored");
        let caught = wait_until(
            || restored.get_core("b/2").is_some(),
            Duration::from_secs(15),
        );
        assert!(
            caught,
            "the restored device pulled what B wrote while it was down: {:?}",
            restored.progress().cycles
        );

        restored.stop_core().expect("stop restored");
        b.stop_core().expect("stop b");
        assert_eq!(restored.stop_reason(), SB_DRIVER_STOP_CANCELLED);
        assert_eq!(b.stop_reason(), SB_DRIVER_STOP_CANCELLED);
    }
}
