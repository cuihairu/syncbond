//! Relay driver over the syncbond C ABI (todo.md DSR-37): one native driver
//! owns the whole network session — the relay HTTP client, the tokio runtime
//! and one worker thread that runs the core driver loop — plus the device
//! state. The Node surface is async wherever the ABI call can block
//! (`start`, `stop`, `write`, `delete`, `get`, `export_state` run on the
//! libuv thread pool through napi `Task`s), so the JS main thread never
//! waits on the driver's worker. This layer only marshals; the driver logic
//! lives in syncbond-core via the C ABI, so the Node semantics cannot drift
//! from the other language bindings.

use crate::{check, cstr, last_error, take_string};
use napi::bindgen_prelude::{AsyncTask, Uint8Array};
use napi::{Env, Result, Task};
use napi_derive::napi;
use std::sync::{Arc, Mutex};
use syncbond_ffi::abi;
use syncbond_ffi::error::SB_STRATEGY_LWW_HLC;

/// One owned relay driver; released (worker stopped and joined) on GC.
struct DriverHandle(*mut syncbond_ffi::sb_relay_driver);
unsafe impl Send for DriverHandle {}
unsafe impl Sync for DriverHandle {}
impl Drop for DriverHandle {
    fn drop(&mut self) {
        unsafe { abi::sb_relay_driver_free(self.0) };
    }
}

/// Monotonic counters the host polls; a running driver keeps them growing.
#[derive(Debug)]
#[napi(object)]
pub struct NativeRelayProgress {
    pub running: bool,
    pub cycles: f64,
    pub sent_batches: f64,
    pub sent_envelopes: f64,
    pub pages_pulled: f64,
    pub applied: f64,
}

/// One device's session against one relay channel, driven from Node.
///
/// Construction owns the device: it generates the identity, imports the
/// group key, and either creates a fresh replicator under `node_id` or
/// restores one from an exported state snapshot (`state`). From then on the
/// host only configures, starts, stops and interleaves writes; the worker
/// syncs in the background and never blocks the JS main thread.
#[napi]
pub struct NativeRelayDriver {
    inner: Arc<Mutex<DriverHandle>>,
}

#[napi]
impl NativeRelayDriver {
    /// Build a driver over one live relay channel. `group_key` is the shared
    /// 32-byte group key material (two devices in one group import the same
    /// bytes); `node_id` names a fresh replicator and is ignored when
    /// `state` restores one. `ca_der` pins a CA when `tls_mode` is
    /// `SB_TLS_VALIDATE_CA`. `state` is an exported snapshot to resume from.
    // The argument list mirrors `sb_relay_driver_new` one-to-one; the C ABI
    // is the contract every binding follows, so the count is fixed.
    #[napi(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay_url: String,
        channel_id: String,
        channel_token: String,
        server_id: String,
        cursor_channel: String,
        group_id: String,
        key_epoch: i64,
        group_key: Uint8Array,
        node_id: String,
        timeout_ms: i64,
        tls_mode: u32,
        ca_der: Option<Uint8Array>,
        state: Option<Uint8Array>,
    ) -> Result<Self> {
        if group_key.len() != 32 {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "group key must be exactly 32 bytes",
            ));
        }
        let c_relay = cstr(&relay_url)?;
        let c_channel = cstr(&channel_id)?;
        let c_token = cstr(&channel_token)?;
        let c_server = cstr(&server_id)?;
        let c_cursor = cstr(&cursor_channel)?;
        let c_group = cstr(&group_id)?;
        let c_node = cstr(&node_id)?;
        let (ca_ptr, ca_len) = match &ca_der {
            Some(der) => (der.as_ptr(), der.len()),
            None => (std::ptr::null(), 0),
        };

        // identity and keyring cannot fail here (the key length was already
        // checked), so no cleanup is needed between the two.
        let identity = abi::sb_identity_generate();
        if identity.is_null() {
            return Err(last_error());
        }
        let keyring = unsafe {
            abi::sb_keyring_import(c_group.as_ptr(), key_epoch as u64, group_key.as_ptr())
        };
        if keyring.is_null() {
            unsafe { abi::sb_identity_free(identity) };
            return Err(last_error());
        }

        // The replicator and receive position come back fresh or restored.
        let (replicator, receive) = match &state {
            Some(blob) => {
                let mut rep: *mut syncbond_ffi::sb_replicator = std::ptr::null_mut();
                let mut recv: *mut syncbond_ffi::sb_receive_state = std::ptr::null_mut();
                let code = unsafe {
                    abi::sb_state_import(
                        blob.as_ptr(),
                        blob.len(),
                        SB_STRATEGY_LWW_HLC,
                        &mut rep,
                        &mut recv,
                    )
                };
                if code != 0 {
                    unsafe {
                        abi::sb_identity_free(identity);
                        abi::sb_keyring_free(keyring);
                    }
                    return Err(last_error());
                }
                (rep, recv)
            }
            None => (
                unsafe { abi::sb_replicator_new(c_node.as_ptr(), SB_STRATEGY_LWW_HLC) },
                abi::sb_receive_state_new(),
            ),
        };
        if replicator.is_null() || receive.is_null() {
            unsafe {
                abi::sb_identity_free(identity);
                abi::sb_keyring_free(keyring);
                abi::sb_replicator_free(replicator);
                abi::sb_receive_state_free(receive);
            }
            return Err(last_error());
        }

        let driver = unsafe {
            abi::sb_relay_driver_new(
                c_relay.as_ptr(),
                c_channel.as_ptr(),
                c_token.as_ptr(),
                c_server.as_ptr(),
                c_cursor.as_ptr(),
                c_group.as_ptr(),
                key_epoch as u64,
                identity,
                keyring,
                replicator,
                receive,
                timeout_ms as u64,
                tls_mode,
                ca_ptr,
                ca_len,
            )
        };
        // The ABI takes ownership of the four handles on success AND failure.
        if driver.is_null() {
            return Err(last_error());
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(DriverHandle(driver))),
        })
    }

    /// Replace the loop's pacing knobs; only effective before `start()`.
    #[napi]
    pub fn config(
        &self,
        page_limit: u32,
        max_pages: u32,
        initial_backoff_ms: i64,
        max_backoff_ms: i64,
        max_attempts: u32,
        idle_interval_ms: i64,
    ) -> Result<()> {
        let handle = self.inner.lock().unwrap();
        unsafe {
            check(abi::sb_relay_driver_config(
                handle.0,
                page_limit as u16,
                max_pages as usize,
                initial_backoff_ms as u64,
                max_backoff_ms as u64,
                max_attempts,
                idle_interval_ms as u64,
            ))
        }
    }

    /// Spawn the worker thread. Runs off the main thread; the returned
    /// promise resolves when the thread is up (or rejects on an input error,
    /// e.g. a second start while running).
    #[napi]
    pub fn start(&self) -> AsyncTask<DriverCallTask> {
        AsyncTask::new(DriverCallTask {
            driver: Arc::clone(&self.inner),
            op: DriverOp::Start,
        })
    }

    /// Cancel the loop and join the worker. Idempotent and safe to call
    /// again; the returned promise resolves when the thread is gone.
    #[napi]
    pub fn stop(&self) -> AsyncTask<DriverCallTask> {
        AsyncTask::new(DriverCallTask {
            driver: Arc::clone(&self.inner),
            op: DriverOp::Stop,
        })
    }

    /// Stage a local write; the worker sends it on its next cycle. Blocks
    /// only until the current cycle finishes, and runs off the main thread.
    #[napi]
    pub fn write(&self, key: String, payload: Uint8Array) -> AsyncTask<DriverCallTask> {
        AsyncTask::new(DriverCallTask {
            driver: Arc::clone(&self.inner),
            op: DriverOp::Write(key, payload.to_vec()),
        })
    }

    /// Stage a local delete (a causal tombstone).
    #[napi]
    pub fn delete(&self, key: String) -> AsyncTask<DriverCallTask> {
        AsyncTask::new(DriverCallTask {
            driver: Arc::clone(&self.inner),
            op: DriverOp::Delete(key),
        })
    }

    /// Read one key from the device's committed state; resolves to the
    /// payload or null when the key is absent or tombstoned.
    #[napi]
    pub fn get(&self, key: String) -> AsyncTask<DriverGetTask> {
        AsyncTask::new(DriverGetTask {
            driver: Arc::clone(&self.inner),
            key,
        })
    }

    /// Export the committed state and receive cursors as one snapshot, the
    /// blob a later `state` restores from.
    #[napi]
    pub fn export_state(&self) -> AsyncTask<DriverExportTask> {
        AsyncTask::new(DriverExportTask {
            driver: Arc::clone(&self.inner),
        })
    }

    #[napi(getter)]
    pub fn running(&self) -> bool {
        let handle = self.inner.lock().unwrap();
        unsafe { abi::sb_relay_driver_running(handle.0) != 0 }
    }

    /// One of the `SB_DRIVER_STOP_*` codes; `SB_DRIVER_STOP_NONE` while
    /// running or never started.
    #[napi(getter)]
    pub fn stop_reason(&self) -> u32 {
        let handle = self.inner.lock().unwrap();
        unsafe { abi::sb_relay_driver_stop_reason(handle.0) as u32 }
    }

    /// Why the loop ended, if it ended with an error; null when it ended
    /// cleanly (or is still running).
    #[napi(getter)]
    pub fn error(&self) -> Result<Option<String>> {
        let handle = self.inner.lock().unwrap();
        let text = unsafe { abi::sb_relay_driver_error(handle.0) };
        if text.is_null() {
            return Ok(None);
        }
        let owned = unsafe { take_string(text)? };
        Ok(Some(owned))
    }

    /// The counters the worker has accumulated so far.
    #[napi]
    pub fn progress(&self) -> Result<NativeRelayProgress> {
        let handle = self.inner.lock().unwrap();
        let mut p: abi::sb_relay_progress_t = unsafe { std::mem::zeroed() };
        unsafe { check(abi::sb_relay_driver_progress(handle.0, &mut p))? };
        Ok(NativeRelayProgress {
            running: p.running != 0,
            cycles: p.cycles as f64,
            sent_batches: p.sent_batches as f64,
            sent_envelopes: p.sent_envelopes as f64,
            pages_pulled: p.pages_pulled as f64,
            applied: p.applied as f64,
        })
    }
}

/// One unit-returning driver call; which call it is.
enum DriverOp {
    Start,
    Stop,
    Write(String, Vec<u8>),
    Delete(String),
}

pub struct DriverCallTask {
    driver: Arc<Mutex<DriverHandle>>,
    op: DriverOp,
}

impl Task for DriverCallTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        let handle = self.driver.lock().unwrap();
        unsafe {
            match &self.op {
                DriverOp::Start => check(abi::sb_relay_driver_start(handle.0)),
                DriverOp::Stop => check(abi::sb_relay_driver_stop(handle.0)),
                DriverOp::Write(key, payload) => {
                    let c_key = cstr(key)?;
                    check(abi::sb_relay_driver_write(
                        handle.0,
                        c_key.as_ptr(),
                        payload.as_ptr(),
                        payload.len(),
                    ))
                }
                DriverOp::Delete(key) => {
                    let c_key = cstr(key)?;
                    check(abi::sb_relay_driver_delete(handle.0, c_key.as_ptr()))
                }
            }
        }
    }

    fn resolve(&mut self, _env: Env, _output: Self::Output) -> Result<Self::JsValue> {
        Ok(())
    }
}

pub struct DriverGetTask {
    driver: Arc<Mutex<DriverHandle>>,
    key: String,
}

impl Task for DriverGetTask {
    type Output = Option<Vec<u8>>;
    type JsValue = Option<Uint8Array>;

    fn compute(&mut self) -> Result<Self::Output> {
        let handle = self.driver.lock().unwrap();
        let c_key = cstr(&self.key)?;
        unsafe {
            let mut buffer: abi::sb_buffer_t = abi::sb_buffer_t {
                data: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            let code = abi::sb_relay_driver_get(handle.0, c_key.as_ptr(), &mut buffer);
            if code == syncbond_ffi::error::SB_RESULT_ABSENT {
                return Ok(None);
            }
            check(code)?;
            let bytes = std::slice::from_raw_parts(buffer.data, buffer.len).to_vec();
            abi::sb_free_buffer(&buffer);
            Ok(Some(bytes))
        }
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.map(Uint8Array::new))
    }
}

pub struct DriverExportTask {
    driver: Arc<Mutex<DriverHandle>>,
}

impl Task for DriverExportTask {
    type Output = Vec<u8>;
    type JsValue = Uint8Array;

    fn compute(&mut self) -> Result<Self::Output> {
        let handle = self.driver.lock().unwrap();
        unsafe {
            let mut buffer: abi::sb_buffer_t = abi::sb_buffer_t {
                data: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            check(abi::sb_relay_driver_export_state(handle.0, &mut buffer))?;
            let bytes = std::slice::from_raw_parts(buffer.data, buffer.len).to_vec();
            abi::sb_free_buffer(&buffer);
            Ok(bytes)
        }
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(Uint8Array::new(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const STOP_NONE: u32 = 0;
    const STOP_CANCELLED: u32 = 1;

    fn fast_config(driver: &NativeRelayDriver) {
        driver.config(2, 8, 1, 2, 1000, 1).unwrap();
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

    fn group_key() -> Uint8Array {
        Uint8Array::new(vec![7u8; 32])
    }

    fn fresh(relay_url: &str, channel_id: &str, token: &str, node: &str) -> NativeRelayDriver {
        NativeRelayDriver::new(
            relay_url.to_owned(),
            channel_id.to_owned(),
            token.to_owned(),
            "relay-1".to_owned(),
            "ch".to_owned(),
            "group-1".to_owned(),
            1,
            group_key(),
            node.to_owned(),
            5_000,
            0,
            None,
            None,
        )
        .expect("driver")
    }

    // The AsyncTask wrappers only exist to hand the call to libuv; the test
    // drives the same compute() the pool would, on the test's own threads.
    fn drive(driver: &NativeRelayDriver, op: DriverOp) {
        DriverCallTask {
            driver: Arc::clone(&driver.inner),
            op,
        }
        .compute()
        .expect("task")
    }

    fn read(driver: &NativeRelayDriver, key: &str) -> Option<Vec<u8>> {
        DriverGetTask {
            driver: Arc::clone(&driver.inner),
            key: key.to_owned(),
        }
        .compute()
        .expect("get")
    }

    fn snapshot(driver: &NativeRelayDriver) -> Vec<u8> {
        DriverExportTask {
            driver: Arc::clone(&driver.inner),
        }
        .compute()
        .expect("export")
    }

    fn start(driver: &NativeRelayDriver) {
        drive(driver, DriverOp::Start);
    }

    fn stop(driver: &NativeRelayDriver) {
        drive(driver, DriverOp::Stop);
    }

    fn write(driver: &NativeRelayDriver, key: &str, value: &[u8]) {
        drive(driver, DriverOp::Write(key.to_owned(), value.to_vec()));
    }

    #[test]
    fn constructor_rejects_bad_arguments() {
        let err = NativeRelayDriver::new(
            "http://127.0.0.1:1".into(),
            String::new(),
            "tok".into(),
            "s".into(),
            "c".into(),
            "g".into(),
            1,
            group_key(),
            "n".into(),
            100,
            0,
            None,
            None,
        )
        .err()
        .expect("empty channel id is refused");
        assert!(
            format!("{err}").contains("code"),
            "empty channel id surfaces the ABI error: {err}"
        );

        let err = NativeRelayDriver::new(
            "http://127.0.0.1:1".into(),
            "ch".into(),
            "tok".into(),
            "s".into(),
            "c".into(),
            "g".into(),
            1,
            Uint8Array::new(vec![1, 2, 3]),
            "n".into(),
            100,
            0,
            None,
            None,
        )
        .err()
        .expect("a short group key is refused");
        assert!(
            format!("{err}").contains("32"),
            "a short group key is refused: {err}"
        );

        let err = NativeRelayDriver::new(
            "http://127.0.0.1:1".into(),
            "ch".into(),
            "tok".into(),
            "s".into(),
            "c".into(),
            "g".into(),
            1,
            group_key(),
            "n".into(),
            100,
            7,
            None,
            None,
        )
        .err()
        .expect("an unknown tls mode is refused");
        assert!(
            format!("{err}").contains("code"),
            "an unknown tls mode is refused: {err}"
        );
    }

    #[test]
    fn dead_endpoint_driver_lifecycle_and_state() {
        let driver = fresh("http://127.0.0.1:1", "ch", "tok", "napi-dead");
        fast_config(&driver);
        assert!(!driver.running(), "not running yet");
        assert_eq!(driver.stop_reason(), STOP_NONE);
        assert!(driver.error().unwrap().is_none(), "no error text yet");
        assert!(!driver.progress().unwrap().running);

        // Start spawns the worker, which retries the dead endpoint in a loop.
        start(&driver);
        assert!(driver.running(), "the worker is up");

        // The host writes and reads through the marshaling layer.
        write(&driver, "k", b"v");
        assert_eq!(read(&driver, "k"), Some(b"v".to_vec()));

        // The committed state exports and re-imports with the write intact.
        let blob = snapshot(&driver);
        assert!(!blob.is_empty(), "the snapshot is not empty");
        let mut rep: *mut syncbond_ffi::sb_replicator = std::ptr::null_mut();
        let mut recv: *mut syncbond_ffi::sb_receive_state = std::ptr::null_mut();
        let code = unsafe {
            abi::sb_state_import(
                blob.as_ptr(),
                blob.len(),
                SB_STRATEGY_LWW_HLC,
                &mut rep,
                &mut recv,
            )
        };
        assert_eq!(code, 0, "the snapshot re-imports");

        // A delete stages a tombstone that survives the snapshot too.
        drive(&driver, DriverOp::Delete("k".to_owned()));
        assert_eq!(read(&driver, "k"), None);
        let blob = snapshot(&driver);
        let mut rep2: *mut syncbond_ffi::sb_replicator = std::ptr::null_mut();
        let mut recv2: *mut syncbond_ffi::sb_receive_state = std::ptr::null_mut();
        let code = unsafe {
            abi::sb_state_import(
                blob.as_ptr(),
                blob.len(),
                SB_STRATEGY_LWW_HLC,
                &mut rep2,
                &mut recv2,
            )
        };
        assert_eq!(code, 0, "the tombstoned snapshot re-imports");

        // Stop cancels and joins; the reason is cancellation, not an error.
        stop(&driver);
        assert!(!driver.running(), "the worker joined");
        assert_eq!(driver.stop_reason(), STOP_CANCELLED);
        assert!(
            driver.error().unwrap().is_none(),
            "a clean stop has no error"
        );
    }

    #[test]
    fn restore_constructor_resumes_from_an_exported_state() {
        let driver = fresh("http://127.0.0.1:1", "ch", "tok", "napi-first");
        fast_config(&driver);
        write(&driver, "persist", b"p");
        let blob = snapshot(&driver);

        // A second driver rebuilt from the snapshot alone (a fresh node id,
        // which the state overrides) sees the committed write.
        let restored = NativeRelayDriver::new(
            "http://127.0.0.1:1".to_owned(),
            "ch".to_owned(),
            "tok".to_owned(),
            "relay-1".to_owned(),
            "ch".to_owned(),
            "group-1".to_owned(),
            1,
            group_key(),
            "different-node".to_owned(),
            5_000,
            0,
            None,
            Some(Uint8Array::new(blob)),
        )
        .expect("restored driver");
        assert_eq!(
            read(&restored, "persist"),
            Some(b"p".to_vec()),
            "the restored device sees the committed write"
        );
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
            .block_on(client.create_channel(&relay.admin, "napi-create-01"))
            .expect("channel");
        let token_a = runtime
            .block_on(client.issue_credential(
                &relay.admin,
                &channel.channel_id,
                &[CredentialScope::Append, CredentialScope::Pull],
                Some("napi-a"),
                "napi-issue-01",
            ))
            .expect("credential a")
            .token;
        let token_b = runtime
            .block_on(client.issue_credential(
                &relay.admin,
                &channel.channel_id,
                &[CredentialScope::Append, CredentialScope::Pull],
                Some("napi-b"),
                "napi-issue-02",
            ))
            .expect("credential b")
            .token;

        let relay_url = format!("http://{}", relay.address);
        let channel_id = channel.channel_id.clone();

        let a = fresh(&relay_url, &channel_id, &token_a, "napi-a");
        let b = fresh(&relay_url, &channel_id, &token_b, "napi-b");
        fast_config(&a);
        fast_config(&b);
        start(&a);
        start(&b);

        write(&a, "a/0", b"a0");
        write(&b, "b/0", b"b0");
        write(&b, "b/1", b"b1");

        // Both directions converge through the relay.
        let converged = wait_until(
            || read(&a, "b/1").is_some() && read(&b, "a/0").is_some(),
            Duration::from_secs(15),
        );
        assert!(
            converged,
            "both devices converged: a={:?} b={:?}",
            a.progress().unwrap(),
            b.progress().unwrap()
        );
        assert_eq!(read(&a, "b/0"), Some(b"b0".to_vec()));
        assert_eq!(read(&b, "a/0"), Some(b"a0".to_vec()));

        // A stops cleanly and exports; B keeps writing while A is down.
        stop(&a);
        assert_eq!(a.stop_reason(), STOP_CANCELLED);
        let blob = snapshot(&a);
        write(&b, "b/2", b"b2");

        // A resumes from the snapshot and catches exactly what it missed.
        let restored = NativeRelayDriver::new(
            relay_url.clone(),
            channel_id.clone(),
            token_a.clone(),
            "relay-1".to_owned(),
            "ch".to_owned(),
            "group-1".to_owned(),
            1,
            group_key(),
            "napi-a".to_owned(),
            5_000,
            0,
            None,
            Some(Uint8Array::new(blob)),
        )
        .expect("restored");
        fast_config(&restored);
        start(&restored);
        let caught = wait_until(|| read(&restored, "b/2").is_some(), Duration::from_secs(15));
        assert!(
            caught,
            "the restored device pulled what B wrote while it was down: {:?}",
            restored.progress().unwrap()
        );

        stop(&restored);
        stop(&b);
        assert_eq!(restored.stop_reason(), STOP_CANCELLED);
        assert_eq!(b.stop_reason(), STOP_CANCELLED);
    }
}
