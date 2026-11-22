//! An in-process relay for other crates' integration tests, behind the
//! `test-support` feature (todo.md DSR-27): the same router, serve loop,
//! SQLite store, and shutdown edge the binary runs, bound to an ephemeral
//! loopback port. Test-only by construction — nothing that ships should
//! embed a relay; the deliverable server is the binary.

/// One relay under test: the address it listens on, its admin credential,
/// and the process shutdown edge. Dropping it aborts the serve task and
/// removes the database, the same way the `http` test harness does.
pub struct TestRelay {
    /// `host:port` the relay serves on (always loopback, ephemeral port).
    pub address: String,
    /// The bootstrap admin credential file's content (trimmed).
    pub admin: String,
    /// The process shutdown edge (DSR-24): firing it is exactly what the
    /// binary's signal handler does.
    pub shutdown: crate::serve::Shutdown,
    _task: tokio::task::JoinHandle<()>,
    _db: std::path::PathBuf,
    /// Whether dropping this relay removes its database file. `boot_relay`
    /// owns a throwaway database and removes it; `boot_relay_in` leaves it
    /// for the caller, so a second relay can resume the same durable state
    /// (the server-restart recovery the recovery suite exercises).
    _remove_db: bool,
    /// The relay's runtime owns the serve task, so it must stay alive
    /// until the relay does. Dropping a runtime blocks, which panics
    /// inside a `#[tokio::test]` body — hand it to a detached OS thread
    /// and let it shut down there.
    _runtime: std::mem::ManuallyDrop<tokio::runtime::Runtime>,
}

impl TestRelay {
    /// The database file path — the durable state the restart tests resume
    /// from, and the cleanup assertion's target.
    pub fn db_path(&self) -> &std::path::Path {
        &self._db
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self._task.abort();
        if self._remove_db {
            std::fs::remove_file(&self._db).ok();
        }
        let runtime = unsafe { std::mem::ManuallyDrop::take(&mut self._runtime) };
        std::thread::spawn(move || drop(runtime));
    }
}

/// Boot a ready relay on an ephemeral port with a fresh database. No
/// browser origins, no trusted proxies, deployment budgets unlimited —
/// the shape every `http` test uses.
pub fn boot_relay() -> TestRelay {
    // Distinct directory per call so parallel tests never share a
    // database or its admin credential.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let dir = std::env::temp_dir().join(format!(
        "syncbond-test-relay-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let db = dir.join("relay.db");
    boot_relay_at(db, true)
}

/// Boot a relay on the caller's own database path (created if missing).
/// The database is left intact when the relay is dropped, so a second call
/// on the same path resumes the durable channel log — the server restart
/// the recovery suite boots over and over. Every other setting matches
/// [`boot_relay`].
pub fn boot_relay_in(dir: &std::path::Path) -> TestRelay {
    std::fs::create_dir_all(dir).expect("create the relay data directory");
    boot_relay_at(dir.join("relay.db"), false)
}

/// The shared boot: the same router, serve loop, SQLite store, and shutdown
/// edge the binary runs, on an ephemeral loopback port.
fn boot_relay_at(db: std::path::PathBuf, remove_db: bool) -> TestRelay {
    let store = std::sync::Arc::new(crate::sqlite::SqliteRelayStore::open(&db).unwrap());
    store.mark_ready();
    let shutdown = crate::serve::Shutdown::new();
    let serve_shutdown = shutdown.clone();
    let state_shutdown = shutdown.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    // Bound inside the relay's own runtime and hand the address back over
    // a std channel (block_on would nest inside a caller's runtime).
    let (address_tx, address_rx) = std::sync::mpsc::channel::<String>();
    let task = runtime.spawn(async move {
        let state = crate::http::AppState {
            store,
            rooms: std::sync::Arc::new(crate::rooms::PairingRooms::new()),
            sessions: std::sync::Arc::new(crate::ws::RoomSessions::default()),
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            subscriptions: std::sync::Arc::new(crate::ws::ChannelSubscriptions::default()),
            ws_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
            ws_heartbeat: crate::ws::Heartbeat::frozen(),
            ws_outbound_queue_bytes: syncbond_relay_protocol::limits::WS_OUTBOUND_QUEUE_BYTES,
            shutdown: state_shutdown,
            live_sessions: std::sync::Arc::new(crate::ws::LiveSessions::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        address_tx
            .send(listener.local_addr().unwrap().to_string())
            .expect("the boot thread always collects the address");
        let app = crate::http::router(state);
        if let Err(error) = crate::serve::serve(
            listener,
            app,
            crate::serve::Limits {
                max_connections: 0,
                header_timeout_seconds: 0,
                drain_timeout_seconds: 5,
            },
            serve_shutdown,
        )
        .await
        {
            eprintln!("test relay serve error: {error}");
        }
    });
    let address = address_rx.recv().unwrap();
    let admin = std::fs::read_to_string(crate::sqlite::admin_credential_path(&db)).unwrap();
    TestRelay {
        address,
        admin: admin.trim().to_owned(),
        shutdown,
        _task: task,
        _db: db,
        _remove_db: remove_db,
        _runtime: std::mem::ManuallyDrop::new(runtime),
    }
}
