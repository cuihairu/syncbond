//! The default self-hosted syncbond relay executable (todo.md DSR-11).
//!
//! Startup and shutdown only: load [`config::Config`], open
//! [`storage::RelayStorage`], assemble the HTTP service and run until
//! interrupted. Routing, auth and error mapping live in `http.rs`
//! (DSR-19); this file must stay the thin assembly point so the process
//! boundary — what the deployer runs — stays auditable.
//!
//! Network stack choice, recorded and locked per default-server.md §2:
//! axum 0.8 (HTTP/1.1 + WebSocket via its `ws` feature, tokio-tungstenite
//! under the hood) on tokio 1.x multi-thread runtime; rusqlite 0.42 with
//! bundled SQLite (WAL) for storage. All versions are pinned in the
//! workspace `Cargo.toml`; core keeps no dependency on any of them.

mod config;
mod http;
mod proxy;
mod rooms;
mod serve;
mod sqlite;
mod storage;
mod ws;

use std::process::ExitCode;

use config::{Config, ConfigError};

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    let config_path = match (args.next(), args.next()) {
        (Some(path), None) => path,
        _ => {
            eprintln!("usage: syncbond-server <config.json>");
            return ExitCode::from(2);
        }
    };

    // The serve loop is asynchronous, so the binary builds one multi-thread
    // runtime and blocks this process thread on it (default-server.md §2).
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot build async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(config_path.into())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Anything that can abort startup before the serve loop exists.
#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Store(#[from] sqlite::StoreOpenError),
    #[error("cannot bind relay listener on {address}")]
    Bind {
        source: std::io::Error,
        address: String,
    },
    #[error("relay serve loop failed: {source}")]
    Serve { source: std::io::Error },
    #[error("final storage checkpoint failed: {source}")]
    Shutdown { source: storage::StorageError },
}

/// Load configuration, open storage, and exit non-zero on any failure
/// before the server starts serving (DSR-11: invalid configuration never
/// half-starts; DSR-12: an unreadable or newer database is a hard stop,
/// never a wipe).
async fn run(config_path: std::path::PathBuf) -> Result<(), StartupError> {
    let config = Config::load(&config_path)?;
    // Assembly order: config first, then storage, then routes (DSR-19).
    // The store outlives this function — the serve loop keeps running with
    // it until the process exits.
    let db_path = config.data_dir.join("relay.db");
    // Quotas come from the deployer's config; a `0` there means "no
    // limit", never "block everything".
    let quotas = sqlite::Quotas {
        channel_bytes: config.channel_quota_bytes,
        disk_bytes: config.disk_quota_bytes,
    };
    let store = std::sync::Arc::new(sqlite::SqliteRelayStore::open_with_quotas(
        &db_path, quotas,
    )?);
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .map_err(|source| StartupError::Bind {
            source,
            address: config.listen.to_string(),
        })?;
    // Readiness flips the instant the listener exists — never before, so a
    // relay that is still opening its database answers liveness but not
    // readiness.
    store.mark_ready();
    // The process stop edge (DSR-24): SIGINT (Ctrl-C) or SIGTERM, exactly
    // what a terminal, a container runtime, or a service manager sends.
    // Firing it starts the bounded drain; until then the server runs
    // forever.
    let shutdown = serve::Shutdown::new();
    let shutdown_task = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = async {
                    // A stream that never yields if the platform has no
                    // SIGTERM; on Unix this is the container-runtime stop.
                    match tokio::signal::unix::signal(
                        tokio::signal::unix::SignalKind::terminate(),
                    ) {
                        Ok(mut term) => {
                            term.recv().await;
                        }
                        Err(_) => std::future::pending::<()>().await,
                    }
                } => {}
            }
            shutdown.fire();
        })
    };
    // The state keeps its own Arc clone; keep one here for the final
    // checkpoint after the drain.
    let store_for_shutdown = store.clone();
    // The process exit waits on this after the connection drain, so every
    // WebSocket goodbye is on the wire before the runtime drops
    // (relay-protocol.md §7: shutdown closes rooms with 1001 after
    // draining in-flight frames).
    let live_sessions = std::sync::Arc::new(ws::LiveSessions::new());
    // One clone for the state, one for the exit wait.
    let drain_sessions = live_sessions.clone();
    let app = http::router(http::AppState {
        store,
        rooms: std::sync::Arc::new(rooms::PairingRooms::new()),
        sessions: std::sync::Arc::new(ws::RoomSessions::default()),
        allowed_origins: config.allowed_origins.clone(),
        trusted_proxies: config.trusted_proxies.clone(),
        subscriptions: std::sync::Arc::new(ws::ChannelSubscriptions::default()),
        ws_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(config.max_ws_sessions)),
        ws_heartbeat: ws::Heartbeat::frozen(),
        ws_outbound_queue_bytes: syncbond_relay_protocol::limits::WS_OUTBOUND_QUEUE_BYTES,
        shutdown: shutdown.clone(),
        live_sessions,
    });
    // Connect info is the peer's socket address; the pairing-room route
    // rate-limits by it (relay-protocol.md §9). The hand-rolled loop adds
    // the deployment's connection budget and header-read timeout, and on
    // a stop signal drains bounded by shutdownTimeoutSeconds
    // (default-server.md §4).
    serve::serve(
        listener,
        app,
        serve::Limits {
            max_connections: config.max_connections,
            header_timeout_seconds: config.header_timeout_seconds,
            drain_timeout_seconds: config.shutdown_timeout_seconds,
        },
        shutdown,
    )
    .await
    .map_err(|source| StartupError::Serve { source })?;
    // The connection drain is over; now the WebSocket sessions. Each saw
    // the same signal and is closing with 1001; wait until the last
    // goodbye is flushed. The same budget bounds this wait, so the whole
    // drain is at most twice `shutdownTimeoutSeconds` — still a promise
    // about the process exit time, just not a tighter one.
    if config.shutdown_timeout_seconds > 0 {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(config.shutdown_timeout_seconds),
            drain_sessions.drained(),
        )
        .await;
    } else {
        drain_sessions.drained().await;
    }
    // No session is alive from here on: no handler can still be
    // mid-request or mid-goodbye. Folding the WAL now is what makes
    // "everything ACKed is pullable after restart" a promise the deployer
    // can verify by copying the data directory, and a failure to
    // checkpoint is a failure to exit cleanly.
    storage::RelayStorage::shutdown(store_for_shutdown.as_ref())
        .map_err(|source| StartupError::Shutdown { source })?;
    shutdown_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn invalid_config_fails_before_any_state() {
        let dir = std::env::temp_dir().join(format!("syncbond-server-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"{\"listen\":\"127.0.0.1:8080\",\"dataDir\":\"\",\"n\":1}")
            .unwrap();
        drop(file);
        assert!(
            Config::load(&path).is_err(),
            "unknown fields and empty dataDir must reject at startup"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
