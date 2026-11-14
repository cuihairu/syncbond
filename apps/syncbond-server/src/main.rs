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
mod sqlite;
mod storage;

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
    let app = http::router(http::AppState { store });
    axum::serve(listener, app)
        .await
        .map_err(|source| StartupError::Serve { source })?;
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
