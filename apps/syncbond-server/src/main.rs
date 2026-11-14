//! The default self-hosted syncbond relay executable (todo.md DSR-11).
//!
//! Startup and shutdown only: load [`config::Config`], open
//! [`storage::RelayStorage`], assemble the HTTP service and run until
//! interrupted. Routing, auth and rate limiting live in `routes.rs`
//! (DSR-19+); this file must stay the thin assembly point so the process
//! boundary — what the deployer runs — stays auditable.
//!
//! Network stack choice, recorded and locked per default-server.md §2:
//! axum 0.8 (HTTP/1.1 + WebSocket via its `ws` feature, tokio-tungstenite
//! under the hood) on tokio 1.x multi-thread runtime; rusqlite 0.42 with
//! bundled SQLite (WAL) for storage. All versions are pinned in the
//! workspace `Cargo.toml`; core keeps no dependency on any of them.

mod config;
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

    match run(config_path.into()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Load configuration and exit non-zero on any failure before the server
/// creates state (DSR-11: invalid configuration never half-starts).
fn run(config_path: std::path::PathBuf) -> Result<(), ConfigError> {
    let config = Config::load(&config_path)?;
    // The storage backend is opened in DSR-12; until then a valid config
    // is the whole deliverable. Keeping the value alive here documents
    // the assembly order: config first, then storage, then routes.
    let _config = config;
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
