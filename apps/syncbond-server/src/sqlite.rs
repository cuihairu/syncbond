//! SQLite persistence for the relay server (todo.md DSR-12).
//!
//! One database file per data directory (`<dataDir>/relay.db`), opened in
//! WAL mode with foreign keys on. The schema is versioned through
//! `PRAGMA user_version` and migrates strictly upward:
//!
//! - a fresh file is initialized at the current [`SCHEMA_VERSION`];
//! - a file at the current version opens as-is (restarts are free);
//! - a file at a *newer* version is refused outright: this binary has no
//!   idea what those tables mean, and "just run the old code anyway" is
//!   how storage gets silently corrupted;
//! - a file SQLite cannot read fails the open, and nothing in this module
//!   ever deletes or rewrites an existing database to "recover".
//!
//! Schema v1 covers the DSR-12 acceptance surface — channels, credential
//! digests, ciphertext envelopes, and the sequence/idempotency indexes:
//!
//! - `channels`: registry of created channels (DSR-15 populates it).
//! - `credentials`: SHA-256 digests only, never the token itself
//!   (relay-protocol.md §auth). `revoked_at IS NULL` means active
//!   (DSR-17 wires revocation).
//! - `envelopes`: one row per committed ciphertext, keyed
//!   `(channel, seq)`; the `UNIQUE (channel, message_id)` index *is* the
//!   append idempotency contract of relay-protocol.md §append. `payload`
//!   holds the canonical JSON of the `relay::Envelope` exactly as
//!   accepted — this server never decrypts or reshapes it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection};
use syncbond_relay_protocol::dto::Envelope;
use syncbond_relay_protocol::error::RelayErrorCode;

use crate::storage::{AppendOutcome, PullPage, RelayStorage, StorageError};

/// Schema version this binary understands. Bump together with a migration
/// step in [`migrate`]; never lower.
const SCHEMA_VERSION: i32 = 1;

const SCHEMA_SQL: &str = "
CREATE TABLE channels (
    id   TEXT PRIMARY KEY
);

CREATE TABLE credentials (
    digest     TEXT PRIMARY KEY,
    scope      TEXT NOT NULL,
    channel    TEXT,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE envelopes (
    channel    TEXT NOT NULL REFERENCES channels(id),
    seq        INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    payload    TEXT NOT NULL,
    PRIMARY KEY (channel, seq),
    UNIQUE (channel, message_id)
);
";

/// Why [`SqliteRelayStore::open`] refused to start. Every variant leaves
/// the database file untouched; startup failure must never be "repaired"
/// by deleting state.
#[derive(Debug, thiserror::Error)]
pub enum StoreOpenError {
    #[error("cannot create data directory {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("database {path} is unreadable, corrupt, or not a SQLite file: {source}")]
    Sqlite {
        path: PathBuf,
        source: rusqlite::Error,
    },
    #[error(
        "database schema version {found} is newer than this server supports \
         ({supported}); refusing to start without touching data"
    )]
    UnknownVersion { found: i32, supported: i32 },
}

/// SQLite-backed [`RelayStorage`]. Opened once at startup by the binary.
/// `rusqlite::Connection` is `Send` but not `Sync`, and [`RelayStorage`]
/// requires `Send + Sync` because the HTTP layer (DSR-19+) shares one
/// store across tokio worker threads — so every access goes through this
/// lock. Single-process by design; multi-instance is not a supported
/// deployment shape.
pub struct SqliteRelayStore {
    conn: Mutex<Connection>,
}

impl SqliteRelayStore {
    /// Open (creating if absent) the database at `path` and migrate it to
    /// [`SCHEMA_VERSION`]. Fails closed on corruption or unknown versions;
    /// see the module docs.
    pub fn open(path: &Path) -> Result<Self, StoreOpenError> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|source| StoreOpenError::Io {
                    path: dir.to_path_buf(),
                    source,
                })?;
            }
        }
        let conn = Connection::open(path).map_err(|source| StoreOpenError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|source| StoreOpenError::Sqlite {
                path: path.to_path_buf(),
                source,
            })?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|source| StoreOpenError::Sqlite {
                path: path.to_path_buf(),
                source,
            })?;
        migrate(&conn, path)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

/// Bring an opened database up to [`SCHEMA_VERSION`]. Version 0 means the
/// file was created by this call (or is an empty file): build the schema.
/// Anything above [`SCHEMA_VERSION`] is a hard refusal.
fn migrate(conn: &Connection, path: &Path) -> Result<(), StoreOpenError> {
    let refuse = |source: rusqlite::Error| StoreOpenError::Sqlite {
        path: path.to_path_buf(),
        source,
    };
    let found: i32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(refuse)?;
    if found > SCHEMA_VERSION {
        return Err(StoreOpenError::UnknownVersion {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    if found == 0 {
        conn.execute_batch(SCHEMA_SQL).map_err(refuse)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(refuse)?;
    }
    // Future versions add `if found < N { ... }` steps here, oldest first.
    Ok(())
}

impl RelayStorage for SqliteRelayStore {
    fn head(&self, channel: &str) -> Result<u64, StorageError> {
        let internal = || StorageError::new(RelayErrorCode::Internal);
        let conn = self.conn.lock().map_err(|_| internal())?;
        // SQLite integers are i64; stored seq values are non-negative by
        // construction, so a negative MAX here means on-disk corruption.
        let head: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM envelopes WHERE channel = ?1",
                params![channel],
                |row| row.get(0),
            )
            .map_err(|_| internal())?;
        head.try_into().map_err(|_| internal())
    }

    fn append(
        &self,
        _channel: &str,
        _envelopes: &[Envelope],
    ) -> Result<AppendOutcome, StorageError> {
        // DSR-13 wires the transactional append (all-or-nothing batch with
        // idempotent ACKs) on top of this schema. Nothing routes here yet.
        unimplemented!("transactional append lands in DSR-13")
    }

    fn pull(
        &self,
        _channel: &str,
        _after: u64,
        _limit: u16,
        _max_bytes: u64,
    ) -> Result<PullPage, StorageError> {
        // DSR-14 wires cursor-bounded pagination. Nothing routes here yet.
        unimplemented!("paginated pull lands in DSR-14")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "syncbond-server-sqlite-{}-{}",
            std::process::id(),
            name
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("relay.db")
    }

    fn raw_connection(path: &Path) -> Connection {
        Connection::open(path).unwrap()
    }

    /// Insert a channel plus three committed envelopes through a separate
    /// raw connection, simulating state written by a previous server run.
    fn seed_committed_channel(path: &Path, channel: &str) {
        let conn = raw_connection(path);
        conn.execute("INSERT INTO channels(id) VALUES (?1)", params![channel])
            .unwrap();
        for seq in 1..=3i64 {
            conn.execute(
                "INSERT INTO envelopes(channel, seq, message_id, payload) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    channel,
                    seq,
                    format!("msg-{seq}"),
                    format!("{{\"seq\":{seq}}}")
                ],
            )
            .unwrap();
        }
    }

    #[test]
    fn fresh_init_and_repeated_startup_succeed() {
        let path = temp_db("fresh-reopen");
        {
            let store = SqliteRelayStore::open(&path).unwrap();
            assert_eq!(store.head("any-channel").unwrap(), 0);
        }
        // Repeated startup on an existing database must be free.
        let store = SqliteRelayStore::open(&path).unwrap();
        assert_eq!(store.head("any-channel").unwrap(), 0);
        let version: i32 = store
            .conn
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn schema_persists_across_restarts() {
        let path = temp_db("persist");
        SqliteRelayStore::open(&path).unwrap();
        seed_committed_channel(&path, "ch-persist");
        let store = SqliteRelayStore::open(&path).unwrap();
        assert_eq!(store.head("ch-persist").unwrap(), 3);
        assert_eq!(store.head("other-channel").unwrap(), 0);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn corrupt_database_fails_without_clearing() {
        let path = temp_db("corrupt");
        let garbage = b"this is definitely not a sqlite database file";
        std::fs::write(&path, garbage).unwrap();
        let error = match SqliteRelayStore::open(&path) {
            Ok(_) => panic!("a corrupt database must refuse to open"),
            Err(error) => error,
        };
        assert!(
            matches!(error, StoreOpenError::Sqlite { .. }),
            "corruption must surface as an unreadable-database error, got {error:?}"
        );
        // The failed open must not have touched the file.
        assert_eq!(std::fs::read(&path).unwrap(), garbage);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn unknown_future_version_refuses_and_preserves_data() {
        let path = temp_db("future-version");
        SqliteRelayStore::open(&path).unwrap();
        seed_committed_channel(&path, "ch-future");
        {
            let conn = raw_connection(&path);
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 7)
                .unwrap();
        }
        let error = match SqliteRelayStore::open(&path) {
            Ok(_) => panic!("a newer schema version must hard-refuse"),
            Err(error) => error,
        };
        assert!(
            matches!(error, StoreOpenError::UnknownVersion { .. }),
            "a newer schema must hard-refuse, got {error:?}"
        );
        // Refusal must not clear data: a newer binary can still read it.
        let conn = raw_connection(&path);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM envelopes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 3);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
