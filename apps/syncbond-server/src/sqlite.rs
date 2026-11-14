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

use rusqlite::{params, Connection, OptionalExtension};
use syncbond_relay_protocol::dto::{Envelope, EnvelopeAck, PullEntry};
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

/// The one storage failure that carries no more specific relay code.
fn internal_error() -> StorageError {
    StorageError::new(RelayErrorCode::Internal)
}

impl RelayStorage for SqliteRelayStore {
    fn head(&self, channel: &str) -> Result<u64, StorageError> {
        let conn = self.conn.lock().map_err(|_| internal_error())?;
        // SQLite integers are i64; stored seq values are non-negative by
        // construction, so a negative MAX here means on-disk corruption.
        let head: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM envelopes WHERE channel = ?1",
                params![channel],
                |row| row.get(0),
            )
            .map_err(|_| internal_error())?;
        head.try_into().map_err(|_| internal_error())
    }

    /// Append a batch inside one immediate transaction: sequences are
    /// assigned in batch order, a retry of an identical envelope returns
    /// the originally committed sequence with `duplicate: true`, a retry
    /// of the same id with different ciphertext is a hard
    /// idempotency_conflict, and any failure rolls the whole batch back —
    /// no ACK is produced that the log does not hold (DSR-13).
    fn append(&self, channel: &str, envelopes: &[Envelope]) -> Result<AppendOutcome, StorageError> {
        if envelopes.is_empty() {
            return Ok(AppendOutcome { acks: Vec::new() });
        }
        let mut conn = self.conn.lock().map_err(|_| internal_error())?;
        // Immediate: take the write lock up front so the sequence window
        // we compute cannot be invalidated by a concurrent writer before
        // commit. The process is single-instance by design (module docs).
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| internal_error())?;
        let channel_exists: bool = tx
            .query_row(
                "SELECT 1 FROM channels WHERE id = ?1",
                params![channel],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| internal_error())?
            .is_some();
        if !channel_exists {
            let _ = tx.rollback();
            return Err(StorageError::new(RelayErrorCode::ChannelNotFound));
        }
        let head: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM envelopes WHERE channel = ?1",
                params![channel],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| internal_error())?;
        let mut next_seq = u64::try_from(head).map_err(|_| internal_error())? + 1;
        let mut acks = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            let payload = serde_json::to_string(envelope).map_err(|_| internal_error())?;
            let stored: Option<(i64, String)> = tx
                .query_row(
                    "SELECT seq, payload FROM envelopes \
                     WHERE channel = ?1 AND message_id = ?2",
                    params![channel, envelope.message_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| internal_error())?;
            if let Some((seq, stored_payload)) = stored {
                if stored_payload == payload {
                    let seq = u64::try_from(seq).map_err(|_| internal_error())?;
                    acks.push(EnvelopeAck {
                        message_id: envelope.message_id.clone(),
                        seq,
                        duplicate: true,
                    });
                    continue;
                }
                // Same id, different ciphertext: the client is reusing an
                // id across distinct payloads. Reject the whole batch.
                let _ = tx.rollback();
                return Err(StorageError::new(RelayErrorCode::IdempotencyConflict));
            }
            tx.execute(
                "INSERT INTO envelopes(channel, seq, message_id, payload) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    channel,
                    i64::try_from(next_seq).map_err(|_| internal_error())?,
                    envelope.message_id,
                    payload
                ],
            )
            .map_err(|_| internal_error())?;
            acks.push(EnvelopeAck {
                message_id: envelope.message_id.clone(),
                seq: next_seq,
                duplicate: false,
            });
            next_seq += 1;
        }
        tx.commit().map_err(|_| internal_error())?;
        Ok(AppendOutcome { acks })
    }

    fn pull(
        &self,
        channel: &str,
        after: u64,
        limit: u16,
        max_bytes: u64,
    ) -> Result<PullPage, StorageError> {
        // The HTTP layer resolves None to the frozen defaults and rejects
        // out-of-range values via `effective_pull_limits`; a zero here would
        // make the cursor loop without advancing, so refuse it too.
        if limit == 0 {
            return Err(StorageError::new(RelayErrorCode::BadRequest));
        }

        let conn = self.conn.lock().map_err(|_| internal_error())?;

        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM channels WHERE id = ?1",
                params![channel],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| internal_error())?;
        if found.is_none() {
            return Err(StorageError::new(RelayErrorCode::ChannelNotFound));
        }

        let head: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM envelopes WHERE channel = ?1",
                params![channel],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| internal_error())?;
        let head = u64::try_from(head).map_err(|_| internal_error())?;
        if after > head {
            return Err(StorageError::new(RelayErrorCode::CursorInvalid));
        }
        let after = i64::try_from(after).map_err(|_| internal_error())?;

        // Fetch one row past the limit so a full page can be told apart
        // from the true end of the channel.
        let mut stmt = conn
            .prepare(
                "SELECT seq, payload FROM envelopes
                 WHERE channel = ?1 AND seq > ?2
                 ORDER BY seq ASC
                 LIMIT ?3",
            )
            .map_err(|_| internal_error())?;
        let mut rows = stmt
            .query(params![channel, after, i64::from(limit) + 1])
            .map_err(|_| internal_error())?;

        let mut entries = Vec::new();
        let mut used_bytes = 0u64;
        let mut has_more = false;
        while let Some(row) = rows.next().map_err(|_| internal_error())? {
            if entries.len() == usize::from(limit) {
                has_more = true;
                break;
            }
            let seq = row.get::<_, i64>(0).map_err(|_| internal_error())?;
            let seq = u64::try_from(seq).map_err(|_| internal_error())?;
            let payload: String = row.get(1).map_err(|_| internal_error())?;
            let envelope: Envelope =
                serde_json::from_str(&payload).map_err(|_| internal_error())?;
            let entry = PullEntry { seq, envelope };
            let entry_bytes = serde_json::to_string(&entry)
                .map_err(|_| internal_error())?
                .len() as u64;
            // A single entry above the cap is an error, never an empty
            // page: an empty page would loop forever on the client.
            if entry_bytes > max_bytes {
                return Err(StorageError::new(RelayErrorCode::ItemTooLarge));
            }
            if used_bytes + entry_bytes > max_bytes {
                // This entry belongs to the next page; the cursor stops at
                // the last delivered sequence.
                has_more = true;
                break;
            }
            used_bytes += entry_bytes;
            entries.push(entry);
        }
        Ok(PullPage { entries, has_more })
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

    fn sample_envelope(channel: &str, id: &str, body: &str) -> Envelope {
        Envelope {
            protocol_version: 1,
            group_id: channel.to_string(),
            sender_device_id: "device-a".to_string(),
            key_epoch: 1,
            message_id: id.to_string(),
            nonce: "nonce".to_string(),
            ciphertext: body.to_string(),
        }
    }

    fn create_channel(path: &Path, channel: &str) {
        let conn = raw_connection(path);
        conn.execute("INSERT INTO channels(id) VALUES (?1)", params![channel])
            .unwrap();
    }

    fn envelope_count(path: &Path, channel: &str) -> i64 {
        let conn = raw_connection(path);
        conn.query_row(
            "SELECT COUNT(*) FROM envelopes WHERE channel = ?1",
            params![channel],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn append_assigns_contiguous_sequences() {
        let path = temp_db("append-seqs");
        let channel = "ch-append";
        SqliteRelayStore::open(&path).unwrap();
        create_channel(&path, channel);
        let store = SqliteRelayStore::open(&path).unwrap();
        let batch = [
            sample_envelope(channel, "msg-1", "ciphertext-1"),
            sample_envelope(channel, "msg-2", "ciphertext-2"),
        ];
        let outcome = store.append(channel, &batch).unwrap();
        let seqs: Vec<u64> = outcome
            .acks
            .iter()
            .map(|ack| (ack.seq, ack.duplicate))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(seq, _)| seq)
            .collect();
        assert_eq!(seqs, vec![1, 2], "sequences must be contiguous from head+1");
        assert!(outcome.acks.iter().all(|ack| !ack.duplicate));
        assert_eq!(store.head(channel).unwrap(), 2);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn duplicate_retry_returns_original_sequence_without_burning_one() {
        let path = temp_db("append-retry");
        let channel = "ch-retry";
        SqliteRelayStore::open(&path).unwrap();
        create_channel(&path, channel);
        let store = SqliteRelayStore::open(&path).unwrap();
        let first = sample_envelope(channel, "msg-1", "ciphertext-1");
        let ack = store
            .append(channel, std::slice::from_ref(&first))
            .unwrap()
            .acks
            .remove(0);
        assert_eq!((ack.seq, ack.duplicate), (1, false));
        // Identical retry: same seq, marked duplicate, no new row.
        let ack = store.append(channel, &[first]).unwrap().acks.remove(0);
        assert_eq!((ack.seq, ack.duplicate), (1, true));
        assert_eq!(store.head(channel).unwrap(), 1);
        // A fresh id after the retry takes the next sequence: the retry
        // must not have consumed one.
        let ack = store
            .append(
                channel,
                &[sample_envelope(channel, "msg-2", "ciphertext-2")],
            )
            .unwrap()
            .acks
            .remove(0);
        assert_eq!((ack.seq, ack.duplicate), (2, false));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn conflicting_content_is_rejected_without_side_effects() {
        let path = temp_db("append-conflict");
        let channel = "ch-conflict";
        SqliteRelayStore::open(&path).unwrap();
        create_channel(&path, channel);
        let store = SqliteRelayStore::open(&path).unwrap();
        store
            .append(
                channel,
                &[sample_envelope(channel, "msg-1", "ciphertext-a")],
            )
            .unwrap();
        let error = store
            .append(
                channel,
                &[sample_envelope(channel, "msg-1", "ciphertext-b")],
            )
            .unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::IdempotencyConflict);
        assert_eq!(store.head(channel).unwrap(), 1);
        assert_eq!(envelope_count(&path, channel), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn failed_batch_rolls_back_atomically() {
        let path = temp_db("append-atomic");
        let channel = "ch-atomic";
        SqliteRelayStore::open(&path).unwrap();
        create_channel(&path, channel);
        let store = SqliteRelayStore::open(&path).unwrap();
        store
            .append(channel, &[sample_envelope(channel, "msg-1", "committed")])
            .unwrap();
        // The second item of the batch reuses a committed id with
        // different content: the injected commit failure. The first,
        // individually fine item must vanish with the batch.
        let batch = [
            sample_envelope(channel, "msg-2", "doomed"),
            sample_envelope(channel, "msg-1", "forged"),
        ];
        let error = store.append(channel, &batch).unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::IdempotencyConflict);
        assert_eq!(store.head(channel).unwrap(), 1, "head must not move");
        assert_eq!(envelope_count(&path, channel), 1, "no dirty rows");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn unknown_channel_is_rejected_without_writes() {
        let path = temp_db("append-unknown-channel");
        let store = SqliteRelayStore::open(&path).unwrap();
        let error = store
            .append(
                "ghost-channel",
                &[sample_envelope("ghost-channel", "msg-1", "x")],
            )
            .unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::ChannelNotFound);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn committed_records_survive_restart() {
        let path = temp_db("append-restart");
        let channel = "ch-restart";
        SqliteRelayStore::open(&path).unwrap();
        create_channel(&path, channel);
        {
            let store = SqliteRelayStore::open(&path).unwrap();
            store
                .append(
                    channel,
                    &[
                        sample_envelope(channel, "msg-1", "ciphertext-1"),
                        sample_envelope(channel, "msg-2", "ciphertext-2"),
                    ],
                )
                .unwrap();
        }
        let store = SqliteRelayStore::open(&path).unwrap();
        assert_eq!(store.head(channel).unwrap(), 2);
        assert_eq!(envelope_count(&path, channel), 2);
        // ACKed ids stay idempotent across the restart too.
        let ack = store
            .append(
                channel,
                &[sample_envelope(channel, "msg-1", "ciphertext-1")],
            )
            .unwrap()
            .acks
            .remove(0);
        assert_eq!((ack.seq, ack.duplicate), (1, true));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn empty_batch_is_a_no_op() {
        let path = temp_db("append-empty");
        SqliteRelayStore::open(&path).unwrap();
        let store = SqliteRelayStore::open(&path).unwrap();
        // A no-op needs no channel to exist and must touch nothing.
        let outcome = store.append("any-channel", &[]).unwrap();
        assert!(outcome.acks.is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// Open a store, create `channel`, and append five envelopes with
    /// uniform shapes so their serialized sizes match.
    fn five_envelope_store(path: &Path, channel: &str) -> SqliteRelayStore {
        let store = SqliteRelayStore::open(path).unwrap();
        create_channel(path, channel);
        store
            .append(
                channel,
                &[
                    sample_envelope(channel, "id-1", "body-1"),
                    sample_envelope(channel, "id-2", "body-2"),
                    sample_envelope(channel, "id-3", "body-3"),
                    sample_envelope(channel, "id-4", "body-4"),
                    sample_envelope(channel, "id-5", "body-5"),
                ],
            )
            .unwrap();
        store
    }

    #[test]
    fn pull_walks_pages_and_cursor_stops_at_last_delivery() {
        let path = temp_db("pull-walk");
        let channel = "walk-chan";
        let store = five_envelope_store(&path, channel);

        // Two entries per page, three pages, cursor lands on each page's
        // last delivered sequence.
        let page = store.pull(channel, 0, 2, u64::MAX).unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(page.has_more);
        assert_eq!(page.entries[1].envelope.message_id, "id-2");

        let page = store.pull(channel, 2, 2, u64::MAX).unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [3, 4]
        );
        assert!(page.has_more);

        let page = store.pull(channel, 4, 2, u64::MAX).unwrap();
        assert_eq!(page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [5]);
        // Head reached: no phantom has_more to send the client back around.
        assert!(!page.has_more);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn pull_at_head_returns_empty_page_without_moving_cursor() {
        let path = temp_db("pull-empty");
        let channel = "empty-chan";
        let store = five_envelope_store(&path, channel);

        // Cursor at head: an empty page and nothing to advance to.
        let page = store.pull(channel, 5, 4, u64::MAX).unwrap();
        assert!(page.entries.is_empty());
        assert!(!page.has_more);
        // The same request must return the same empty page: the cursor
        // was not skipped past anything.
        let again = store.pull(channel, 5, 4, u64::MAX).unwrap();
        assert_eq!(page, again);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn pull_rejects_invalid_cursor_and_unknown_channel() {
        let path = temp_db("pull-bad-cursor");
        let channel = "cursor-chan";
        let store = five_envelope_store(&path, channel);

        let error = store.pull(channel, 6, 4, u64::MAX).unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::CursorInvalid);
        let error = store.pull("no-such-channel", 0, 4, u64::MAX).unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::ChannelNotFound);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn pull_single_entry_over_byte_cap_is_an_error_not_a_page() {
        let path = temp_db("pull-item-too-large");
        let channel = "big-chan";
        let store = five_envelope_store(&path, channel);

        // Calibrate: the real serialized size of one entry.
        let one = store.pull(channel, 0, 1, u64::MAX).unwrap();
        let entry_bytes = serde_json::to_string(&one.entries[0]).unwrap().len() as u64;

        // One byte under: the entry alone busts the cap, so an explicit
        // error rather than an empty page (which would loop the client).
        let error = store.pull(channel, 0, 4, entry_bytes - 1).unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::ItemTooLarge);
        // Exactly the cap: the single entry fits.
        let page = store.pull(channel, 0, 4, entry_bytes).unwrap();
        assert_eq!(page.entries.len(), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn pull_byte_cap_splits_pages_without_skipping_entries() {
        let path = temp_db("pull-byte-split");
        let channel = "split-chan";
        let store = five_envelope_store(&path, channel);

        let one = store.pull(channel, 0, 1, u64::MAX).unwrap();
        let entry_bytes = serde_json::to_string(&one.entries[0]).unwrap().len() as u64;

        // Two entries fit exactly; the rest wait behind the same cursor.
        let page = store.pull(channel, 0, 64, entry_bytes * 2).unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(page.has_more);

        // Three entries remain and all fit in a raised cap: now the
        // count limit (64) is what would bound the page, not bytes.
        let page = store.pull(channel, 2, 64, entry_bytes * 3).unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [3, 4, 5]
        );
        assert!(!page.has_more);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn pull_survives_restart_and_stays_gap_free() {
        let path = temp_db("pull-restart");
        let channel = "restart-chan";
        {
            let store = five_envelope_store(&path, channel);
            assert_eq!(store.head(channel).unwrap(), 5);
        }
        let store = SqliteRelayStore::open(&path).unwrap();
        let page = store.pull(channel, 0, 64, u64::MAX).unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5]
        );
        assert!(!page.has_more);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
