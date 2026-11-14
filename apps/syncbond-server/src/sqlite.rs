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
//! Schema v2 covers the DSR-12..DSR-16 acceptance surface — channels,
//! credential digests, ciphertext envelopes, and the sequence/idempotency
//! indexes:
//!
//! - `channels`: registry of created channels (DSR-15 populates it).
//! - `credentials`: SHA-256 digests only, never the token itself
//!   (relay-protocol.md §auth), plus the public `credential_id` devices
//!   revoke by and a display `label` (v2, DSR-16). `revoked_at IS NULL`
//!   means active (DSR-17 wires revocation).
//! - `envelopes`: one row per committed ciphertext, keyed
//!   `(channel, seq)`; the `UNIQUE (channel, message_id)` index *is* the
//!   append idempotency contract of relay-protocol.md §append. `payload`
//!   holds the canonical JSON of the `relay::Envelope` exactly as
//!   accepted — this server never decrypts or reshapes it.
//!
//! DSR-15 adds the admin-plane bootstrap: on first initialization a
//! 32-byte random credential is written as 64 lowercase hex chars to
//! `<dbDir>/admin-credential` with `0600` permissions (relay-protocol.md
//! §auth: generated at first initialization, no hardcoded or development
//! default). Restarts read that file back; an existing database whose
//! credential file is gone refuses to start — the deployer restores it
//! from backup, this binary never regenerates authority over live data.
//! The in-memory copy redacts itself from [`fmt::Debug`] and compares in
//! constant time, so it can neither leak through logs nor take a timing
//! side channel into the HTTP layer.
//!
//! DSR-18 enforces the append budgets on the same transactional basis: a
//! batch is only committed after the channel and disk byte counts were
//! checked against [`Quotas`], and a refusal rolls the whole batch back
//! rather than half-consume a budget. Quotas can never block a read, and
//! v1 never prunes — a full channel stays readable at its full history.

// Until DSR-19 wires the HTTP layer, the admin-plane surface (the admin
// credential and its verification) is exercised by tests only.
#![allow(dead_code)]

use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::Digest as _;
use syncbond_relay_protocol::dto::{CredentialScope, Envelope, EnvelopeAck, PullEntry};
use syncbond_relay_protocol::error::RelayErrorCode;

use crate::storage::{
    AppendOutcome, IssuedCredential, PullPage, RelayStorage, RevokeOutcome, StorageError,
};

/// Schema version this binary understands. Bump together with a migration
/// step in [`migrate`]; never lower.
const SCHEMA_VERSION: i32 = 2;

const SCHEMA_SQL: &str = "
CREATE TABLE channels (
    id   TEXT PRIMARY KEY
);

CREATE TABLE credentials (
    digest        TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL UNIQUE,
    scope         TEXT NOT NULL,
    channel       TEXT,
    created_at    INTEGER NOT NULL,
    revoked_at    INTEGER,
    label         TEXT
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
    #[error(
        "admin credential file is missing for an existing database; restore \
         it from the deployer backup — refusing to start without touching data"
    )]
    AdminCredentialMissing,
    #[error("admin credential file is invalid: {0}")]
    AdminCredential(&'static str),
}

/// Where the admin credential file lives: next to the database file, per
/// relay-protocol.md §auth.
fn admin_credential_path(db_path: &Path) -> PathBuf {
    match db_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join("admin-credential"),
        _ => PathBuf::from("admin-credential"),
    }
}

/// The bootstrap admin credential in its on-disk form: 64 lowercase hex
/// chars. Kept in memory only to verify incoming admin requests — the
/// [`fmt::Debug`] impl redacts, [`AdminCredential::verify`] compares in
/// constant time, and nothing else ever reads it.
pub struct AdminCredential {
    hex: String,
}

impl AdminCredential {
    /// Generate 32 fresh random bytes from the OS entropy pool. There is
    /// deliberately no deterministic or default fallback: a credential
    /// that can be predicted is not a credential.
    fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            hex: hex_encode(&bytes),
        }
    }

    fn parse(content: &str) -> Result<Self, StoreOpenError> {
        let hex = content.trim();
        if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(StoreOpenError::AdminCredential(
                "expected exactly 64 lowercase hex chars",
            ));
        }
        Ok(Self {
            hex: hex.to_owned(),
        })
    }

    /// Constant-time comparison: fold the XOR of every byte pair so the
    /// branch behavior does not depend on where the first mismatch is.
    /// Length differences return early — the length (64) is public.
    fn verify(&self, candidate: &str) -> bool {
        let candidate = candidate.trim().as_bytes();
        let expected = self.hex.as_bytes();
        if candidate.len() != expected.len() {
            return false;
        }
        candidate
            .iter()
            .zip(expected)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl fmt::Debug for AdminCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminCredential([redacted])")
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// SQLite-backed [`RelayStorage`]. Opened once at startup by the binary.
/// `rusqlite::Connection` is `Send` but not `Sync`, and [`RelayStorage`]
/// requires `Send + Sync` because the HTTP layer (DSR-19+) shares one
/// store across tokio worker threads — so every access goes through this
/// lock. Single-process by design; multi-instance is not a supported
/// deployment shape.
pub struct SqliteRelayStore {
    conn: Mutex<Connection>,
    admin_credential: AdminCredential,
    quotas: Quotas,
    db_path: PathBuf,
}

/// Append budgets, per relay-protocol.md §limits: a per-channel byte
/// budget and a whole-database one, either of which `0` disables. Reads
/// are never blocked by a quota, and v1 never prunes — reaching a budget
/// only stops further appends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    pub channel_bytes: u64,
    pub disk_bytes: u64,
}

impl Default for Quotas {
    /// The frozen relay defaults: 1 GiB per channel, 8 GiB per disk.
    fn default() -> Self {
        Self {
            channel_bytes: 1024 * 1024 * 1024,
            disk_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

impl fmt::Debug for SqliteRelayStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // finish_non_exhaustive: no field of this struct belongs in a log
        // line — the connection points at the data directory, the admin
        // credential must never be printable.
        f.debug_struct("SqliteRelayStore").finish_non_exhaustive()
    }
}

impl SqliteRelayStore {
    /// Open (creating if absent) the database at `path` and migrate it to
    /// [`SCHEMA_VERSION`]. Fails closed on corruption or unknown versions;
    /// see the module docs.
    pub fn open(path: &Path) -> Result<Self, StoreOpenError> {
        Self::open_with_quotas(path, Quotas::default())
    }

    /// Open with explicit append budgets; see [`Quotas`].
    pub fn open_with_quotas(path: &Path, quotas: Quotas) -> Result<Self, StoreOpenError> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|source| StoreOpenError::Io {
                    path: dir.to_path_buf(),
                    source,
                })?;
            }
        }
        // The database decides freshness first: a corrupt or
        // newer-version file must report *that*, not an admin-credential
        // problem. Only after the database itself opens and migrates do
        // we bootstrap the admin credential.
        let first_init = !path.exists();
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
        let credential_path = admin_credential_path(path);
        let admin_credential = if first_init {
            // Fresh database. A leftover file from a wiped database is
            // stale — the data it administered no longer exists — so it is
            // replaced rather than resurrected. The file is created with
            // owner-only mode directly: it must never briefly exist
            // world-readable.
            let token = AdminCredential::generate().hex;
            write_admin_file(&credential_path, &token).map_err(|source| StoreOpenError::Io {
                path: credential_path.clone(),
                source,
            })?;
            AdminCredential::parse(&token)?
        } else {
            // Existing database. No credential file means no way to
            // administer live data — regenerate would hand a fresh key to
            // whoever deleted the file, so refuse instead.
            let content = std::fs::read_to_string(&credential_path)
                .map_err(|_| StoreOpenError::AdminCredentialMissing)?;
            AdminCredential::parse(&content)?
        };
        Ok(Self {
            conn: Mutex::new(conn),
            admin_credential,
            quotas,
            db_path: path.to_path_buf(),
        })
    }

    /// Check an admin candidate against the bootstrap credential.
    pub fn verify_admin(&self, candidate: &str) -> bool {
        self.admin_credential.verify(candidate)
    }
}

/// Write the admin credential file with owner-only permissions from the
/// moment it first exists (Unix); other platforms fall back to the
/// platform default.
#[cfg(unix)]
fn write_admin_file(path: &Path, token: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(token.as_bytes()))
}

#[cfg(not(unix))]
fn write_admin_file(path: &Path, token: &str) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .and_then(|mut file| file.write_all(token.as_bytes()))
}

/// Server-assigned channel id per relay-protocol.md §3.1: opaque,
/// `ch_`-prefixed, 12 random bytes in hex (27 chars total, within the
/// 1–128 limit).
fn generate_channel_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    format!("ch_{}", hex_encode(&bytes))
}

/// A device credential token: 32 fresh random bytes, hex. Shown to the
/// caller exactly once at issue time and never stored anywhere.
fn generate_credential_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// Public credential id (`cred_…`, 8 random bytes in hex) — the handle
/// devices revoke by; carries no authority of its own.
fn generate_credential_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    format!("cred_{}", hex_encode(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

/// Canonical storage form of a scope set: fixed order, deduplicated,
/// comma-joined (`"append"`, `"pull"`, `"append,pull"`, …).
fn scopes_to_str(scopes: &[CredentialScope]) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if scopes.contains(&CredentialScope::Append) {
        parts.push("append");
    }
    if scopes.contains(&CredentialScope::Pull) {
        parts.push("pull");
    }
    parts.join(",")
}

fn str_to_scopes(stored: &str) -> Vec<CredentialScope> {
    let mut scopes = Vec::new();
    for part in stored.split(',') {
        match part {
            "append" => scopes.push(CredentialScope::Append),
            "pull" => scopes.push(CredentialScope::Pull),
            _ => {}
        }
    }
    scopes
}

fn now_unix() -> Result<i64, StorageError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .map_err(|_| internal_error())
}

/// v1 → v2 (DSR-16): credentials gain `credential_id` (the id devices
/// revoke by, relay-protocol.md §3.2) and `label`. v1 predates any
/// deployment, so backfilling the public id with the digest — already
/// unique and stable — is exact, not lossy.
const V1_TO_V2_SQL: &str = "
ALTER TABLE credentials ADD COLUMN credential_id TEXT;
UPDATE credentials SET credential_id = digest WHERE credential_id IS NULL;
CREATE UNIQUE INDEX credentials_by_credential_id ON credentials(credential_id);
ALTER TABLE credentials ADD COLUMN label TEXT;
";

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
    // Upgrades run oldest first; each step lands on the next version.
    if found == 1 {
        conn.execute_batch(V1_TO_V2_SQL).map_err(refuse)?;
        conn.pragma_update(None, "user_version", 2)
            .map_err(refuse)?;
    }
    Ok(())
}

/// The one storage failure that carries no more specific relay code.
fn internal_error() -> StorageError {
    StorageError::new(RelayErrorCode::Internal)
}

/// Refuse the append if the batch would cross a configured budget. Runs
/// with every row staged but before `commit`; the caller returns while
/// the transaction is still open, so the drop rolls the whole batch back
/// and a budget is never half-consumed. A budget of `0`
/// is disabled (relay-protocol.md §limits), and nothing here can block a
/// read: quotas are append-only and v1 never prunes.
fn check_quotas(
    quotas: Quotas,
    channel_used: u64,
    disk_used: u64,
    new_bytes: u64,
) -> Result<(), StorageError> {
    if quotas.channel_bytes != 0 && channel_used.saturating_add(new_bytes) > quotas.channel_bytes {
        return Err(StorageError::new(RelayErrorCode::QuotaExceeded));
    }
    if quotas.disk_bytes != 0 && disk_used.saturating_add(new_bytes) > quotas.disk_bytes {
        return Err(StorageError::new(RelayErrorCode::QuotaExceeded));
    }
    Ok(())
}

/// Bytes the database occupies on disk, sidecar files included. WAL mode
/// parks committed bytes in `relay.db-wal` until a checkpoint, so
/// reading the main file alone would let a channel overshoot its budget
/// for the rest of the process's life.
fn disk_bytes_used(db_path: &Path) -> u64 {
    let mut total = 0u64;
    for suffix in ["", "-wal", "-shm"] {
        let name = format!("{}{}", db_path.display(), suffix);
        if let Ok(meta) = std::fs::metadata(std::path::Path::new(&name)) {
            total = total.saturating_add(meta.len());
        }
    }
    total
}

/// Whether `channel` is registered. Reads take no transaction: channel
/// rows are never deleted, so an ordinary read is authoritative here.
fn channel_exists(conn: &Connection, channel: &str) -> Result<bool, StorageError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM channels WHERE id = ?1",
            params![channel],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| internal_error())?;
    Ok(found.is_some())
}

impl RelayStorage for SqliteRelayStore {
    /// Create a channel with a fresh server-assigned id. The id space is
    /// 96 random bits, so the retry loop below exists for completeness,
    /// not because collisions are expected.
    fn create_channel(&self) -> Result<String, StorageError> {
        let conn = self.conn.lock().map_err(|_| internal_error())?;
        for _ in 0..4 {
            let id = generate_channel_id();
            match conn.execute("INSERT INTO channels(id) VALUES (?1)", params![id]) {
                Ok(_) => return Ok(id),
                Err(rusqlite::Error::SqliteFailure(ref failure, _))
                    if failure.code == rusqlite::ffi::ErrorCode::ConstraintViolation =>
                {
                    continue;
                }
                Err(_) => return Err(internal_error()),
            }
        }
        Err(internal_error())
    }

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
        let quotas = self.quotas;
        let channel_used: i64 = tx
            .query_row(
                "SELECT COALESCE(SUM(octet_length(payload)), 0) \
                 FROM envelopes WHERE channel = ?1",
                params![channel],
                |row| row.get(0),
            )
            .map_err(|_| internal_error())?;
        let channel_used = u64::try_from(channel_used).map_err(|_| internal_error())?;
        let disk_used = disk_bytes_used(&self.db_path);
        // Bytes this batch would newly occupy. Duplicates add no data, so
        // a retry storm can never exhaust a budget.
        let mut new_bytes = 0u64;
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
            new_bytes = new_bytes.saturating_add(payload.len() as u64);
            next_seq += 1;
        }
        if let Err(error) = check_quotas(quotas, channel_used, disk_used, new_bytes) {
            // Roll the staged rows back explicitly: a quota refusal must
            // not consume even part of a budget, and it must not ACK
            // anything.
            let _ = tx.rollback();
            return Err(error);
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

    fn issue_credential(
        &self,
        channel: &str,
        scopes: &[CredentialScope],
        label: Option<&str>,
    ) -> Result<IssuedCredential, StorageError> {
        let conn = self.conn.lock().map_err(|_| internal_error())?;
        if !channel_exists(&conn, channel)? {
            return Err(StorageError::new(RelayErrorCode::ChannelNotFound));
        }
        let created_at = now_unix()?;
        let scope_str = scopes_to_str(scopes);
        let scopes = str_to_scopes(&scope_str);
        for _ in 0..4 {
            let token = generate_credential_token();
            let credential_id = generate_credential_id();
            let digest = sha256_hex(token.as_bytes());
            let inserted = conn.execute(
                "INSERT INTO credentials (digest, credential_id, scope, channel, \
                 created_at, revoked_at, label) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                params![digest, credential_id, scope_str, channel, created_at, label],
            );
            match inserted {
                Ok(_) => {
                    return Ok(IssuedCredential {
                        credential_id,
                        token,
                        scopes,
                        label: label.map(str::to_owned),
                    })
                }
                Err(rusqlite::Error::SqliteFailure(ref failure, _))
                    if failure.code == rusqlite::ffi::ErrorCode::ConstraintViolation =>
                {
                    // A digested token or credential id collided with a
                    // live row: regenerate, never reuse.
                    continue;
                }
                Err(_) => return Err(internal_error()),
            }
        }
        Err(internal_error())
    }

    fn authorize(
        &self,
        channel: &str,
        token: &str,
        scope: CredentialScope,
    ) -> Result<(), StorageError> {
        if token.is_empty() {
            // A missing Authorization header reaches here as an empty
            // token; treat it as absent rather than as a real digest
            // lookup, which would burn a hash on every unauthenticated
            // probe.
            return Err(StorageError::new(RelayErrorCode::Unauthorized));
        }
        let conn = self.conn.lock().map_err(|_| internal_error())?;
        let digest = sha256_hex(token.as_bytes());
        let row: Option<(String, Option<String>, Option<i64>)> = conn
            .query_row(
                "SELECT scope, channel, revoked_at FROM credentials \
                 WHERE digest = ?1",
                params![digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| internal_error())?;
        let (scope_str, credential_channel, revoked_at) = match row {
            Some(row) => row,
            // Unknown token. Deliberately the same code as a revoked one —
            // distinguishing them would let a device poll for revocation
            // timing on credentials it was never given.
            None => return Err(StorageError::new(RelayErrorCode::Unauthorized)),
        };
        if revoked_at.is_some() {
            return Err(StorageError::new(RelayErrorCode::Unauthorized));
        }
        if credential_channel.as_deref() != Some(channel) {
            return Err(StorageError::new(RelayErrorCode::Forbidden));
        }
        if !str_to_scopes(&scope_str).contains(&scope) {
            return Err(StorageError::new(RelayErrorCode::Forbidden));
        }
        Ok(())
    }

    fn revoke_credential(
        &self,
        channel: &str,
        credential_id: &str,
    ) -> Result<RevokeOutcome, StorageError> {
        let conn = self.conn.lock().map_err(|_| internal_error())?;
        if !channel_exists(&conn, channel)? {
            return Err(StorageError::new(RelayErrorCode::ChannelNotFound));
        }
        // Reads and writes here are serialized by this store's mutex
        // (single-process deployment), so the select-then-update pair is
        // not a TOCTOU window.
        let revoked_at: Option<Option<i64>> = conn
            .query_row(
                "SELECT revoked_at FROM credentials \
                 WHERE credential_id = ?1 AND channel = ?2",
                params![credential_id, channel],
                |row| Ok(Some(row.get(0)?)),
            )
            .optional()
            .map_err(|_| internal_error())?
            .flatten();
        let revoked_at = match revoked_at {
            Some(stamp) => stamp,
            // Not issued here. Refuse as `Unauthorized` rather than
            // pretending the credential exists: otherwise an admin could
            // enumerate ids by their error codes.
            None => {
                return Err(StorageError::new(RelayErrorCode::Unauthorized));
            }
        };
        if revoked_at.is_some() {
            return Ok(RevokeOutcome::AlreadyRevoked);
        }
        conn.execute(
            "UPDATE credentials SET revoked_at = ?1 \
             WHERE credential_id = ?2 AND channel = ?3",
            params![now_unix()?, credential_id, channel],
        )
        .map_err(|_| internal_error())?;
        Ok(RevokeOutcome::Revoked)
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

    fn admin_file(path: &Path) -> PathBuf {
        admin_credential_path(path)
    }

    #[test]
    fn first_init_writes_admin_credential_file_owner_only() {
        let path = temp_db("admin-first-init");
        let store = SqliteRelayStore::open(&path).unwrap();
        let file = admin_file(&path);
        let token = std::fs::read_to_string(&file).unwrap();
        // On-disk form: exactly 64 lowercase hex chars, the token itself.
        assert_eq!(token.trim().len(), 64);
        assert!(token
            .trim()
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        // Owner-only from birth: the file never exists world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Verification accepts only the real credential.
        assert!(store.verify_admin(token.trim()));
        assert!(!store.verify_admin(&"0".repeat(64)));
        // The Debug impl must not be a leak path for logs.
        let debug = format!("{store:?}");
        assert!(!debug.contains(token.trim()));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn restart_reads_back_the_same_admin_credential() {
        let path = temp_db("admin-restart");
        let token = {
            let _store = SqliteRelayStore::open(&path).unwrap();
            std::fs::read_to_string(admin_file(&path)).unwrap()
        };
        let store = SqliteRelayStore::open(&path).unwrap();
        // Same credential, no silent regeneration on restart.
        assert!(store.verify_admin(token.trim()));
        // No hardcoded or development default: an independent fresh
        // server gets an independent credential.
        let other = temp_db("admin-restart-other");
        let other_token = {
            let _store = SqliteRelayStore::open(&other).unwrap();
            std::fs::read_to_string(admin_file(&other)).unwrap()
        };
        assert_ne!(token, other_token);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(other.parent().unwrap()).ok();
    }

    #[test]
    fn missing_admin_file_for_existing_db_refuses_startup() {
        let path = temp_db("admin-missing");
        {
            let store = SqliteRelayStore::open(&path).unwrap();
            store.create_channel().unwrap();
        }
        std::fs::remove_file(admin_file(&path)).unwrap();
        let error = match SqliteRelayStore::open(&path) {
            Ok(_) => panic!("a live database without its admin credential must refuse to start"),
            Err(error) => error,
        };
        assert!(matches!(error, StoreOpenError::AdminCredentialMissing));
        // Refusal leaves the database untouched for the deployer.
        assert_eq!(envelope_count(&path, "no-channel"), 0);
        let conn = raw_connection(&path);
        let channels: i64 = conn
            .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
            .unwrap();
        assert_eq!(channels, 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn create_channel_assigns_fresh_ids_and_enables_traffic() {
        let path = temp_db("create-channel");
        let store = SqliteRelayStore::open(&path).unwrap();
        let first = store.create_channel().unwrap();
        let second = store.create_channel().unwrap();
        // Server-assigned opaque ids within the protocol contract.
        assert!(first.starts_with("ch_"));
        assert_ne!(first, second);
        assert!(first.len() <= 128 && second.len() <= 128);
        // The created channel is immediately usable end to end.
        store
            .append(&first, &[sample_envelope(&first, "msg-1", "ciphertext-1")])
            .unwrap();
        assert_eq!(store.head(&first).unwrap(), 1);
        let page = store.pull(&first, 0, 16, u64::MAX).unwrap();
        assert_eq!(page.entries[0].envelope.message_id, "msg-1");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// Everything a database can hold, as text: the only sound way to
    /// assert "the token is not stored anywhere" without trusting a
    /// column list.
    fn all_db_text(path: &Path) -> String {
        let conn = raw_connection(path);
        let mut out = String::new();
        for table in ["channels", "credentials", "envelopes"] {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let count = stmt.column_names().len();
            let rows = stmt
                .query_map([], |row| {
                    let mut parts = String::new();
                    for i in 0..count {
                        if let Ok(s) = row.get::<_, String>(i) {
                            parts.push_str(&s);
                        }
                        if let Ok(n) = row.get::<_, i64>(i) {
                            parts.push_str(&n.to_string());
                        }
                    }
                    Ok(parts)
                })
                .unwrap();
            for r in rows {
                out.push_str(&r.unwrap());
            }
        }
        out
    }

    #[test]
    fn issue_credential_stores_the_digest_and_not_the_token() {
        let path = temp_db("issue-digest");
        let store = SqliteRelayStore::open(&path).unwrap();
        let channel = store.create_channel().unwrap();
        let issued = store
            .issue_credential(
                &channel,
                &[CredentialScope::Append, CredentialScope::Pull],
                Some("phone"),
            )
            .unwrap();
        assert!(issued.credential_id.starts_with("cred_"));
        assert!(issued.token.len() >= 32);
        assert_eq!(issued.label.as_deref(), Some("phone"));
        assert_eq!(issued.scopes.len(), 2);
        // The digest is the only form of the token the database sees.
        let dump = all_db_text(&path);
        assert!(!dump.contains(&issued.token));
        assert!(dump.contains(&sha256_hex(issued.token.as_bytes())));
        // Debug of the issued struct is not a leak path either.
        assert!(!format!("{issued:?}").contains(&issued.token));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn issue_credential_rejects_unknown_channel() {
        let path = temp_db("issue-unknown-channel");
        let store = SqliteRelayStore::open(&path).unwrap();
        let error = store
            .issue_credential("no-such-channel", &[CredentialScope::Pull], None)
            .unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::ChannelNotFound);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn authorize_rejects_unknown_empty_and_garbage_tokens() {
        let path = temp_db("authorize-bad");
        let store = SqliteRelayStore::open(&path).unwrap();
        let channel = store.create_channel().unwrap();
        let issued = store
            .issue_credential(&channel, &[CredentialScope::Pull], None)
            .unwrap();
        let good = issued.token;
        assert_eq!(
            store
                .authorize(&channel, "not-a-token", CredentialScope::Pull)
                .unwrap_err()
                .code(),
            RelayErrorCode::Unauthorized
        );
        // A missing Authorization header reaches here empty; it must not
        // be mistaken for a digest hit.
        assert_eq!(
            store
                .authorize(&channel, "", CredentialScope::Pull)
                .unwrap_err()
                .code(),
            RelayErrorCode::Unauthorized
        );
        // The real credential for this channel still authorizes.
        store
            .authorize(&channel, &good, CredentialScope::Pull)
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn authorize_enforces_scopes_independently() {
        let path = temp_db("authorize-scope");
        let store = SqliteRelayStore::open(&path).unwrap();
        let channel = store.create_channel().unwrap();
        let append_only = store
            .issue_credential(&channel, &[CredentialScope::Append], None)
            .unwrap();
        store
            .authorize(&channel, &append_only.token, CredentialScope::Append)
            .unwrap();
        assert_eq!(
            store
                .authorize(&channel, &append_only.token, CredentialScope::Pull,)
                .unwrap_err()
                .code(),
            RelayErrorCode::Forbidden
        );
        let both = store
            .issue_credential(
                &channel,
                &[CredentialScope::Append, CredentialScope::Pull],
                None,
            )
            .unwrap();
        store
            .authorize(&channel, &both.token, CredentialScope::Append)
            .unwrap();
        store
            .authorize(&channel, &both.token, CredentialScope::Pull)
            .unwrap();
        // Every credential keeps its own scope set, independently.
        assert_ne!(append_only.credential_id, both.credential_id);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn authorize_cross_channel_is_forbidden_not_not_found() {
        let path = temp_db("authorize-cross");
        let store = SqliteRelayStore::open(&path).unwrap();
        let a = store.create_channel().unwrap();
        let b = store.create_channel().unwrap();
        let issued = store
            .issue_credential(&a, &[CredentialScope::Pull], None)
            .unwrap();
        // A valid foreign credential is 403, not a 404 that reveals
        // whether the channel exists (relay-protocol.md §auth).
        assert_eq!(
            store
                .authorize(&b, &issued.token, CredentialScope::Pull)
                .unwrap_err()
                .code(),
            RelayErrorCode::Forbidden
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn authorize_survives_restart() {
        let path = temp_db("authorize-restart");
        let (channel, token) = {
            let store = SqliteRelayStore::open(&path).unwrap();
            let channel = store.create_channel().unwrap();
            let issued = store
                .issue_credential(&channel, &[CredentialScope::Pull], Some("dev"))
                .unwrap();
            (channel, issued.token)
        };
        let store = SqliteRelayStore::open(&path).unwrap();
        store
            .authorize(&channel, &token, CredentialScope::Pull)
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// The credentials table as it shipped in schema v1: no `credential_id`,
    /// no `label`. Building it by hand is the only way to exercise the
    /// upgrade on realistic data rather than an empty table.
    const V1_SCHEMA_SQL: &str = "
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

    fn build_v1_database(path: &Path, channel: &str, token: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(V1_SCHEMA_SQL).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute("INSERT INTO channels(id) VALUES (?1)", params![channel])
            .unwrap();
        conn.execute(
            "INSERT INTO credentials (digest, scope, channel, created_at, \
             revoked_at) VALUES (?1, 'pull', ?2, 1700000000, NULL)",
            params![sha256_hex(token.as_bytes()), channel],
        )
        .unwrap();
        drop(conn);
    }

    #[test]
    fn v1_database_upgrades_to_v2_and_keeps_credential_authenticating() {
        let path = temp_db("v1-upgrade");
        let channel = "upgraded-chan";
        let token = "a-token-a-v1-binary-might-have-issued";
        build_v1_database(&path, channel, token);
        // The admin file is written the way a deployer would have it;
        // without it the existing database would refuse to start, which
        // is correct but not what this test is about.
        let file = admin_credential_path(&path);
        std::fs::write(&file, hex_encode(&[7u8; 32])).unwrap();

        let store = SqliteRelayStore::open(&path).unwrap();
        let version: i32 = store
            .conn
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let conn = raw_connection(&path);
        let backfilled: String = conn
            .query_row(
                "SELECT credential_id FROM credentials WHERE digest = ?1",
                params![sha256_hex(token.as_bytes())],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(backfilled, sha256_hex(token.as_bytes()));
        // The upgraded row authorizes exactly as it did before.
        store
            .authorize(channel, token, CredentialScope::Pull)
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    fn store_with_channel_and_credential(
        path: &Path,
        scopes: &[CredentialScope],
        label: Option<&str>,
    ) -> (String, IssuedCredential) {
        let store = SqliteRelayStore::open(path).unwrap();
        let channel = store.create_channel().unwrap();
        let issued = store.issue_credential(&channel, scopes, label).unwrap();
        (channel, issued)
    }

    #[test]
    fn revoke_refuses_the_credential_on_every_later_access() {
        let path = temp_db("revoke-immediate");
        let (channel, issued) = store_with_channel_and_credential(
            &path,
            &[CredentialScope::Append, CredentialScope::Pull],
            Some("phone"),
        );
        let store = SqliteRelayStore::open(&path).unwrap();
        let token = issued.token;
        // An already-connected device keeps a token in memory; what stops
        // it is the re-read of revocation on every authorize.
        store
            .authorize(&channel, &token, CredentialScope::Pull)
            .unwrap();
        assert_eq!(
            store
                .revoke_credential(&channel, &issued.credential_id)
                .unwrap(),
            RevokeOutcome::Revoked
        );
        for scope in [CredentialScope::Append, CredentialScope::Pull] {
            assert_eq!(
                store.authorize(&channel, &token, scope).unwrap_err().code(),
                RelayErrorCode::Unauthorized
            );
        }
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn revoke_survives_restart_and_leaves_other_credentials_alone() {
        let path = temp_db("revoke-restart");
        let scopes = &[CredentialScope::Append, CredentialScope::Pull];
        let channel = {
            let store = SqliteRelayStore::open(&path).unwrap();
            store.create_channel().unwrap()
        };
        let (revoked, kept) = {
            let store = SqliteRelayStore::open(&path).unwrap();
            (
                store
                    .issue_credential(&channel, scopes, Some("phone"))
                    .unwrap(),
                store
                    .issue_credential(&channel, scopes, Some("laptop"))
                    .unwrap(),
            )
        };
        {
            let store = SqliteRelayStore::open(&path).unwrap();
            store
                .revoke_credential(&channel, &revoked.credential_id)
                .unwrap();
        }
        let store = SqliteRelayStore::open(&path).unwrap();
        // The revoked one is still refused after the restart, on both
        // of its scopes.
        for scope in [CredentialScope::Append, CredentialScope::Pull] {
            assert_eq!(
                store
                    .authorize(&channel, &revoked.token, scope)
                    .unwrap_err()
                    .code(),
                RelayErrorCode::Unauthorized
            );
        }
        // The other device's credential is untouched — revocation is per
        // credential, never per channel and never global.
        store
            .authorize(&channel, &kept.token, CredentialScope::Append)
            .unwrap();
        store
            .authorize(&channel, &kept.token, CredentialScope::Pull)
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn revoke_is_idempotent_and_refuses_unknown_ids() {
        let path = temp_db("revoke-idempotent");
        let (channel, issued) =
            store_with_channel_and_credential(&path, &[CredentialScope::Pull], None);
        let store = SqliteRelayStore::open(&path).unwrap();
        let first = store
            .revoke_credential(&channel, &issued.credential_id)
            .unwrap();
        let second = store
            .revoke_credential(&channel, &issued.credential_id)
            .unwrap();
        assert_eq!(first, RevokeOutcome::Revoked);
        assert_eq!(second, RevokeOutcome::AlreadyRevoked);
        // A duplicate revoke is not an error, so retrying a UI action is
        // safe; it also cannot un-revoke.
        assert_eq!(
            store
                .authorize(&channel, &issued.token, CredentialScope::Pull)
                .unwrap_err()
                .code(),
            RelayErrorCode::Unauthorized
        );
        // Unknown ids, and ids that belong to another channel, refuse
        // with the same code: revocation never reveals presence.
        for bad in ["cred_0000000000000000", issued.credential_id.as_str()] {
            let error = store.revoke_credential("no-such-channel", bad).unwrap_err();
            assert_eq!(error.code(), RelayErrorCode::ChannelNotFound);
        }
        assert_eq!(
            store
                .revoke_credential(&channel, "cred_0000000000000000")
                .unwrap_err()
                .code(),
            RelayErrorCode::Unauthorized
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn revoke_records_a_timestamp_and_never_stores_the_token() {
        let path = temp_db("revoke-record");
        let (channel, issued) =
            store_with_channel_and_credential(&path, &[CredentialScope::Pull], Some("tablet"));
        let store = SqliteRelayStore::open(&path).unwrap();
        store
            .revoke_credential(&channel, &issued.credential_id)
            .unwrap();
        let conn = raw_connection(&path);
        let revoked_at: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM credentials WHERE digest = ?1",
                params![sha256_hex(issued.token.as_bytes())],
                |row| row.get(0),
            )
            .unwrap();
        assert!(revoked_at.is_some());
        assert!(revoked_at.unwrap() > 0);
        // The row is retained, and only as a digest: the token still
        // appears nowhere after revocation.
        assert!(!all_db_text(&path).contains(&issued.token));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// Open a store with small budgets so a test can reach a quota without
    /// gigabytes of ciphertext.
    fn store_with_quotas(path: &Path, quotas: Quotas) -> (SqliteRelayStore, String) {
        let store = SqliteRelayStore::open_with_quotas(path, quotas).unwrap();
        let channel = store.create_channel().unwrap();
        (store, channel)
    }

    /// Bytes the channel occupies, the same measurement `append` uses for
    /// its budget check. A separate connection lets the measurement
    /// survive dropping the store.
    fn channel_used_bytes(path: &Path, channel: &str) -> i64 {
        let conn = raw_connection(path);
        conn.query_row(
            "SELECT COALESCE(SUM(octet_length(payload)), 0)              FROM envelopes WHERE channel = ?1",
            params![channel],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn batch(n: usize, channel: &str) -> Vec<Envelope> {
        (1..=n)
            .map(|i| sample_envelope(channel, &format!("id-{i:02}"), &format!("body-{i:02}")))
            .collect()
    }

    #[test]
    fn channel_quota_stops_append_and_leaves_everything_readable() {
        let path = temp_db("quota-channel");
        // Commit with limits disabled, then reopen at exactly the bytes
        // already stored: any further append must cross the budget.
        let (store, channel) = store_with_quotas(
            &path,
            Quotas {
                channel_bytes: 0,
                disk_bytes: 0,
            },
        );
        store.append(&channel, &batch(2, &channel)).unwrap();
        let budget = channel_used_bytes(&path, &channel) as u64;
        drop(store);
        let (store, _) = store_with_quotas(
            &path,
            Quotas {
                channel_bytes: budget,
                disk_bytes: 0,
            },
        );
        let error = store.append(&channel, &batch(16, &channel)).unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::QuotaExceeded);
        // Reads are never blocked by a quota: the two committed rows are
        // still there, in order, with nothing half-consumed.
        assert_eq!(store.head(&channel).unwrap(), 2);
        let page = store.pull(&channel, 0, 64, u64::MAX).unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(!page.has_more);
        // The rejected batch wrote nothing at all.
        assert_eq!(envelope_count(&path, &channel), 2);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn disk_quota_spans_channels_and_rolls_the_batch_back() {
        let path = temp_db("quota-disk");
        let (store, channel) = store_with_quotas(
            &path,
            Quotas {
                channel_bytes: 0,
                disk_bytes: 0,
            },
        );
        let other = store.create_channel().unwrap();
        store.append(&channel, &batch(2, &channel)).unwrap();
        store.append(&other, &batch(2, &other)).unwrap();
        drop(store);
        // Measured after the drop: closing the connection checkpoints
        // and frees the WAL sidecar, so a budget taken while it was
        // still open would not be the budget the reopened store sees.
        let budget = disk_bytes_used(&path);
        let (store, _) = store_with_quotas(
            &path,
            Quotas {
                channel_bytes: 0,
                disk_bytes: budget,
            },
        );
        // A genuinely new message id: a duplicate id would add no bytes
        // and so could never cross a budget.
        let probe = sample_envelope(&other, "id-probe", "body-probe");
        let error = store
            .append(&other, std::slice::from_ref(&probe))
            .unwrap_err();
        assert_eq!(error.code(), RelayErrorCode::QuotaExceeded);
        // Both committed channels read fine; the refused batch left no
        // row in either one.
        assert_eq!(store.head(&channel).unwrap(), 2);
        assert_eq!(store.head(&other).unwrap(), 2);
        assert_eq!(envelope_count(&path, &channel), 2);
        assert_eq!(envelope_count(&path, &other), 2);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn quota_is_not_enforced_on_reads_after_a_quota_refusal() {
        let path = temp_db("quota-reads-open");
        let (store, channel) = store_with_quotas(
            &path,
            Quotas {
                channel_bytes: 0,
                disk_bytes: 0,
            },
        );
        store.append(&channel, &batch(2, &channel)).unwrap();
        let budget = channel_used_bytes(&path, &channel) as u64;
        drop(store);
        let (store, _) = store_with_quotas(
            &path,
            Quotas {
                channel_bytes: budget,
                disk_bytes: 0,
            },
        );
        let _ = store.append(&channel, &batch(16, &channel)).unwrap_err();
        // Pull and head keep working against a full channel — this is the
        // v1 retention contract: no pruning, so a read cannot be evicted.
        let page = store.pull(&channel, 1, 64, u64::MAX).unwrap();
        assert_eq!(page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [2]);
        assert_eq!(store.head(&channel).unwrap(), 2);
        // Issuance and revocation stay available too: they are not data
        // growth and the relay must remain administrable.
        let issued = store
            .issue_credential(&channel, &[CredentialScope::Pull], None)
            .unwrap();
        store
            .authorize(&channel, &issued.token, CredentialScope::Pull)
            .unwrap();
        assert_eq!(
            store
                .revoke_credential(&channel, &issued.credential_id)
                .unwrap(),
            RevokeOutcome::Revoked
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn quota_refusal_is_not_recorded_and_survives_restart() {
        let path = temp_db("quota-restart");
        let (store, channel) = store_with_quotas(
            &path,
            Quotas {
                channel_bytes: 0,
                disk_bytes: 0,
            },
        );
        store.append(&channel, &batch(2, &channel)).unwrap();
        drop(store);
        let budget = channel_used_bytes(&path, &channel) as u64;
        let quotas = Quotas {
            channel_bytes: budget,
            disk_bytes: 0,
        };
        let (store, _) = store_with_quotas(&path, quotas);
        let rejected = batch(16, &channel);
        let _ = store.append(&channel, &rejected).unwrap_err();
        // Reopen with the same budgets: still full, still readable, and
        // the refused batch is not queued for later replay.
        drop(store);
        let (store, _) = store_with_quotas(&path, quotas);
        assert_eq!(store.head(&channel).unwrap(), 2);
        assert_eq!(envelope_count(&path, &channel), 2);
        let probe = sample_envelope(&channel, "id-probe", "body-probe");
        let again = store
            .append(&channel, std::slice::from_ref(&probe))
            .unwrap_err();
        assert_eq!(again.code(), RelayErrorCode::QuotaExceeded);
        assert_eq!(
            store.pull(&channel, 0, 64, u64::MAX).unwrap().entries.len(),
            2
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn zero_quota_disables_the_limit_and_duplicates_never_count_against_it() {
        let path = temp_db("quota-zero");
        // `0` means disabled, never "block everything" (relay-protocol.md
        // §limits).
        let (store, channel) = store_with_quotas(
            &path,
            Quotas {
                channel_bytes: 0,
                disk_bytes: 0,
            },
        );
        let two = batch(2, &channel);
        store.append(&channel, &two).unwrap();
        // A retry of the same batch adds no bytes, so it can never push a
        // real budget over the edge: measure the stored bytes, reopen at
        // exactly that, and replay.
        let budget = channel_used_bytes(&path, &channel) as u64;
        drop(store);
        let path2 = temp_db("quota-duplicate");
        let (store2, channel2) = store_with_quotas(
            &path2,
            Quotas {
                channel_bytes: 0,
                disk_bytes: 0,
            },
        );
        let two2 = batch(2, &channel2);
        let acks = store2.append(&channel2, &two2).unwrap().acks;
        assert_eq!(acks.len(), 2);
        let tight = channel_used_bytes(&path2, &channel2) as u64;
        assert!(tight > 0 && budget > 0);
        drop(store2);
        let (store2, _) = store_with_quotas(
            &path2,
            Quotas {
                channel_bytes: tight,
                disk_bytes: 0,
            },
        );
        let retry = store2.append(&channel2, &two2).unwrap().acks;
        assert!(retry.iter().all(|ack| ack.duplicate));
        assert_eq!(store2.head(&channel2).unwrap(), 2);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(path2.parent().unwrap()).ok();
    }
}
