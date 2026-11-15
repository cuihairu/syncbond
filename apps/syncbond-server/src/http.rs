//! The v1 HTTP surface (todo.md DSR-19): channel management, append,
//! pull, and health/readiness, wired onto [`RelayStorage`].
//!
//! Everything here is transport-shaped: parse the body, check the version,
//! authenticate, call storage, map the result to the frozen status/body
//! pair from relay-protocol.md §3 and §6. No rule about *what* is allowed
//! lives in this file — the storage layer owns authorization semantics and
//! the protocol crate owns codes, statuses and limits.
//!
//! Two invariants worth stating because they are easy to lose:
//!
//! - A body this layer cannot parse is still answered with the frozen
//!   [`ErrorBody`] shape and `requestId: null`; clients switch on `code`,
//!   so a bare framework 400 would be a contract break.
//! - Tokens are read from the `Authorization` header only. They never enter
//!   logs, error messages, or the response, and admin tokens never leave
//!   this module's comparison in storage.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use syncbond_relay_protocol::dto::{
    AppendAck, AppendRequest, ChannelCreated, CreateRoomRequest, CredentialIssued,
    CredentialRevoked, IssueCredentialRequest, PullRequest, PullResponse, RoomCreated,
};
use syncbond_relay_protocol::error::{ErrorBody, RelayError, RelayErrorCode};
use syncbond_relay_protocol::{
    check_batch, check_envelope, check_request_id, check_version, effective_pull_limits,
    RELAY_PROTOCOL_VERSION,
};

use crate::rooms::PairingRooms;
use crate::sqlite::SqliteRelayStore;
use crate::storage::{IssuedCredential, RelayStorage, StorageError};
use crate::ws::RoomSessions;

/// Shared state for every route. The store is `Send + Sync` by contract,
/// which is exactly why `SqliteRelayStore` guards its connection with a
/// mutex (see its module docs). Pairing rooms are separate: they are
/// 120-second memory-only state and never touch storage.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<SqliteRelayStore>,
    pub rooms: Arc<PairingRooms>,
    /// Live pairing-room sockets (the WebSocket join route's forwarding
    /// table, DSR-21).
    pub sessions: Arc<RoomSessions>,
    /// Origins a browser client may present at a WebSocket upgrade; an
    /// Origin header not in this list is a 403. Non-browser clients send
    /// no Origin and are unaffected.
    pub allowed_origins: Vec<String>,
    /// Proxies whose `X-Forwarded-For` may key the room-creation rate
    /// limit (crate::proxy); empty means the peer address is always the
    /// client address.
    pub trusted_proxies: Vec<crate::proxy::TrustedProxy>,
    /// Live channel-event subscriptions (crate::ws, DSR-22): the append
    /// route pushes lossy hints through this registry after a commit.
    pub subscriptions: std::sync::Arc<crate::ws::ChannelSubscriptions>,
}

/// Build the router. Kept separate from `listen` so tests can drive it
/// through a real socket or mount it elsewhere. Serving must use
/// `into_make_service_with_connect_info` — the pairing-room creation route
/// rate-limits by the peer's socket address.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/ready", get(ready))
        .route("/v1/channels", post(create_channel))
        .route(
            "/v1/channels/{channel_id}/credentials",
            post(issue_credential).get(list_credentials),
        )
        .route(
            "/v1/channels/{channel_id}/credentials/{credential_id}",
            delete(revoke_credential),
        )
        .route("/v1/channels/{channel_id}/append", post(append))
        .route("/v1/channels/{channel_id}/pull", post(pull))
        .route(
            "/v1/channels/{channel_id}/events",
            get(crate::ws::events_stream),
        )
        .route("/v1/pairing/rooms", post(create_room))
        .route("/v1/pairing/{room_id}", get(crate::ws::join_room))
        .with_state(state)
}

// ---------------------------------------------------------------- health

/// Liveness: the process answers at all. Deliberately does not touch
/// storage — a relay that is still opening its database is alive, and
/// reporting it dead would restart it in a loop.
async fn health() -> Response {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

/// Readiness: storage can answer a read right now.
async fn ready(State(state): State<AppState>) -> Response {
    if state.store.ready() {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready" })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "unavailable" })),
        )
            .into_response()
    }
}

// ------------------------------------------------------------- plumbing

/// A wire failure: code, message, the status and retryability come from
/// the frozen mapping. `request_id` is whatever the request managed to
/// carry, or `None` when even that could not be parsed.
pub(crate) struct Failure {
    error: RelayError,
    request_id: Option<String>,
}

impl Failure {
    fn new(error: RelayError, request_id: Option<String>) -> Self {
        Self { error, request_id }
    }

    fn from_storage(error: StorageError, request_id: Option<String>) -> Self {
        Self::new(RelayError::new(error.code(), error.message()), request_id)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.error.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ErrorBody::new(
            RELAY_PROTOCOL_VERSION,
            self.request_id.as_deref(),
            &self.error,
        );
        (status, Json(body)).into_response()
    }
}

/// Parse a JSON body into `T`, echoing `requestId` when the raw JSON still
/// carries one. `deny_unknown_fields` on every DTO means shape violations
/// surface here as `bad_request`, which is exactly the frozen behavior.
fn parse_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, Failure> {
    serde_json::from_slice::<T>(body).map_err(|error| {
        let request_id = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .get("requestId")
                    .and_then(|id| id.as_str())
                    .map(str::to_owned)
            });
        Failure::new(
            RelayError::new(RelayErrorCode::BadRequest, error.to_string()),
            request_id,
        )
    })
}

/// Run the version and request-id checks that every body-carrying route
/// shares, after deserialization so `requestId` can be echoed.
fn validate_envelope_fields(protocol_version: u16, request_id: &str) -> Result<(), Failure> {
    check_version(protocol_version)
        .and_then(|()| check_request_id(request_id))
        .map_err(|error| Failure::new(error, Some(request_id.to_string())))
}

/// The bearer token, if the header is present and well-formed. A header
/// that is present but not `Bearer <token>` is treated as absent: there is
/// no third state, and a malformed header must not read as a credential.
pub(crate) fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?;
    let text = value.to_str().ok()?;
    let token = text.strip_prefix("Bearer ")?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

/// Admin routes: a missing token is 401, a wrong token is 401 as well (the
/// token is simply not the admin credential), and a channel credential is
/// never accepted here.
fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
    request_id: Option<String>,
) -> Result<(), Failure> {
    let token = bearer(headers).ok_or_else(|| {
        Failure::new(
            RelayError::new(RelayErrorCode::Unauthorized, "admin credential required"),
            request_id.clone(),
        )
    })?;
    if state.store.verify_admin(&token) {
        Ok(())
    } else {
        Err(Failure::new(
            RelayError::new(RelayErrorCode::Unauthorized, "admin credential required"),
            request_id,
        ))
    }
}

// ------------------------------------------------------ channel management

async fn create_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct CreateChannelRequest {
        protocol_version: u16,
        request_id: String,
    }
    let request: CreateChannelRequest = match parse_body(&body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let request_id = Some(request.request_id.clone());
    if let Err(failure) = validate_envelope_fields(request.protocol_version, &request.request_id) {
        return failure.into_response();
    }
    if let Err(failure) = require_admin(&state, &headers, request_id.clone()) {
        return failure.into_response();
    }
    match state.store.create_channel() {
        Ok(channel_id) => (
            StatusCode::CREATED,
            Json(ChannelCreated {
                protocol_version: RELAY_PROTOCOL_VERSION,
                request_id: request.request_id,
                channel_id,
            }),
        )
            .into_response(),
        Err(error) => Failure::from_storage(error, request_id).into_response(),
    }
}

// ---------------------------------------------------------- pairing rooms

/// Create a pairing room (relay-protocol.md §7). No credential — the route
/// is open and answered with the rate limit alone: per source IP, over a
/// sliding one-minute window. The response shows the capability exactly
/// once; the relay stores only its digest.
async fn create_room(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request: CreateRoomRequest = match parse_body(&body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let request_id = Some(request.request_id.clone());
    if let Err(failure) = validate_envelope_fields(request.protocol_version, &request.request_id) {
        return failure.into_response();
    }
    let now_ms = match unix_now_ms() {
        Ok(now_ms) => now_ms,
        Err(failure) => return failure.into_response(),
    };
    // Rate-limit key: the peer address, or — behind a trusted proxy —
    // the client the proxy chain saw (crate::proxy for the policy).
    let client_ip = crate::proxy::client_ip(
        peer.ip(),
        headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok()),
        &state.trusted_proxies,
    );
    match state.rooms.create(client_ip, now_ms) {
        Ok(created) => (
            StatusCode::CREATED,
            Json(RoomCreated {
                protocol_version: RELAY_PROTOCOL_VERSION,
                request_id: request.request_id,
                room_id: created.room_id,
                capability: created.capability,
                expires_at: crate::rooms::rfc3339_utc(created.expires_at_ms),
            }),
        )
            .into_response(),
        Err(error) => Failure::new(
            RelayError::new(error.code(), "room creation rate limit exceeded"),
            request_id,
        )
        .into_response(),
    }
}

/// Wall-clock unix milliseconds. A clock before the epoch cannot address a
/// TTL deadline and is surfaced instead of silently minting dead rooms.
pub(crate) fn unix_now_ms() -> Result<u64, Failure> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .map_err(|_| {
            Failure::new(
                RelayError::new(
                    RelayErrorCode::Internal,
                    "system clock is before the unix epoch",
                ),
                None,
            )
        })
}

async fn issue_credential(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request: IssueCredentialRequest = match parse_body(&body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let request_id = Some(request.request_id.clone());
    if let Err(failure) = validate_envelope_fields(request.protocol_version, &request.request_id) {
        return failure.into_response();
    }
    if let Err(failure) = require_admin(&state, &headers, request_id.clone()) {
        return failure.into_response();
    }
    // An empty scope set would mint a credential that can do nothing;
    // refuse it rather than hand out a token with no use.
    if request.scopes.is_empty() {
        return Failure::new(
            RelayError::new(RelayErrorCode::BadRequest, "scopes must not be empty"),
            request_id,
        )
        .into_response();
    }
    let issued =
        match state
            .store
            .issue_credential(&channel_id, &request.scopes, request.label.as_deref())
        {
            Ok(issued) => issued,
            Err(error) => return Failure::from_storage(error, request_id).into_response(),
        };
    // The token leaves the process exactly here and never again.
    let IssuedCredential {
        credential_id,
        token,
        scopes,
        label,
    } = issued;
    (
        StatusCode::CREATED,
        Json(CredentialIssued {
            protocol_version: RELAY_PROTOCOL_VERSION,
            request_id: request.request_id,
            credential_id,
            token,
            scopes,
            label,
        }),
    )
        .into_response()
}

/// The list shape is this module's own: the frozen contract fixes the route
/// and its constraints ("digests and metadata only, never tokens") but not
/// the exact JSON, so the fields here are named after the record they
/// project and carry no token — there is no field that could.
async fn list_credentials(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(failure) = require_admin(&state, &headers, None) {
        return failure.into_response();
    }
    match state.store.list_credentials(&channel_id) {
        Ok(records) => {
            let credentials: Vec<serde_json::Value> = records
                .into_iter()
                .map(|record| {
                    serde_json::json!({
                        "credentialId": record.credential_id,
                        "digest": record.digest,
                        "scopes": record.scopes,
                        "label": record.label,
                        "createdAt": record.created_at,
                        "revokedAt": record.revoked_at,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "protocolVersion": RELAY_PROTOCOL_VERSION,
                    "channelId": channel_id,
                    "credentials": credentials,
                })),
            )
                .into_response()
        }
        Err(error) => Failure::from_storage(error, None).into_response(),
    }
}

/// Revoke by path, per relay-protocol.md §3.2. No body: the route is a
/// DELETE and there is nothing to say beyond "this credential id, this
/// channel". `requestId` therefore comes from the `X-Request-Id` header,
/// the one field a request-less route can echo — or stays empty when the
/// caller sent none, which is what "there was no id to echo" means.
async fn revoke_credential(
    State(state): State<AppState>,
    Path((channel_id, credential_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let request_id = headers
        .get(axum::http::HeaderName::from_static("x-request-id"))
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if let Err(failure) = require_admin(&state, &headers, Some(request_id.clone())) {
        return failure.into_response();
    }
    match state.store.revoke_credential(&channel_id, &credential_id) {
        Ok(_outcome) => {
            // AlreadyRevoked is not an error: the post-state the caller
            // asked for holds either way, and a retried UI action must not
            // fail.
            (
                StatusCode::OK,
                Json(CredentialRevoked {
                    protocol_version: RELAY_PROTOCOL_VERSION,
                    request_id,
                    revoked: credential_id,
                }),
            )
                .into_response()
        }
        Err(error) => Failure::from_storage(error, None).into_response(),
    }
}

// ---------------------------------------------------- append and pull

async fn append(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request: AppendRequest = match parse_body(&body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let request_id = Some(request.request_id.clone());
    if let Err(failure) = validate_envelope_fields(request.protocol_version, &request.request_id) {
        return failure.into_response();
    }
    if let Err(failure) = channel_token(
        &state,
        &headers,
        &channel_id,
        SyncScope::Append,
        request_id.clone(),
    ) {
        return failure.into_response();
    }
    // Batch shape first (count/total bytes), then per-envelope field
    // bounds: a client that sent 17 envelopes should hear batch_too_large,
    // not a complaint about envelope #3.
    if let Err(error) = check_batch(&request.envelopes) {
        return Failure::new(RelayError::new(error.code(), error.to_string()), request_id)
            .into_response();
    }
    for envelope in &request.envelopes {
        if let Err(error) = check_envelope(envelope) {
            return Failure::new(error, request_id).into_response();
        }
        // The outer contract version governs the request; an envelope
        // claiming a different one is from a client that mixed versions.
        if envelope.protocol_version != RELAY_PROTOCOL_VERSION {
            return Failure::new(
                RelayError::new(
                    RelayErrorCode::VersionUnsupported,
                    format!(
                        "envelope protocolVersion {} is not supported (expected {RELAY_PROTOCOL_VERSION})",
                        envelope.protocol_version
                    ),
                ),
                request_id,
            )
            .into_response();
        }
    }
    match state.store.append(&channel_id, &request.envelopes) {
        Ok(outcome) => {
            // Hints follow the commit they describe: the ACK below is only
            // built because the transaction committed (DSR-13), so any
            // push here reports real state. Each subscriber re-authorizes
            // on its push, which is where a revoked credential's stream
            // is closed with 4401 (relay-protocol.md §8).
            if let Some(seq) = outcome.acks.last().map(|ack| ack.seq) {
                state.subscriptions.notify(&channel_id, seq, &mut |token| {
                    use crate::storage::RelayStorage as _;
                    state
                        .store
                        .authorize(
                            &channel_id,
                            token,
                            syncbond_relay_protocol::dto::CredentialScope::Pull,
                        )
                        .is_ok()
                });
            }
            (
                StatusCode::OK,
                Json(AppendAck {
                    protocol_version: RELAY_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    channel_id,
                    acks: outcome.acks,
                }),
            )
                .into_response()
        }
        Err(error) => Failure::from_storage(error, request_id).into_response(),
    }
}

async fn pull(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request: PullRequest = match parse_body(&body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let request_id = Some(request.request_id.clone());
    if let Err(failure) = validate_envelope_fields(request.protocol_version, &request.request_id) {
        return failure.into_response();
    }
    if let Err(failure) = channel_token(
        &state,
        &headers,
        &channel_id,
        SyncScope::Pull,
        request_id.clone(),
    ) {
        return failure.into_response();
    }
    let (limit, max_bytes) = match effective_pull_limits(request.limit, request.max_bytes) {
        Ok(limits) => limits,
        Err(error) => {
            return Failure::new(RelayError::new(error.code(), error.to_string()), request_id)
                .into_response();
        }
    };
    match state
        .store
        .pull(&channel_id, request.after, limit, max_bytes)
    {
        Ok(page) => {
            // An empty page must echo the input cursor: advancing it past
            // an empty page would skip records on the next call.
            let next_cursor = page
                .entries
                .last()
                .map(|entry| entry.seq)
                .unwrap_or(request.after);
            (
                StatusCode::OK,
                Json(PullResponse {
                    protocol_version: RELAY_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    channel_id,
                    entries: page.entries,
                    next_cursor,
                    has_more: page.has_more,
                }),
            )
                .into_response()
        }
        Err(error) => Failure::from_storage(error, request_id).into_response(),
    }
}

/// Which channel scope a data route needs.
#[derive(Clone, Copy)]
enum SyncScope {
    Append,
    Pull,
}

/// Authenticate a channel credential for `(channel, scope)`: missing token
/// is 401, a token that is unknown/revoked is 401, and a valid token for
/// another channel or without the scope is 403 (relay-protocol.md §auth).
fn channel_token(
    state: &AppState,
    headers: &HeaderMap,
    channel_id: &str,
    scope: SyncScope,
    request_id: Option<String>,
) -> Result<(), Failure> {
    let token = bearer(headers).ok_or_else(|| {
        Failure::new(
            RelayError::new(RelayErrorCode::Unauthorized, "credential required"),
            request_id.clone(),
        )
    })?;
    let scope_enum = match scope {
        SyncScope::Append => syncbond_relay_protocol::dto::CredentialScope::Append,
        SyncScope::Pull => syncbond_relay_protocol::dto::CredentialScope::Pull,
    };
    state
        .store
        .authorize(channel_id, &token, scope_enum)
        .map_err(|error| Failure::from_storage(error, request_id))
}

#[cfg(test)]
mod tests {
    // Real-socket coverage for todo.md DSR-19: every assertion below drives
    // the router over a live TCP listener on 127.0.0.1:0, so the status
    // code, the `protocolVersion` and the `error.code` are what a client
    // actually receives — not what a handler happens to return.
    use super::*;
    use crate::sqlite::{admin_credential_path, SqliteRelayStore};
    use base64::Engine as _;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// One relay under test: the address it listens on, its admin
    /// credential, and the state that must outlive the serve loop. Dropping
    /// it aborts the listener and removes the database.
    struct Relay {
        address: String,
        admin: String,
        _task: tokio::task::JoinHandle<()>,
        _db: std::path::PathBuf,
        /// The relay's runtime: it owns the serve task, so it must stay
        /// alive until the relay does.
        _runtime: std::mem::ManuallyDrop<tokio::runtime::Runtime>,
    }

    impl Drop for Relay {
        fn drop(&mut self) {
            self._task.abort();
            std::fs::remove_file(&self._db).ok();
            // Runtime's own drop blocks, which panics inside a
            // #[tokio::test] body; hand the runtime to a detached OS
            // thread and let it shut down there.
            let runtime = unsafe { std::mem::ManuallyDrop::take(&mut self._runtime) };
            std::thread::spawn(move || drop(runtime));
        }
    }

    fn fresh_db() -> std::path::PathBuf {
        // Distinct directories per thread and per call so parallel tests
        // never share a database or its admin credential.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "syncbond-http-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("relay.db")
    }

    /// The state `main` assembles, as the tests assemble it: one store,
    /// one room registry, one forwarding table, no browser origins.
    fn boot_state(store: std::sync::Arc<SqliteRelayStore>) -> AppState {
        AppState {
            store,
            rooms: std::sync::Arc::new(PairingRooms::new()),
            sessions: std::sync::Arc::new(RoomSessions::default()),
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            subscriptions: std::sync::Arc::new(crate::ws::ChannelSubscriptions::default()),
        }
    }

    /// Boot a relay: one store, one listener on an ephemeral port. `ready`
    /// lifts the readiness gate the way the binary's serve loop does.
    fn boot(db: std::path::PathBuf, ready: bool) -> Relay {
        boot_with(db, ready, boot_state)
    }

    /// The same relay, with the caller assembling state — used by the
    /// WebSocket tests to pre-seed rooms against a shifted clock or to
    /// configure browser origins.
    fn boot_with(
        db: std::path::PathBuf,
        ready: bool,
        state_of: impl FnOnce(std::sync::Arc<SqliteRelayStore>) -> AppState + Send + 'static,
    ) -> Relay {
        let store = std::sync::Arc::new(SqliteRelayStore::open(&db).unwrap());
        if ready {
            store.mark_ready();
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        // Bound inside the relay's own runtime and handed back over a std
        // channel: from_std needs a reactor, and block_on would nest inside
        // the #[tokio::test] bodies. Works from sync tests the same way.
        let (address_tx, address_rx) = std::sync::mpsc::channel::<String>();
        // Served exactly the way `main` serves it: with connect info,
        // because the pairing-room route rate-limits per peer address.
        let task = runtime.spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            address_tx
                .send(listener.local_addr().unwrap().to_string())
                .expect("the boot thread always collects the address");
            let app = router(state_of(store));
            if let Err(error) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                eprintln!("test relay serve error: {error}");
            }
        });
        let address = address_rx.recv().unwrap();
        let admin = std::fs::read_to_string(admin_credential_path(&db)).unwrap();
        Relay {
            address,
            admin: admin.trim().to_owned(),
            _task: task,
            _db: db,
            _runtime: std::mem::ManuallyDrop::new(runtime),
        }
    }

    /// A fresh relay, serving and ready.
    fn start() -> Relay {
        boot(fresh_db(), true)
    }

    /// One channel plus one credential, minted over HTTP so the routes
    /// under test produced their own preconditions.
    fn provision(
        relay: &Relay,
        scopes: serde_json::Value,
        label: &str,
    ) -> (String, String, String) {
        let created = call(
            &relay.address,
            "POST",
            "/v1/channels",
            Some(&json_request(1, "c-000000000001")),
            Some(&admin_authorization(&relay.admin)),
        );
        let channel = created["channelId"].as_str().unwrap().to_owned();
        let request = serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": "i-000000000001",
            "scopes": scopes,
            "label": label,
        }))
        .unwrap();
        let issued = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/credentials"),
            Some(&request),
            Some(&admin_authorization(&relay.admin)),
        );
        let credential_id = issued["credentialId"].as_str().unwrap().to_owned();
        let token = issued["token"].as_str().unwrap().to_owned();
        (channel, credential_id, token)
    }

    fn admin_authorization(admin: &str) -> String {
        format!("Authorization: Bearer {admin}")
    }

    fn bearer(token: &str) -> String {
        format!("Authorization: Bearer {token}")
    }

    fn json_request(protocol_version: u16, request_id: &str) -> String {
        serde_json::to_string(&serde_json::json!({
            "protocolVersion": protocol_version,
            "requestId": request_id,
        }))
        .unwrap()
    }

    /// The same envelope, but its version field is the caller's to set.
    /// Used for the wrong-version case, where the body must still carry
    /// `envelopes` or deserialization would reject it before the version
    /// check ran.
    fn versioned_request(protocol_version: u16, request_id: &str) -> String {
        serde_json::to_string(&serde_json::json!({
            "protocolVersion": protocol_version,
            "requestId": request_id,
            "envelopes": [],
        }))
        .unwrap()
    }

    /// A well-formed envelope: right id length (16..=64 chars), non-empty
    /// group and device ids, `keyEpoch >= 1`.
    fn envelope(id: &str, ciphertext: &str) -> serde_json::Value {
        serde_json::json!({
            "protocolVersion": 1,
            "groupId": "g_0123456789abcdef",
            "senderDeviceId": "dev-phone",
            "keyEpoch": 1,
            "messageId": id,
            "nonce": "n-0123456789abcdef",
            "ciphertext": ciphertext,
        })
    }

    fn append_request(message_ids: &[&str]) -> String {
        let envelopes: Vec<serde_json::Value> =
            message_ids.iter().map(|id| envelope(id, "AAAA")).collect();
        serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": "r-append-00000001",
            "envelopes": envelopes,
        }))
        .unwrap()
    }

    fn pull_request(after: u64, limit: Option<u16>) -> String {
        let mut request = serde_json::json!({
            "protocolVersion": 1,
            "requestId": "r-pull-00000001",
            "after": after,
        });
        if let Some(limit) = limit {
            request["limit"] = serde_json::json!(limit);
        }
        serde_json::to_string(&request).unwrap()
    }

    /// HTTP status plus the parsed response body.
    struct Reply {
        status: u16,
        body: serde_json::Value,
    }

    /// One blocking HTTP/1.1 request over a real socket. `Connection: close`
    /// and reading to EOF is enough for a one-shot call; the tests assert
    /// the full wire shape, status included.
    fn call_with_status(
        address: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        header: Option<&str>,
    ) -> Reply {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(extra) = header {
            request.push_str(extra);
            request.push_str("\r\n");
        }
        let payload = body.unwrap_or("");
        request.push_str(&format!(
            "Content-Length: {}\r\n\r\n{payload}",
            payload.len()
        ));
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .expect("a response always has a header block");
        let status = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap_or(599);
        Reply {
            status,
            body: serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
        }
    }

    fn call(
        address: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        header: Option<&str>,
    ) -> serde_json::Value {
        call_with_status(address, method, path, body, header).body
    }

    // ---------------------------------------------------------- happy paths

    #[test]
    fn health_answers_liveness_without_touching_storage() {
        let relay = start();
        let body = call(&relay.address, "GET", "/v1/health", None, None);
        assert_eq!(body["status"], "ok");
    }

    #[test]
    fn readiness_reports_not_ready_until_the_gate_lifts() {
        // The gate, not the handler, is what flips 200 -> 503, so a process
        // that has not finished starting says exactly that.
        let relay = boot(fresh_db(), false);
        let body = call(&relay.address, "GET", "/v1/ready", None, None);
        assert_eq!(body["status"], "unavailable");
        let reply = call_with_status(&relay.address, "GET", "/v1/ready", None, None);
        assert_eq!(reply.status, 503);
        // Liveness still answers: the process is alive, just not ready.
        let alive = call(&relay.address, "GET", "/v1/health", None, None);
        assert_eq!(alive["status"], "ok");
    }

    #[test]
    fn readiness_reports_ready_once_the_gate_lifts() {
        let relay = start();
        let body = call(&relay.address, "GET", "/v1/ready", None, None);
        assert_eq!(body["status"], "ready");
    }

    #[test]
    fn admin_creates_a_channel() {
        let relay = start();
        let body = call(
            &relay.address,
            "POST",
            "/v1/channels",
            Some(&json_request(1, "c-000000000001")),
            Some(&admin_authorization(&relay.admin)),
        );
        assert!(body["channelId"].as_str().unwrap().starts_with("ch_"));
        assert_eq!(body["protocolVersion"], 1);
        assert_eq!(body["requestId"], "c-000000000001");
    }

    #[test]
    fn admin_issues_a_credential_and_its_token_works() {
        let relay = start();
        let (channel, credential_id, token) =
            provision(&relay, serde_json::json!(["append", "pull"]), "phone");
        assert!(token.len() >= 32);
        assert!(credential_id.starts_with("cred_"));
        // The token is accepted exactly on the channel it was issued for.
        let ack = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&append_request(&["m-0000000000000001"])),
            Some(&bearer(&token)),
        );
        assert_eq!(ack["channelId"], channel);
        assert_eq!(ack["acks"][0]["seq"], 1);
    }

    #[test]
    fn a_revoked_credential_is_refused() {
        let relay = start();
        let (channel, credential_id, token) =
            provision(&relay, serde_json::json!(["append", "pull"]), "phone");
        let revoked = call(
            &relay.address,
            "DELETE",
            &format!("/v1/channels/{channel}/credentials/{credential_id}"),
            None,
            Some(&admin_authorization(&relay.admin)),
        );
        assert_eq!(revoked["revoked"], credential_id);
        // The revoked token now fails: revocation is a persisted flag the
        // authorize path re-reads, not a cache invalidation.
        let refused = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&append_request(&["m-0000000000000002"])),
            Some(&bearer(&token)),
        );
        assert_eq!(refused["error"]["code"], "unauthorized");
    }

    #[test]
    fn admin_lists_credentials_without_leaking_tokens() {
        let relay = start();
        let (channel, credential_id, token) =
            provision(&relay, serde_json::json!(["append", "pull"]), "phone");
        let listed = call(
            &relay.address,
            "GET",
            &format!("/v1/channels/{channel}/credentials"),
            None,
            Some(&admin_authorization(&relay.admin)),
        );
        let credentials = listed["credentials"].as_array().unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0]["credentialId"], credential_id);
        // Digests and metadata only: the token is nowhere in the list.
        assert_eq!(
            credentials[0]["scopes"],
            serde_json::json!(["append", "pull"])
        );
        assert_eq!(credentials[0]["label"], "phone");
        assert!(!listed.to_string().contains(&token));
    }

    #[test]
    fn append_assigns_contiguous_sequences_and_paginates() {
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["append", "pull"]), "phone");
        let first = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&append_request(&[
                "m-0000000000000001",
                "m-0000000000000002",
            ])),
            Some(&bearer(&token)),
        );
        assert_eq!(first["acks"][0]["seq"], 1);
        assert_eq!(first["acks"][1]["seq"], 2);
        // Idempotent retry: same id returns the original seq, no new row.
        let retry = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&append_request(&[
                "m-0000000000000001",
                "m-0000000000000002",
            ])),
            Some(&bearer(&token)),
        );
        assert_eq!(retry["acks"][0]["duplicate"], true);
        assert_eq!(retry["acks"][0]["seq"], 1);
        // Page 1: limit 1, cursor at the head.
        let page = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/pull"),
            Some(&pull_request(0, Some(1))),
            Some(&bearer(&token)),
        );
        assert_eq!(page["entries"].as_array().unwrap().len(), 1);
        assert_eq!(page["entries"][0]["seq"], 1);
        assert_eq!(page["nextCursor"], 1);
        assert_eq!(page["hasMore"], true);
        // Page 2: from the last delivered seq — no gap, and hasMore false.
        let tail = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/pull"),
            Some(&pull_request(1, Some(1))),
            Some(&bearer(&token)),
        );
        assert_eq!(tail["entries"][0]["seq"], 2);
        assert_eq!(tail["nextCursor"], 2);
        assert_eq!(tail["hasMore"], false);
        // Empty page at the head echoes the input cursor, never skips it.
        let empty = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/pull"),
            Some(&pull_request(2, Some(16))),
            Some(&bearer(&token)),
        );
        assert_eq!(empty["entries"].as_array().unwrap().len(), 0);
        assert_eq!(empty["nextCursor"], 2);
        assert_eq!(empty["hasMore"], false);
    }

    // ------------------------------------------------------ version mapping

    #[test]
    fn a_wrong_protocol_version_is_version_unsupported() {
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let body = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&versioned_request(2, "r-000000000001")),
            Some(&bearer(&token)),
        );
        assert_eq!(body["error"]["code"], "version_unsupported");
        assert_eq!(body["protocolVersion"], 1);
    }

    #[test]
    fn an_envelope_claiming_another_version_is_version_unsupported() {
        // The outer request is v1; one envelope inside it says v9. That is a
        // client mixing versions and the batch is refused as a whole.
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let mut offending = envelope("m-0000000000000003", "AAAA");
        offending["protocolVersion"] = serde_json::json!(9);
        let request = serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": "r-000000000002",
            "envelopes": [offending],
        }))
        .unwrap();
        let body = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&request),
            Some(&bearer(&token)),
        );
        assert_eq!(body["error"]["code"], "version_unsupported");
    }

    // ------------------------------------------------------- error mapping

    #[test]
    fn an_unparseable_body_is_a_frozen_error_not_a_framework_400() {
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some("{not json"),
            Some(&bearer(&token)),
        );
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"]["code"], "bad_request");
        // `requestId` is null: the request never parsed enough to carry one.
        assert_eq!(reply.body["requestId"], serde_json::Value::Null);
    }

    #[test]
    fn a_missing_admin_token_is_401() {
        let relay = start();
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/channels",
            Some(&json_request(1, "c-000000000002")),
            None,
        );
        assert_eq!(reply.status, 401);
        assert_eq!(reply.body["error"]["code"], "unauthorized");
    }

    #[test]
    fn a_wrong_admin_token_is_401() {
        let relay = start();
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/channels",
            Some(&json_request(1, "c-000000000003")),
            Some("Authorization: Bearer not-the-admin-credential"),
        );
        assert_eq!(reply.status, 401);
        assert_eq!(reply.body["error"]["code"], "unauthorized");
    }

    #[test]
    fn a_channel_token_cannot_administer_channels() {
        // A valid channel credential is not an admin credential: it fails the
        // admin comparison rather than silently passing it.
        let relay = start();
        let (_channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/channels",
            Some(&json_request(1, "c-000000000004")),
            Some(&bearer(&token)),
        );
        assert_eq!(reply.status, 401);
    }

    #[test]
    fn an_unknown_channel_is_404_channel_not_found() {
        // The admin routes address the channel directly, which is where
        // channel_not_found surfaces.
        let relay = start();
        let reply = call_with_status(
            &relay.address,
            "GET",
            "/v1/channels/ch_does-not-exist/credentials",
            None,
            Some(&admin_authorization(&relay.admin)),
        );
        assert_eq!(reply.status, 404);
        assert_eq!(reply.body["error"]["code"], "channel_not_found");
    }

    #[test]
    fn a_missing_credential_is_401() {
        let relay = start();
        let (channel, _credential_id, _token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&append_request(&["m-0000000000000005"])),
            Some("Authorization: Bearer no-such-token"),
        );
        assert_eq!(reply.status, 401);
        assert_eq!(reply.body["error"]["code"], "unauthorized");
    }

    #[test]
    fn a_pull_only_credential_cannot_append() {
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["pull"]), "phone");
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&append_request(&["m-0000000000000006"])),
            Some(&bearer(&token)),
        );
        assert_eq!(reply.status, 403);
        assert_eq!(reply.body["error"]["code"], "forbidden");
    }

    #[test]
    fn a_cross_channel_credential_is_403_not_404() {
        let relay = start();
        let (_channel_one, _id, token_one) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let (channel_two, _id, _token) = provision(&relay, serde_json::json!(["append"]), "laptop");
        // A valid credential aimed at another channel is forbidden, never a
        // 404: the contract keeps channel existence out of the answer.
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel_two}/append"),
            Some(&append_request(&["m-0000000000000007"])),
            Some(&bearer(&token_one)),
        );
        assert_eq!(reply.status, 403);
        assert_eq!(reply.body["error"]["code"], "forbidden");
    }

    #[test]
    fn an_invalid_cursor_is_400_cursor_invalid() {
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["pull"]), "phone");
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/pull"),
            Some(&pull_request(99999, Some(16))),
            Some(&bearer(&token)),
        );
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"]["code"], "cursor_invalid");
    }

    #[test]
    fn a_zero_pull_limit_is_400_page_too_large() {
        // A zero-length page is refused: its cursor could never advance and
        // the client would loop. The frozen code for an out-of-range limit
        // is `page_too_large`.
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["pull"]), "phone");
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/pull"),
            Some(&pull_request(0, Some(0))),
            Some(&bearer(&token)),
        );
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"]["code"], "page_too_large");
    }

    #[test]
    fn an_overlong_request_id_is_400_bad_request() {
        // requestId is 1..=64 chars. Over the bound it is a bad request.
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let request = serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": "r".repeat(65),
            "envelopes": [],
        }))
        .unwrap();
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&request),
            Some(&bearer(&token)),
        );
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"]["code"], "bad_request");
    }

    #[test]
    fn a_conflicting_retry_is_409_idempotency_conflict() {
        let relay = start();
        let (channel, _credential_id, token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        // First append of an id.
        call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&append_request(&["m-0000000000000008"])),
            Some(&bearer(&token)),
        );
        // Same id, different ciphertext: the client reused an id.
        let request = serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": "r-000000000006",
            "envelopes": [envelope("m-0000000000000008", "BBBB")],
        }))
        .unwrap();
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&request),
            Some(&bearer(&token)),
        );
        assert_eq!(reply.status, 409);
        assert_eq!(reply.body["error"]["code"], "idempotency_conflict");
    }

    #[test]
    fn an_empty_scope_set_is_400_bad_request() {
        let relay = start();
        let (channel, _credential_id, _token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let request = serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": "i-000000000002",
            "scopes": [],
        }))
        .unwrap();
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/credentials"),
            Some(&request),
            Some(&admin_authorization(&relay.admin)),
        );
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"]["code"], "bad_request");
    }

    #[test]
    fn an_unknown_scope_is_400_bad_request() {
        let relay = start();
        let (channel, _credential_id, _token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        let request = serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": "i-000000000003",
            "scopes": ["admin"],
        }))
        .unwrap();
        let reply = call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/credentials"),
            Some(&request),
            Some(&admin_authorization(&relay.admin)),
        );
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"]["code"], "bad_request");
    }

    // ------------------------------------------------------- pairing rooms

    fn room_request(protocol_version: u16, request_id: &str) -> String {
        serde_json::to_string(&serde_json::json!({
            "protocolVersion": protocol_version,
            "requestId": request_id,
        }))
        .unwrap()
    }

    #[test]
    fn admin_creates_a_pairing_room_with_a_128_bit_capability() {
        let relay = start();
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&room_request(1, "rm-000000000001")),
            None,
        );
        assert_eq!(reply.status, 201, "create is unauthenticated and succeeds");
        assert_eq!(reply.body["protocolVersion"], 1);
        assert_eq!(reply.body["requestId"], "rm-000000000001");
        let room_id = reply.body["roomId"].as_str().unwrap();
        assert!(
            room_id.starts_with("rm_"),
            "room id is server-assigned: {room_id}"
        );
        let capability = reply.body["capability"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(capability)
            .expect("capability is canonical base64url");
        assert_eq!(
            decoded.len(),
            16,
            "capability is 128 bits, got {}",
            decoded.len()
        );
        let expires_at = reply.body["expiresAt"].as_str().unwrap();
        assert!(
            expires_at.ends_with('Z') && expires_at.len() == 20,
            "expiresAt is the frozen RFC 3339 shape: {expires_at}"
        );
    }

    #[test]
    fn two_rooms_never_share_a_capability_or_an_id() {
        let relay = start();
        let mut capabilities = std::collections::HashSet::new();
        let mut room_ids = std::collections::HashSet::new();
        for offset in 0..4 {
            let reply = call_with_status(
                &relay.address,
                "POST",
                "/v1/pairing/rooms",
                Some(&room_request(1, &format!("rm-00000000001{offset}"))),
                None,
            );
            assert_eq!(reply.status, 201);
            assert!(capabilities.insert(reply.body["capability"].as_str().unwrap().to_owned()));
            assert!(room_ids.insert(reply.body["roomId"].as_str().unwrap().to_owned()));
        }
    }

    #[test]
    fn a_room_request_carrying_a_short_code_is_rejected() {
        // The relay must never receive the code: `deny_unknown_fields`
        // turns a body that tries to hand one over into a bad_request.
        let relay = start();
        let request = serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": "rm-000000000020",
            "code": "ABCD2345",
        }))
        .unwrap();
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&request),
            None,
        );
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"]["code"], "bad_request");
        assert_eq!(reply.body["requestId"], "rm-000000000020");
    }

    #[test]
    fn an_unsupported_room_protocol_version_is_version_unsupported() {
        let relay = start();
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&room_request(2, "rm-000000000021")),
            None,
        );
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"]["code"], "version_unsupported");
    }

    #[test]
    fn room_creation_is_rate_limited_per_source_ip() {
        // 16 creates per minute per IP (relay-protocol.md §9). The whole
        // test suite arrives from 127.0.0.1, so this test owns a fresh
        // relay and spends the window itself.
        let relay = start();
        for offset in 0..16 {
            let reply = call_with_status(
                &relay.address,
                "POST",
                "/v1/pairing/rooms",
                Some(&room_request(1, &format!("rm-00000000003{offset:02}"))),
                None,
            );
            assert_eq!(
                reply.status,
                201,
                "create #{} is inside the window",
                offset + 1
            );
        }
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&room_request(1, "rm-000000000040")),
            None,
        );
        assert_eq!(reply.status, 429, "the 17th create in a minute is limited");
        assert_eq!(reply.body["error"]["code"], "rate_limited");
        assert_eq!(reply.body["error"]["retryable"], true);
        assert_eq!(reply.body["requestId"], "rm-000000000040");
        // The limited create minted nothing: the refused request leaves no
        // room behind, and the limiter is a gate rather than a data path.
        assert!(reply.body.get("capability").is_none());
    }

    #[test]
    fn a_room_creation_rate_limit_does_not_touch_channel_routes() {
        // Burning the room window must not lock out control-plane traffic:
        // the limit is scoped to the one open route.
        let relay = start();
        for offset in 0..17 {
            let _ = call_with_status(
                &relay.address,
                "POST",
                "/v1/pairing/rooms",
                Some(&room_request(1, &format!("rm-00000000005{offset:02}"))),
                None,
            );
        }
        let (channel, _credential_id, _token) =
            provision(&relay, serde_json::json!(["append"]), "phone");
        assert!(channel.starts_with("ch_"), "channel management still works");
    }

    // ------------------------------------------- pairing rooms over WebSocket

    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    type ClientSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// A real WebSocket client dialing the relay: same engine the server
    /// uses, over a real TCP socket. The capability rides only in the
    /// Authorization header, never the URL (relay-protocol.md §7).
    async fn ws_connect(
        address: &str,
        path: &str,
        token: Option<&str>,
        origin: Option<&str>,
    ) -> Result<ClientSocket, tokio_tungstenite::tungstenite::Error> {
        let mut request = format!("ws://{address}{path}").into_client_request()?;
        if let Some(token) = token {
            request.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
        }
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert("Origin", HeaderValue::from_str(origin).unwrap());
        }
        let (socket, _response) = connect_async(request).await?;
        Ok(socket)
    }

    async fn ws_join(
        address: &str,
        room: &str,
        capability: Option<&str>,
        origin: Option<&str>,
    ) -> Result<ClientSocket, tokio_tungstenite::tungstenite::Error> {
        ws_connect(address, &format!("/v1/pairing/{room}"), capability, origin).await
    }

    async fn ws_join_ok(address: &str, room: &str, capability: &str) -> ClientSocket {
        ws_join(address, room, Some(capability), None)
            .await
            .expect("a valid capability joins the room")
    }

    async fn ws_events_ok(address: &str, channel: &str, token: &str) -> ClientSocket {
        ws_connect(
            address,
            &format!("/v1/channels/{channel}/events"),
            Some(token),
            None,
        )
        .await
        .expect("a pull credential subscribes")
    }

    /// Issue one more credential on an existing channel; returns
    /// (credentialId, token).
    fn issue_on(
        relay: &Relay,
        channel: &str,
        scopes: serde_json::Value,
        request_id: &str,
        label: &str,
    ) -> (String, String) {
        let request = serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "requestId": request_id,
            "scopes": scopes,
            "label": label,
        }))
        .unwrap();
        let issued = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/credentials"),
            Some(&request),
            Some(&admin_authorization(&relay.admin)),
        );
        (
            issued["credentialId"].as_str().unwrap().to_owned(),
            issued["token"].as_str().unwrap().to_owned(),
        )
    }

    fn append_call(relay: &Relay, channel: &str, message_ids: &[&str], token: &str) -> Reply {
        call_with_status(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/append"),
            Some(&append_request(message_ids)),
            Some(&bearer(token)),
        )
    }

    /// Create a pairing room over the real HTTP route.
    fn create_room(relay: &Relay) -> (String, String) {
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&room_request(1, "rm-ws-0000000001")),
            None,
        );
        assert_eq!(reply.status, 201);
        (
            reply.body["roomId"].as_str().unwrap().to_owned(),
            reply.body["capability"].as_str().unwrap().to_owned(),
        )
    }

    fn ws_frame(data: &str) -> String {
        serde_json::to_string(&serde_json::json!({
            "protocolVersion": 1,
            "type": "pairing.frame",
            "data": data,
        }))
        .unwrap()
    }

    async fn next_json(socket: &mut ClientSocket) -> serde_json::Value {
        match socket.next().await {
            Some(Ok(WsMessage::Text(text))) => serde_json::from_str(text.as_str()).unwrap(),
            other => panic!("expected a text message, got {other:?}"),
        }
    }

    async fn next_close(socket: &mut ClientSocket) -> u16 {
        match socket.next().await {
            Some(Ok(WsMessage::Close(Some(frame)))) => u16::from(frame.code),
            other => panic!("expected a close frame, got {other:?}"),
        }
    }

    /// Build a relay whose room registry holds a room created `age_ms`
    /// ago on the shifted clock, returning it with the relay.
    fn boot_with_aged_room(age_ms: u64) -> (Relay, String, String) {
        let rooms = std::sync::Arc::new(PairingRooms::new());
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let created = rooms
            .create(std::net::IpAddr::from([127, 0, 0, 9]), now_ms - age_ms)
            .unwrap();
        let relay = boot_with(fresh_db(), true, |store| AppState {
            store,
            rooms,
            sessions: std::sync::Arc::new(RoomSessions::default()),
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            subscriptions: std::sync::Arc::new(crate::ws::ChannelSubscriptions::default()),
        });
        (relay, created.room_id, created.capability)
    }

    #[tokio::test]
    async fn two_participants_are_routed_and_frames_flow_both_ways() {
        let relay = start();
        let (room, capability) = create_room(&relay);
        let mut first = ws_join_ok(&relay.address, &room, &capability).await;
        let mut second = ws_join_ok(&relay.address, &room, &capability).await;

        let greeting = next_json(&mut first).await;
        assert_eq!(greeting["type"], "room.joined");
        assert_eq!(greeting["roomId"], room);
        assert_eq!(greeting["peerJoined"], false, "the first joiner is alone");

        let greeting = next_json(&mut second).await;
        assert_eq!(
            greeting["peerJoined"], true,
            "the second joiner hears the peer is already there"
        );

        first
            .send(WsMessage::Text(
                ws_frame("cGstZnJhbWUtZnJvbS1maXJzdA").into(),
            ))
            .await
            .unwrap();
        let forwarded = next_json(&mut second).await;
        assert_eq!(forwarded["type"], "pairing.frame");
        assert_eq!(forwarded["data"], "cGstZnJhbWUtZnJvbS1maXJzdA");

        second
            .send(WsMessage::Text(
                ws_frame("cGstZnJhbWUtZnJvbS1zZWNvbmQ").into(),
            ))
            .await
            .unwrap();
        let forwarded = next_json(&mut first).await;
        assert_eq!(forwarded["type"], "pairing.frame");
        assert_eq!(forwarded["data"], "cGstZnJhbWUtZnJvbS1zZWNvbmQ");
    }

    #[tokio::test]
    async fn a_third_participant_gets_an_error_then_4409() {
        let relay = start();
        let (room, capability) = create_room(&relay);
        let _first = ws_join_ok(&relay.address, &room, &capability).await;
        let _second = ws_join_ok(&relay.address, &room, &capability).await;
        let mut third = ws_join_ok(&relay.address, &room, &capability).await;

        let error = next_json(&mut third).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["code"], "room_full");
        assert_eq!(next_close(&mut third).await, 4409);
    }

    #[tokio::test]
    async fn a_wrong_capability_gets_an_error_then_4401() {
        let relay = start();
        let (room, _capability) = create_room(&relay);
        let mut socket = ws_join_ok(&relay.address, &room, "wrong-capability").await;
        let error = next_json(&mut socket).await;
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(next_close(&mut socket).await, 4401);
    }

    #[tokio::test]
    async fn an_unknown_room_join_gets_4404() {
        let relay = start();
        let mut socket = ws_join_ok(&relay.address, "rm_does_not_exist", "any").await;
        let error = next_json(&mut socket).await;
        assert_eq!(error["code"], "room_not_found");
        assert_eq!(next_close(&mut socket).await, 4404);
    }

    #[tokio::test]
    async fn a_capability_from_another_room_is_4401_not_4404() {
        let relay = start();
        let (_room_a, capability_a) = create_room(&relay);
        let (room_b, _capability_b) = create_room(&relay);
        let mut socket = ws_join_ok(&relay.address, &room_b, &capability_a).await;
        // Cross-room is an authentication failure: the capability is real
        // but not for this room, and 4404 would leak room existence to a
        // capability holder.
        let error = next_json(&mut socket).await;
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(next_close(&mut socket).await, 4401);
    }

    #[tokio::test]
    async fn a_disconnected_peer_closes_the_roommate_with_1001() {
        let relay = start();
        let (room, capability) = create_room(&relay);
        let mut first = ws_join_ok(&relay.address, &room, &capability).await;
        let mut second = ws_join_ok(&relay.address, &room, &capability).await;
        let _ = next_json(&mut first).await;
        let _ = next_json(&mut second).await;

        first.close(None).await.unwrap();
        // The server notices the dropped peer and closes the remaining
        // socket with 1001: the handshake is dead, re-pair in a new room.
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(5), next_close(&mut second)).await;
        assert_eq!(closed.expect("the roommate is closed"), 1001);
    }

    #[tokio::test]
    async fn joining_an_expired_room_gets_4410() {
        let (relay, room, capability) = boot_with_aged_room(121_000);
        let mut socket = ws_join_ok(&relay.address, &room, &capability).await;
        let error = next_json(&mut socket).await;
        assert_eq!(error["code"], "room_expired");
        assert_eq!(next_close(&mut socket).await, 4410);
    }

    #[tokio::test]
    async fn a_room_expires_mid_session_error_then_4410() {
        // Created 118.5 s "ago": about 1.5 s of life left at boot.
        let (relay, room, capability) = boot_with_aged_room(118_500);
        let mut socket = ws_join_ok(&relay.address, &room, &capability).await;
        let greeting = next_json(&mut socket).await;
        assert_eq!(greeting["type"], "room.joined");

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let error = next_json(&mut socket).await;
            assert_eq!(error["type"], "error");
            assert_eq!(error["code"], "room_expired");
            next_close(&mut socket).await
        })
        .await
        .expect("the deadline task closes the session");
        assert_eq!(outcome, 4410);
    }

    #[tokio::test]
    async fn a_disallowed_browser_origin_is_rejected_at_the_upgrade() {
        let rooms = std::sync::Arc::new(PairingRooms::new());
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let created = rooms
            .create(std::net::IpAddr::from([127, 0, 0, 9]), now_ms)
            .unwrap();
        let relay = boot_with(fresh_db(), true, |store| AppState {
            store,
            rooms,
            sessions: std::sync::Arc::new(RoomSessions::default()),
            allowed_origins: vec!["https://ok.example".to_owned()],
            trusted_proxies: Vec::new(),
            subscriptions: std::sync::Arc::new(crate::ws::ChannelSubscriptions::default()),
        });

        // An Origin the deployer did not allow never gets a socket.
        let rejected = ws_join(
            &relay.address,
            &created.room_id,
            Some(&created.capability),
            Some("https://evil.example"),
        )
        .await;
        match rejected {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), 403);
            }
            other => panic!("expected an HTTP 403 rejection, got {other:?}"),
        }

        // The allowed origin joins normally, and no-Origin clients (every
        // other test in this module) were never affected.
        let mut allowed = ws_join(
            &relay.address,
            &created.room_id,
            Some(&created.capability),
            Some("https://ok.example"),
        )
        .await
        .expect("the allowed origin joins");
        let greeting = next_json(&mut allowed).await;
        assert_eq!(greeting["type"], "room.joined");
    }

    #[tokio::test]
    async fn a_message_with_an_unknown_type_closes_with_1008() {
        let relay = start();
        let (room, capability) = create_room(&relay);
        let mut socket = ws_join_ok(&relay.address, &room, &capability).await;
        let _ = next_json(&mut socket).await;
        socket
            .send(WsMessage::Text(
                r#"{"protocolVersion":1,"type":"chat","data":"hello"}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(next_close(&mut socket).await, 1008);
    }

    #[tokio::test]
    async fn a_frame_with_an_unknown_field_closes_with_1008() {
        let relay = start();
        let (room, capability) = create_room(&relay);
        let mut socket = ws_join_ok(&relay.address, &room, &capability).await;
        let _ = next_json(&mut socket).await;
        socket
            .send(WsMessage::Text(
                r#"{"protocolVersion":1,"type":"pairing.frame","data":"QUJD","extra":1}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(next_close(&mut socket).await, 1008);
    }

    #[tokio::test]
    async fn an_over_capacity_frame_closes_with_1008() {
        let relay = start();
        let (room, capability) = create_room(&relay);
        let mut socket = ws_join_ok(&relay.address, &room, &capability).await;
        let _ = next_json(&mut socket).await;
        // Canonical base64url for 16 MiB would be 22_369_622 chars; one
        // char more decodes past the cap.
        let over = "A".repeat(22_369_623);
        socket
            .send(WsMessage::Text(ws_frame(&over).into()))
            .await
            .unwrap();
        assert_eq!(next_close(&mut socket).await, 1008);
    }

    #[test]
    fn a_forwarded_header_without_a_trusted_proxy_is_ignored() {
        // Default config trusts nobody: 17 creates each claiming a
        // different client must still exhaust, because the budget is keyed
        // on the real peer and a caller cannot mint budgets with headers.
        let relay = start();
        for offset in 0..16 {
            let reply = call_with_status(
                &relay.address,
                "POST",
                "/v1/pairing/rooms",
                Some(&room_request(1, &format!("rm-00000000006{offset:02}"))),
                Some(&format!("X-Forwarded-For: 198.51.100.{offset}")),
            );
            assert_eq!(
                reply.status,
                201,
                "create #{} spoofs a fresh budget",
                offset + 1
            );
        }
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&room_request(1, "rm-000000000070")),
            Some("X-Forwarded-For: 198.51.100.99"),
        );
        assert_eq!(reply.status, 429, "spoofed headers never escape the budget");
    }

    #[test]
    fn a_trusted_proxy_moves_the_rate_limit_to_the_forwarded_client() {
        let trusted = crate::proxy::TrustedProxy::parse("127.0.0.1").unwrap();
        let relay = boot_with(fresh_db(), true, |store| AppState {
            store,
            rooms: std::sync::Arc::new(PairingRooms::new()),
            sessions: std::sync::Arc::new(RoomSessions::default()),
            allowed_origins: Vec::new(),
            trusted_proxies: vec![trusted],
            subscriptions: std::sync::Arc::new(crate::ws::ChannelSubscriptions::default()),
        });
        // One client behind the proxy burns its own budget...
        for offset in 0..16 {
            let reply = call_with_status(
                &relay.address,
                "POST",
                "/v1/pairing/rooms",
                Some(&room_request(1, &format!("rm-00000000008{offset:02}"))),
                Some("X-Forwarded-For: 198.51.100.7"),
            );
            assert_eq!(
                reply.status,
                201,
                "create #{} is client #1's budget",
                offset + 1
            );
        }
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&room_request(1, "rm-000000000090")),
            Some("X-Forwarded-For: 198.51.100.7"),
        );
        assert_eq!(
            reply.status, 429,
            "the forwarded client is limited, not the proxy"
        );
        // ...a different client keeps its own budget...
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&room_request(1, "rm-000000000091")),
            Some("X-Forwarded-For: 203.0.113.9"),
        );
        assert_eq!(reply.status, 201, "budgets are per client, not per proxy");
        // ...and a direct peer (no header) is keyed on the proxy address,
        // never on anything a caller could have forged.
        let reply = call_with_status(
            &relay.address,
            "POST",
            "/v1/pairing/rooms",
            Some(&room_request(1, "rm-000000000092")),
            None,
        );
        assert_eq!(
            reply.status, 201,
            "no header falls back to the peer address"
        );
    }

    // --------------------------------------- channel update notifications

    #[tokio::test]
    async fn the_events_stream_greets_and_pushes_committed_batches() {
        let relay = start();
        let (channel, _id, pull_token) = provision(&relay, serde_json::json!(["pull"]), "listener");
        let (_id, append_token) = issue_on(
            &relay,
            &channel,
            serde_json::json!(["append"]),
            "i-000000000002",
            "writer",
        );
        let mut socket = ws_events_ok(&relay.address, &channel, &pull_token).await;

        let greeting = next_json(&mut socket).await;
        assert_eq!(greeting["type"], "events.subscribed");
        assert_eq!(greeting["protocolVersion"], 1);
        assert_eq!(greeting["channelId"], channel);

        let reply = append_call(
            &relay,
            &channel,
            &["m-0000000000000001", "m-0000000000000002"],
            &append_token,
        );
        assert_eq!(reply.status, 200);
        let hint = next_json(&mut socket).await;
        assert_eq!(hint["type"], "channel.appended");
        assert_eq!(hint["channelId"], channel);
        assert_eq!(
            hint["seq"], 2,
            "one hint per committed batch, carrying the batch's last seq"
        );

        let reply = append_call(&relay, &channel, &["m-0000000000000003"], &append_token);
        assert_eq!(reply.status, 200);
        let hint = next_json(&mut socket).await;
        assert_eq!(hint["seq"], 3);
    }

    #[tokio::test]
    async fn a_credential_without_pull_scope_is_refused_with_4403() {
        let relay = start();
        let (channel, _id, append_token) =
            provision(&relay, serde_json::json!(["append"]), "writer");
        let mut socket = ws_events_ok(&relay.address, &channel, &append_token).await;
        let error = next_json(&mut socket).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["code"], "forbidden");
        assert_eq!(next_close(&mut socket).await, 4403);
    }

    #[tokio::test]
    async fn a_missing_or_unknown_credential_is_refused_with_4401() {
        let relay = start();
        let (channel, _id, _pull_token) = provision(&relay, serde_json::json!(["pull"]), "pull");
        // No Authorization header at all.
        let mut socket = ws_connect(
            &relay.address,
            &format!("/v1/channels/{channel}/events"),
            None,
            None,
        )
        .await
        .expect("the refusal still completes the upgrade");
        let error = next_json(&mut socket).await;
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(next_close(&mut socket).await, 4401);
        // A token that grants nothing.
        let mut socket = ws_events_ok(&relay.address, &channel, "not-a-token").await;
        let error = next_json(&mut socket).await;
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(next_close(&mut socket).await, 4401);
    }

    #[tokio::test]
    async fn a_nonexistent_channel_is_not_distinguishable_from_a_foreign_one() {
        // No credential: 4401, the same answer any unknown token gets —
        // the channel's existence is never leaked to a probe.
        let relay = start();
        let mut socket = ws_connect(
            &relay.address,
            "/v1/channels/ch_does_not_exist/events",
            None,
            None,
        )
        .await
        .expect("the refusal still completes the upgrade");
        let error = next_json(&mut socket).await;
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(next_close(&mut socket).await, 4401);
        // A real credential for another channel: 4403, again without
        // saying whether the named channel exists.
        let (_other_channel, _id, token) =
            provision(&relay, serde_json::json!(["pull"]), "elsewhere");
        let mut socket = ws_connect(
            &relay.address,
            "/v1/channels/ch_does_not_exist/events",
            Some(&token),
            None,
        )
        .await
        .expect("the refusal still completes the upgrade");
        let error = next_json(&mut socket).await;
        assert_eq!(error["code"], "forbidden");
        assert_eq!(next_close(&mut socket).await, 4403);
    }

    #[tokio::test]
    async fn a_revoked_credential_is_disconnected_on_the_next_push() {
        let relay = start();
        let (channel, revoked_id, revoked_token) =
            provision(&relay, serde_json::json!(["pull"]), "revoked");
        let (kept_id, kept_token) = issue_on(
            &relay,
            &channel,
            serde_json::json!(["pull"]),
            "i-000000000002",
            "kept",
        );
        let (_id, append_token) = issue_on(
            &relay,
            &channel,
            serde_json::json!(["append"]),
            "i-000000000003",
            "writer",
        );
        let _ = kept_id;
        let mut revoked = ws_events_ok(&relay.address, &channel, &revoked_token).await;
        let mut kept = ws_events_ok(&relay.address, &channel, &kept_token).await;
        let _ = next_json(&mut revoked).await;
        let _ = next_json(&mut kept).await;

        let reply = call_with_status(
            &relay.address,
            "DELETE",
            &format!("/v1/channels/{channel}/credentials/{revoked_id}"),
            None,
            Some(&admin_authorization(&relay.admin)),
        );
        assert_eq!(reply.status, 200);
        let reply = append_call(&relay, &channel, &["m-0000000000000001"], &append_token);
        assert_eq!(reply.status, 200);

        // The revoked stream dies on the push attempt that follows the
        // commit — one error message, then the 4401 close.
        let error = next_json(&mut revoked).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(next_close(&mut revoked).await, 4401);
        // The other device's subscription is untouched by the revocation.
        let hint = next_json(&mut kept).await;
        assert_eq!(hint["type"], "channel.appended");
        assert_eq!(hint["seq"], 1);
    }

    #[tokio::test]
    async fn a_lost_hint_loses_nothing_because_pull_recovers() {
        let relay = start();
        let (channel, _id, token) =
            provision(&relay, serde_json::json!(["pull", "append"]), "both");
        // Three commits reach the log while nobody is subscribed: no
        // listener exists, so no hint is ever delivered anywhere.
        for ids in [
            vec!["m-0000000000000001"],
            vec!["m-0000000000000002"],
            vec!["m-0000000000000003"],
        ] {
            let reply = append_call(&relay, &channel, &ids, &token);
            assert_eq!(reply.status, 200);
        }
        // The recovery path is pull from a cursor, and it has everything.
        let body = call(
            &relay.address,
            "POST",
            &format!("/v1/channels/{channel}/pull"),
            Some(&pull_request(0, None)),
            Some(&bearer(&token)),
        );
        assert_eq!(body["entries"].as_array().unwrap().len(), 3);
        assert_eq!(body["hasMore"], false);
        // A listener joining now is told nothing about the past: the
        // subscription carries no state, the greeting is all it gets.
        let mut socket = ws_events_ok(&relay.address, &channel, &token).await;
        let greeting = next_json(&mut socket).await;
        assert_eq!(greeting["type"], "events.subscribed");
    }

    #[tokio::test]
    async fn an_events_origin_gate_blocks_disallowed_browsers() {
        let relay = boot_with(fresh_db(), true, |store| AppState {
            store,
            rooms: std::sync::Arc::new(PairingRooms::new()),
            sessions: std::sync::Arc::new(RoomSessions::default()),
            allowed_origins: vec!["https://ok.example".to_owned()],
            trusted_proxies: Vec::new(),
            subscriptions: std::sync::Arc::new(crate::ws::ChannelSubscriptions::default()),
        });
        let (channel, _id, token) = provision(&relay, serde_json::json!(["pull"]), "browser");

        let rejected = ws_connect(
            &relay.address,
            &format!("/v1/channels/{channel}/events"),
            Some(&token),
            Some("https://evil.example"),
        )
        .await;
        match rejected {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), 403);
            }
            other => panic!("expected an HTTP 403 rejection, got {other:?}"),
        }

        let mut allowed = ws_connect(
            &relay.address,
            &format!("/v1/channels/{channel}/events"),
            Some(&token),
            Some("https://ok.example"),
        )
        .await
        .expect("the allowed origin subscribes");
        let greeting = next_json(&mut allowed).await;
        assert_eq!(greeting["type"], "events.subscribed");
    }

    #[tokio::test]
    async fn a_client_message_on_the_events_stream_closes_with_1008() {
        let relay = start();
        let (channel, _id, token) = provision(&relay, serde_json::json!(["pull"]), "listener");
        let mut socket = ws_events_ok(&relay.address, &channel, &token).await;
        let _ = next_json(&mut socket).await;
        // A listener has no client vocabulary: anything sent is a shape
        // violation, exactly like on the pairing surface.
        socket
            .send(WsMessage::Text(r#"{"type":"chat"}"#.into()))
            .await
            .unwrap();
        assert_eq!(next_close(&mut socket).await, 1008);
    }
}
