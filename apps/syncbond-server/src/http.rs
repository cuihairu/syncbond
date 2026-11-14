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

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use syncbond_relay_protocol::dto::{
    AppendAck, AppendRequest, ChannelCreated, CredentialIssued, CredentialRevoked,
    IssueCredentialRequest, PullRequest, PullResponse,
};
use syncbond_relay_protocol::error::{ErrorBody, RelayError, RelayErrorCode};
use syncbond_relay_protocol::{
    check_batch, check_envelope, check_request_id, check_version, effective_pull_limits,
    RELAY_PROTOCOL_VERSION,
};

use crate::sqlite::SqliteRelayStore;
use crate::storage::{IssuedCredential, RelayStorage, StorageError};

/// Shared state for every route. The store is `Send + Sync` by contract,
/// which is exactly why `SqliteRelayStore` guards its connection with a
/// mutex (see its module docs).
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<SqliteRelayStore>,
}

/// Build the router. Kept separate from `listen` so tests can drive it
/// through a real socket or mount it elsewhere.
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
struct Failure {
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
fn bearer(headers: &HeaderMap) -> Option<String> {
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
        Ok(outcome) => (
            StatusCode::OK,
            Json(AppendAck {
                protocol_version: RELAY_PROTOCOL_VERSION,
                request_id: request.request_id,
                channel_id,
                acks: outcome.acks,
            }),
        )
            .into_response(),
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
        /// Must outlive the serve task: dropping a runtime aborts the tasks
        /// it owns, which is how a listener goes away before its first
        /// request is answered.
        _runtime: tokio::runtime::Runtime,
    }

    impl Drop for Relay {
        fn drop(&mut self) {
            self._task.abort();
            std::fs::remove_file(&self._db).ok();
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

    /// Boot a relay: one store, one listener on an ephemeral port. `ready`
    /// lifts the readiness gate the way the binary's serve loop does.
    fn boot(db: std::path::PathBuf, ready: bool) -> Relay {
        let store = std::sync::Arc::new(SqliteRelayStore::open(&db).unwrap());
        if ready {
            store.mark_ready();
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (address, task) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let task = tokio::task::spawn(async move {
                let _ = axum::serve(listener, router(AppState { store })).await;
            });
            (address, task)
        });
        let admin = std::fs::read_to_string(admin_credential_path(&db)).unwrap();
        Relay {
            address,
            admin: admin.trim().to_owned(),
            _task: task,
            _db: db,
            _runtime: runtime,
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
}
