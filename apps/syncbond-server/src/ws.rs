//! The v1 WebSocket surface: pairing-room frame forwarding (todo.md
//! DSR-21, relay-protocol.md §7) and channel update notifications
//! (todo.md DSR-22, relay-protocol.md §8).
//!
//! The relay is a courier, nothing more: it admits a bearer of the room
//! capability (the registry in [`crate::rooms`] owns admission), tells each
//! joiner whether their peer is already waiting, and then copies
//! `pairing.frame` messages from one participant to the other without
//! looking inside. Every refusal path upgrades first and then closes with
//! the frozen 44xx code after one `error` message — a browser cannot see
//! the HTTP status of a failed upgrade, so the close code *is* the error
//! channel a client can actually read.
//!
//! Lifecycles, and who owns them:
//!
//! - **Peer disconnect** closes the remaining socket with `1001`: the
//!   pairing handshake is dead when either side drops, and per the room
//!   registry's no-seat-freeing rule the honest peer re-pairs in a fresh
//!   room rather than waiting out the TTL alone.
//! - **Room expiry** closes both sockets with `4410` after one
//!   `room_expired` error, driven by a per-join deadline task — the
//!   registry sweeps lazily, so the socket side keeps its own clock.
//! - **Shape violations** (a non-`pairing.frame` type, unknown fields,
//!   non-canonical or over-cap frames) close with `1008`.
//! - **Heartbeat** (todo.md DSR-23, frozen §9): the server pings every
//!   30 s and closes a socket idle beyond 90 s with `1008`. Client
//!   pings are answered by the transport; any received frame counts as
//!   life.
//! - **Shutdown** (todo.md DSR-24): when the process stop signal fires,
//!   every session ends declared — one `1001` (going away) close, after
//!   whatever is already queued is flushed, so a mid-pairing handshake
//!   ends as a clean goodbye rather than a reset. A hint subscriber
//!   loses nothing: hints are lossy by contract and the client pulls
//!   from its cursor on reconnect.
//!
//! Browser clients must present an `Origin` in the configured
//! `allowedOrigins` (403 at the upgrade, before any room state is
//! touched); clients without an `Origin` header are unaffected.
//!
//! Resource bounds (todo.md DSR-23): every outbound queue is bounded in
//! count and bytes. On the pairing surface a peer that will not drain is
//! closed with `1013` once its queue empties — a declared failure, never
//! a silent frame drop, because pairing frames are lossless by contract.
//! Event hints are lossy by contract, so a full queue simply loses the
//! hint. A session budget (`maxWsSessions`) bounds live sockets: past
//! it, an upgrade completes and closes with `1013` after one
//! `rate_limited` error — the same bounded-failure shape as every other
//! refusal.
//!
//! The channel events surface (todo.md DSR-22, relay-protocol.md §8) is
//! lossy by design: a subscription is a hint generator, never state. The
//! append route pushes one `channel.appended` hint per committed batch
//! and each push re-checks the subscriber's pull credential — a revoked
//! credential is dropped with a 4401 close on the next push attempt,
//! exactly the contract's revocation semantics. A client that misses a
//! hint (offline, queue full, mid-subscribe) recovers by pulling from
//! its cursor, which is why nothing here buffers or retries.
//!
//! Refusal close codes on the events route mirror the HTTP mapping:
//! 4401 unauthorized (missing, unknown, or revoked credential), 4403
//! forbidden (credential lacks pull scope or belongs to another
//! channel). There is deliberately no "unknown channel" code: authorize
//! cannot distinguish a nonexistent channel from a foreign one, so
//! channel existence is never leaked to a subscription probe.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use syncbond_relay_protocol::dto::{CredentialScope, WsClientMessage, WsServerMessage};
use syncbond_relay_protocol::error::RelayErrorCode;
use syncbond_relay_protocol::limits::{
    PAIRING_FRAME_MAX_BYTES, WS_HEARTBEAT_INTERVAL_MS, WS_IDLE_TIMEOUT_MS,
};
use syncbond_relay_protocol::RELAY_PROTOCOL_VERSION;

use crate::http::{bearer, unix_now_ms, AppState};
use crate::rooms::JoinRoomError;
use crate::storage::RelayStorage as _;

/// The wire cap for one WS message: a legitimate `pairing.frame` holds at
/// most `PAIRING_FRAME_MAX_BYTES` bytes as canonical base64url plus the
/// JSON envelope, so anything above this is rejected by the socket layer
/// before user code parses it. Frames between this ceiling and the decoded
/// cap (i.e. oversized but under the socket cap) are closed with 1008 by
/// [`decode_frame`], which is the contract's close code.
const MAX_WS_MESSAGE_BYTES: usize = (PAIRING_FRAME_MAX_BYTES / 3 + 1) * 4 + 4096;

/// Heartbeat timing for every WebSocket on this server. The frozen §9
/// values are the default; tests inject smaller ones through the state —
/// the contract's numbers are never configurable, only replaceable in
/// test assemblies.
#[derive(Debug, Clone, Copy)]
pub struct Heartbeat {
    ping_every_ms: u64,
    idle_after_ms: u64,
}

impl Heartbeat {
    /// The frozen §9 timing: ping every 30 s, close past 90 s idle.
    pub fn frozen() -> Self {
        Self {
            ping_every_ms: WS_HEARTBEAT_INTERVAL_MS,
            idle_after_ms: WS_IDLE_TIMEOUT_MS,
        }
    }

    /// Test-only timing: production always takes the frozen values; the
    /// heartbeat is proven over milliseconds, not half-minutes.
    #[cfg(test)]
    pub(crate) fn for_tests(ping_every_ms: u64, idle_after_ms: u64) -> Self {
        Self {
            ping_every_ms,
            idle_after_ms,
        }
    }

    fn ping_every(&self) -> Duration {
        Duration::from_millis(self.ping_every_ms)
    }

    fn idle_after(&self) -> Duration {
        Duration::from_millis(self.idle_after_ms)
    }
}

/// Live-session accounting for the shutdown drain (todo.md DSR-24): every
/// admitted session holds one [`LiveGuard`] from *before* its upgrade
/// completes until its goodbye is flushed, and the process exit waits on
/// [`LiveSessions::drained`]. Without the counter the drain could return
/// while a session task is still mid-goodbye and the runtime drop would
/// cancel it — exactly the reset-instead-of-close the contract forbids.
/// The guard is taken in the route handler, not inside the spawned
/// session task, so there is no scheduling gap in which the counter reads
/// zero while a session is about to exist.
#[derive(Default)]
pub struct LiveSessions {
    live: Mutex<usize>,
    idle: tokio::sync::Notify,
}

/// One admitted session's hold on the drain. Dropping it — from any exit
/// path, including a panic — releases the wait.
pub struct LiveGuard {
    sessions: std::sync::Arc<LiveSessions>,
}

impl LiveSessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a hold. Call once per admitted session.
    pub fn enter(self: &std::sync::Arc<Self>) -> LiveGuard {
        *self.lock() += 1;
        LiveGuard {
            sessions: self.clone(),
        }
    }

    /// Resolve when no session holds a guard anymore.
    pub async fn drained(&self) {
        loop {
            if self.count() == 0 {
                return;
            }
            let notified = self.idle.notified();
            tokio::pin!(notified);
            // Register before re-checking, so a guard dropped between the
            // count and the await cannot fall through the gap.
            notified.as_mut().enable();
            if self.count() == 0 {
                return;
            }
            notified.await;
        }
    }

    fn count(&self) -> usize {
        *self.lock()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, usize> {
        self.live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        let mut live = self.sessions.lock();
        *live -= 1;
        if *live == 0 {
            // notify_waiters: every waiter re-checks the count, so one
            // edge wakes them all; a missed edge cannot happen because
            // `drained` re-checks after registering.
            self.sessions.idle.notify_waiters();
        }
    }
}

/// The bounded outbound path of one socket. `try_send` refuses when the
/// queued bytes would pass `limit` — the caller decides what a refusal
/// means for its surface (declared failure on pairing, lost hint on
/// events). The writer subtracts each message's weight after it goes to
/// the wire, so the counter tracks what the socket still owes.
#[derive(Clone)]
struct Outbound {
    tx: tokio::sync::mpsc::Sender<(usize, Message)>,
    queued: Arc<AtomicU64>,
    /// Set when a peer must be closed once its queue drains (the close
    /// itself cannot fit into a full queue).
    drain_close: Arc<AtomicBool>,
    /// Wakes the writer so a pending drain close fires while the queue is
    /// idle — without it the writer would sleep in `recv` with nothing
    /// left to send and the peer would never hear the failure.
    close_signal: Arc<tokio::sync::Notify>,
    limit: u64,
}

const MAX_QUEUED_MESSAGES: usize = 16;

impl Outbound {
    fn new(limit: usize) -> (Self, tokio::sync::mpsc::Receiver<(usize, Message)>) {
        let (tx, rx) = tokio::sync::mpsc::channel(MAX_QUEUED_MESSAGES);
        (
            Self {
                tx,
                queued: Arc::new(AtomicU64::new(0)),
                drain_close: Arc::new(AtomicBool::new(false)),
                close_signal: Arc::new(tokio::sync::Notify::new()),
                limit: limit.max(1) as u64,
            },
            rx,
        )
    }

    /// Enqueue without waiting. `false` means bounded refusal (over the
    /// byte budget) or a dead socket (receiver gone).
    fn try_send(&self, message: Message) -> bool {
        let weight = wire_weight(&message);
        if self.queued.load(Ordering::Relaxed) + weight as u64 > self.limit {
            return false;
        }
        if self.tx.try_send((weight, message)).is_err() {
            return false;
        }
        self.queued.fetch_add(weight as u64, Ordering::Relaxed);
        true
    }

    /// Awaited send for startup messages (the greeting): the queue cannot
    /// be full yet, so only a dead socket fails this.
    async fn send(&self, message: Message) -> bool {
        let weight = wire_weight(&message);
        if self.tx.send((weight, message)).await.is_err() {
            return false;
        }
        self.queued.fetch_add(weight as u64, Ordering::Relaxed);
        true
    }

    /// Close this socket with `1013` once everything already queued has
    /// gone out: the bounded failure for a peer that will not drain.
    fn request_drain_close(&self) {
        self.drain_close.store(true, Ordering::Relaxed);
        // notify_one (not waiters): a permit set while the writer is not
        // parked is kept for its next `notified()`, so the flag is never
        // missed between the writer's check and its wait.
        self.close_signal.notify_one();
    }

    /// Drop this sending half. Once every handle is gone — the caller
    /// must have removed any registry entry first, or the writer waits
    /// forever on that clone — the writer's queue closes, it finishes
    /// what is queued and ends the socket cleanly.
    async fn finish(self, writer: tokio::task::JoinHandle<()>) {
        drop(self);
        let _ = writer.await;
    }
}

/// Approximate wire weight of one queued message, for the byte budget.
fn wire_weight(message: &Message) -> usize {
    match message {
        Message::Text(text) => text.len() + 8,
        _ => 128,
    }
}

/// Drive the outbound half: drain the queue, fire a pending
/// bounded-failure close the moment the queue empties (even mid-session),
/// then end the socket cleanly so the peer reads close codes instead of a
/// reset.
async fn write_outbound(
    mut sender: futures_util::stream::SplitSink<WebSocket, Message>,
    mut rx: tokio::sync::mpsc::Receiver<(usize, Message)>,
    queued: Arc<AtomicU64>,
    drain_close: Arc<AtomicBool>,
    close_signal: Arc<tokio::sync::Notify>,
) {
    loop {
        // The queue is empty and a failure is pending: everything owed has
        // gone out, so declare the failure now rather than waiting for a
        // session end that a slow peer may delay indefinitely.
        if rx.is_empty() && drain_close.swap(false, Ordering::Relaxed) {
            let _ = sender
                .send(close_message(1013, "outbound budget exhausted"))
                .await;
            break;
        }
        let (weight, message) = tokio::select! {
            item = rx.recv() => match item {
                Some(item) => item,
                None => break,
            },
            _ = close_signal.notified() => continue,
        };
        if sender.send(message).await.is_err() {
            break;
        }
        queued.fetch_sub(weight as u64, Ordering::Relaxed);
    }
    if drain_close.swap(false, Ordering::Relaxed) {
        let _ = sender
            .send(close_message(1013, "outbound budget exhausted"))
            .await;
    }
    let _ = sender.close().await;
}

/// Live pairing-room sockets, keyed by room id. The registry in
/// `rooms.rs` decides who gets in; this map is only about reaching the
/// ones who already did.
#[derive(Default)]
pub struct RoomSessions {
    rooms: Mutex<HashMap<String, Vec<Participant>>>,
}

struct Participant {
    id: u64,
    out: Outbound,
}

static PARTICIPANT_IDS: AtomicU64 = AtomicU64::new(1);

impl RoomSessions {
    fn register(&self, room: &str, out: Outbound) -> u64 {
        let id = PARTICIPANT_IDS.fetch_add(1, Ordering::Relaxed);
        self.lock()
            .entry(room.to_owned())
            .or_default()
            .push(Participant { id, out });
        id
    }

    /// Hand `message` to every participant in `room` except `from`. A
    /// participant whose queue is over budget is marked for a drain
    /// close: its socket ends with `1013` once flushed. Pairing frames
    /// are lossless by contract — a full queue may fail the socket, but
    /// may not silently eat a frame.
    fn forward(&self, room: &str, from: u64, message: Message) {
        let guard = self.lock();
        let Some(participants) = guard.get(room) else {
            return;
        };
        for participant in participants.iter().filter(|p| p.id != from) {
            if !participant.out.try_send(message.clone()) {
                participant.out.request_drain_close();
            }
        }
    }

    /// One participant left without a close (its socket dropped): close
    /// the remaining socket(s) with 1001 and dissolve the room.
    fn peer_gone(&self, room: &str, from: u64) {
        let mut rooms = self.lock();
        let Some(participants) = rooms.get_mut(room) else {
            return;
        };
        for participant in participants.iter().filter(|p| p.id != from) {
            let _ = participant
                .out
                .try_send(close_message(1001, "peer disconnected"));
        }
        rooms.remove(room);
    }

    /// The room died (TTL): one error message, then a 4410 close for
    /// everyone still attached.
    fn expire(&self, room: &str) {
        let mut rooms = self.lock();
        let Some(participants) = rooms.get_mut(room) else {
            return;
        };
        for participant in participants.iter() {
            let _ = participant.out.try_send(error_message(
                RelayErrorCode::RoomExpired,
                "pairing room TTL elapsed",
            ));
            let _ = participant
                .out
                .try_send(close_message(4410, "room expired"));
        }
        rooms.remove(room);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<Participant>>> {
        self.rooms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Live channel-event subscriptions (relay-protocol.md §8). The events
/// route adds subscribers; the append route notifies them after a commit.
/// Nothing buffers beyond the queue: a refused hint is a lost hint, which
/// the contract declares harmless.
#[derive(Default)]
pub struct ChannelSubscriptions {
    channels: Mutex<HashMap<String, Vec<Subscriber>>>,
}

struct Subscriber {
    id: u64,
    /// The pull credential as presented, kept only in memory: every push
    /// re-authorizes with it, which is how a revoked credential's stream
    /// dies on the next push attempt without any cache to invalidate.
    token: String,
    out: Outbound,
}

impl ChannelSubscriptions {
    fn subscribe(&self, channel: &str, token: &str, out: Outbound) -> u64 {
        let id = PARTICIPANT_IDS.fetch_add(1, Ordering::Relaxed);
        self.lock()
            .entry(channel.to_owned())
            .or_default()
            .push(Subscriber {
                id,
                token: token.to_owned(),
                out,
            });
        id
    }

    fn unsubscribe(&self, channel: &str, id: u64) {
        let mut channels = self.lock();
        if let Some(subscribers) = channels.get_mut(channel) {
            subscribers.retain(|subscriber| subscriber.id != id);
            if subscribers.is_empty() {
                channels.remove(channel);
            }
        }
    }

    /// One committed append: re-authorize every subscriber, hint the ones
    /// that still hold pull rights, and disconnect the revoked with a
    /// 4401 close. `still_authorized` is the store's authorize bound to
    /// the channel — the caller owns storage, the registry owns sockets.
    pub fn notify(&self, channel: &str, seq: u64, still_authorized: &mut dyn FnMut(&str) -> bool) {
        let mut channels = self.lock();
        let Some(subscribers) = channels.get_mut(channel) else {
            return;
        };
        subscribers.retain(|subscriber| {
            if !still_authorized(&subscriber.token) {
                let _ = subscriber.out.try_send(error_message(
                    RelayErrorCode::Unauthorized,
                    "credential revoked",
                ));
                let _ = subscriber
                    .out
                    .try_send(close_message(4401, "credential revoked"));
                return false;
            }
            let hint = WsServerMessage::ChannelAppended {
                protocol_version: RELAY_PROTOCOL_VERSION,
                channel_id: channel.to_owned(),
                seq,
            };
            let _ = subscriber.out.try_send(Message::Text(
                serde_json::to_string(&hint)
                    .expect("a hint always serializes")
                    .into(),
            ));
            true
        });
        if subscribers.is_empty() {
            channels.remove(channel);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<Subscriber>>> {
        self.channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One WebSocket session against the deployment's budget. Held by every
/// live pairing join and event subscription; dropped at session end.
type SessionPermit = tokio::sync::OwnedSemaphorePermit;

fn acquire_session(state: &AppState) -> Option<SessionPermit> {
    state.ws_permits.clone().try_acquire_owned().ok()
}

/// The bounded refusal for a full session budget: same shape as every
/// other refusal — upgrade, one error, then the close. `1013` (Try Again
/// Later) is the standard code for a load refusal, and `rate_limited` is
/// the contract's retryable load signal.
fn budget_refusal(upgrade: WebSocketUpgrade) -> Response {
    upgrade
        .on_upgrade(|mut socket| async move {
            let _ = socket
                .send(error_message(
                    RelayErrorCode::RateLimited,
                    "connection budget exhausted",
                ))
                .await;
            let _ = socket
                .send(close_message(1013, "connection budget exhausted"))
                .await;
        })
        .into_response()
}

/// `GET /v1/channels/{channelId}/events` — the update-notification
/// stream (relay-protocol.md §8). A pull-scope credential subscribes;
/// the socket is a pure listener, so any client message is a 1008.
pub async fn events_stream(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    // Same browser gate as the pairing join, before any channel state.
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        if !state
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
        {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    let upgrade = upgrade
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES);
    // An absent header is the empty token: authorize maps it to
    // Unauthorized like any other credential that grants nothing.
    let token = bearer(&headers).unwrap_or_default();
    if let Err(error) = state
        .store
        .authorize(&channel_id, &token, CredentialScope::Pull)
    {
        let (code, wire_code, reason) = events_refusal(error.code());
        return upgrade
            .on_upgrade(move |mut socket| async move {
                let _ = socket.send(error_message(wire_code, reason)).await;
                let _ = socket.send(close_message(code, reason)).await;
            })
            .into_response();
    }
    let Some(permit) = acquire_session(&state) else {
        return budget_refusal(upgrade);
    };
    // The drain hold is taken here, not inside the spawned session: the
    // upgrade response returns at once, and a shutdown in the gap between
    // must still see this session counted.
    let live = state.live_sessions.enter();
    upgrade
        .on_upgrade(move |socket| {
            run_events_session(socket, state, channel_id, token, permit, live)
        })
        .into_response()
}

/// The events route's refusal mapping: HTTP-parallel close codes, one
/// error message before the close, same upgrade-first pattern as the
/// pairing join. Foreign channel and missing scope arrive as the same
/// code — the requester learns the credential is no good, not whether
/// the named channel exists.
fn events_refusal(code: RelayErrorCode) -> (u16, RelayErrorCode, &'static str) {
    match code {
        RelayErrorCode::Unauthorized => (
            4401,
            RelayErrorCode::Unauthorized,
            "credential invalid or revoked",
        ),
        RelayErrorCode::Forbidden => (
            4403,
            RelayErrorCode::Forbidden,
            "credential lacks pull scope",
        ),
        _ => (1011, RelayErrorCode::Internal, "internal error"),
    }
}

/// Drive one subscribed listener: greet, receive hints from the append
/// route's pushes, and leave quietly. The client has no vocabulary on
/// this socket — anything it sends but pings is a 1008.
async fn run_events_session(
    socket: WebSocket,
    state: AppState,
    channel_id: String,
    token: String,
    _permit: SessionPermit,
    _live: LiveGuard,
) {
    let (sender, mut receiver) = socket.split();
    let (out, out_rx) = Outbound::new(state.ws_outbound_queue_bytes);
    let writer = tokio::task::spawn(write_outbound(
        sender,
        out_rx,
        out.queued.clone(),
        out.drain_close.clone(),
        out.close_signal.clone(),
    ));
    let my_id = state
        .subscriptions
        .subscribe(&channel_id, &token, out.clone());
    let greeting = WsServerMessage::EventsSubscribed {
        protocol_version: RELAY_PROTOCOL_VERSION,
        channel_id: channel_id.clone(),
    };
    if !out
        .send(Message::Text(
            serde_json::to_string(&greeting)
                .expect("the greeting always serializes")
                .into(),
        ))
        .await
    {
        writer.abort();
        return;
    }
    let mut last_seen = tokio::time::Instant::now();
    let mut next_ping = last_seen + state.ws_heartbeat.ping_every();
    // Fired once per session; a hint subscriber leaves the same way it
    // would on any other quiet exit — the client recovers by pulling.
    let mut stopping = false;
    loop {
        tokio::select! {
            incoming = receiver.next() => {
                let Some(incoming) = incoming else { break };
                let message = match incoming {
                    Ok(message) => message,
                    Err(_) => break,
                };
                last_seen = tokio::time::Instant::now();
                match message {
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => {}
                    // A listener has nothing to say: any other frame is a
                    // shape violation and closes with 1008, like the
                    // pairing surface.
                    Message::Text(_) | Message::Binary(_) => {
                        let _ = out.try_send(close_message(1008, "invalid events message"));
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(next_ping) => {
                let now = tokio::time::Instant::now();
                if now.duration_since(last_seen) > state.ws_heartbeat.idle_after() {
                    let _ = out.try_send(close_message(1008, "idle timeout"));
                    break;
                }
                let _ = out.try_send(Message::Ping(Bytes::new()));
                next_ping = now + state.ws_heartbeat.ping_every();
            }
            _ = state.shutdown.wait() => {
                stopping = true;
                break;
            }
        }
    }
    state.subscriptions.unsubscribe(&channel_id, my_id);
    if stopping {
        // 1001 (going away) is the code for "this endpoint is shutting
        // down": the client reconnects to the next process and pulls from
        // its cursor, which is the contract's recovery for a lost stream.
        let _ = out.try_send(close_message(1001, "server shutting down"));
    }
    out.finish(writer).await;
}

/// `GET /v1/pairing/{roomId}` — the WebSocket join (relay-protocol.md §7).
/// The capability rides only in the `Authorization` header, never the URL.
pub async fn join_room(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    // Browser gate first: an Origin the deployer did not allow never
    // reaches any room state, not even the existence checks.
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        if !state
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
        {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    let capability = bearer(&headers);
    let upgrade = upgrade
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES);
    // The session budget is checked before admission: a full server must
    // not burn a stranger's join attempt just to say "come back later".
    let permit = match acquire_session(&state) {
        Some(permit) => permit,
        None => return budget_refusal(upgrade),
    };
    // Same drain hold as the events route: taken in the handler so the
    // gap between the response and the spawned session stays counted.
    let live = state.live_sessions.enter();
    let now_ms = match unix_now_ms() {
        Ok(now_ms) => now_ms,
        Err(_) => {
            return upgrade
                .on_upgrade(move |mut socket| async move {
                    let _ = socket
                        .send(error_message(
                            RelayErrorCode::Internal,
                            "system clock is before the unix epoch",
                        ))
                        .await;
                    let _ = socket.send(close_message(1011, "internal error")).await;
                })
                .into_response()
        }
    };
    match state.rooms.join(
        room_id.as_str(),
        capability.as_deref().unwrap_or(""),
        now_ms,
    ) {
        Ok(joined) => upgrade
            .on_upgrade(move |socket| async move {
                run_session(
                    socket,
                    state,
                    room_id,
                    joined.peer_joined,
                    joined.expires_at_ms,
                    permit,
                    live,
                )
                .await;
            })
            .into_response(),
        // Refuse inside the socket: the close code is the only error
        // channel a browser can read (failed upgrades hide their HTTP
        // status), so every rejection completes the upgrade and then
        // sends one error message before the 44xx close.
        Err(error) => {
            drop(permit);
            drop(live);
            let (code, wire_code, reason) = refusal(&error);
            upgrade
                .on_upgrade(move |mut socket| async move {
                    let _ = socket.send(error_message(wire_code, reason)).await;
                    let _ = socket.send(close_message(code, reason)).await;
                })
                .into_response()
        }
    }
}

/// What a refused join closes with: the frozen close code plus the error
/// code that rides in the final message.
fn refusal(error: &JoinRoomError) -> (u16, RelayErrorCode, &'static str) {
    match error {
        JoinRoomError::CapabilityMismatch => {
            (4401, RelayErrorCode::Unauthorized, "capability invalid")
        }
        JoinRoomError::RoomNotFound => {
            (4404, RelayErrorCode::RoomNotFound, "pairing room not found")
        }
        JoinRoomError::Full => (4409, RelayErrorCode::RoomFull, "pairing room is full"),
        JoinRoomError::Expired => (4410, RelayErrorCode::RoomExpired, "pairing room expired"),
    }
}

/// Drive one admitted participant's socket: greet, forward, and leave.
async fn run_session(
    socket: WebSocket,
    state: AppState,
    room_id: String,
    peer_joined: bool,
    expires_at_ms: u64,
    _permit: SessionPermit,
    _live: LiveGuard,
) {
    let (sender, mut receiver) = socket.split();
    let (out, out_rx) = Outbound::new(state.ws_outbound_queue_bytes);
    let writer = tokio::task::spawn(write_outbound(
        sender,
        out_rx,
        out.queued.clone(),
        out.drain_close.clone(),
        out.close_signal.clone(),
    ));
    // The deadline task is the socket side's own clock: the registry
    // sweeps lazily, so expiry must fire even if nobody touches the room.
    let sessions = state.sessions.clone();
    let expiry_room = room_id.clone();
    let expiry = tokio::task::spawn(async move {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_millis() as u64)
            .unwrap_or(0);
        let wait = std::time::Duration::from_millis(expires_at_ms.saturating_sub(now_ms));
        tokio::time::sleep(wait).await;
        sessions.expire(&expiry_room);
    });

    // The greeting: `room.joined` once, with `peerJoined` saying whether
    // the other device is already here. It is never re-sent — when the
    // second participant joins they get their own `peerJoined: true`.
    let greeting = WsServerMessage::PairingRoomJoined {
        protocol_version: RELAY_PROTOCOL_VERSION,
        room_id: room_id.clone(),
        peer_joined,
    };
    if !out
        .send(Message::Text(
            serde_json::to_string(&greeting)
                .expect("the greeting always serializes")
                .into(),
        ))
        .await
    {
        writer.abort();
        expiry.abort();
        return;
    }

    let my_id = state.sessions.register(&room_id, out.clone());
    let mut last_seen = tokio::time::Instant::now();
    let mut next_ping = last_seen + state.ws_heartbeat.ping_every();
    // Fired once per session; drives the exit bookkeeping below.
    let mut stopping = false;
    loop {
        tokio::select! {
            incoming = receiver.next() => {
                let Some(incoming) = incoming else { break };
                let message = match incoming {
                    Ok(message) => message,
                    Err(_) => break,
                };
                last_seen = tokio::time::Instant::now();
                match message {
                    Message::Text(text) => {
                        let Some(frame) = decode_frame(&text) else {
                            // Wrong type, unknown fields, non-canonical
                            // base64url or an over-cap frame: 1008, per
                            // the contract.
                            let _ = out.try_send(close_message(1008, "invalid pairing message"));
                            break;
                        };
                        let forwarded = WsServerMessage::PairingFrame {
                            protocol_version: RELAY_PROTOCOL_VERSION,
                            data: frame,
                        };
                        state.sessions.forward(
                            &room_id,
                            my_id,
                            Message::Text(
                                serde_json::to_string(&forwarded)
                                    .expect("a frame echo always serializes")
                                    .into(),
                            ),
                        );
                    }
                    // The contract's client vocabulary is JSON text only.
                    Message::Binary(_) => {
                        let _ = out.try_send(close_message(1008, "invalid pairing message"));
                        break;
                    }
                    Message::Close(_) => break,
                    // Ping/Pong are transport housekeeping; tungstenite
                    // answers pings itself, and both count as life.
                    Message::Ping(_) | Message::Pong(_) => {}
                }
            }
            _ = tokio::time::sleep_until(next_ping) => {
                let now = tokio::time::Instant::now();
                if now.duration_since(last_seen) > state.ws_heartbeat.idle_after() {
                    let _ = out.try_send(close_message(1008, "idle timeout"));
                    break;
                }
                let _ = out.try_send(Message::Ping(Bytes::new()));
                next_ping = now + state.ws_heartbeat.ping_every();
            }
            _ = state.shutdown.wait() => {
                stopping = true;
                break;
            }
        }
    }
    if stopping {
        // Say "going away" before the bookkeeping: the roommate's own
        // shutdown branch sends its goodbye through the same path, so a
        // mid-pairing handshake ends declared, not reset.
        let _ = out.try_send(close_message(1001, "server shutting down"));
    }
    // Leaving: notify the roommate (1001) unless the room already
    // dissolved (expiry or the roommate left first — both remove it).
    state.sessions.peer_gone(&room_id, my_id);
    expiry.abort();
    // Close the queue and let the writer finish: aborting it here could
    // drop the socket before the close frame is flushed, and the peer
    // would see a connection reset where the contract says a close code.
    out.finish(writer).await;
}

/// Validate one client text message and return its frame payload
/// (canonical base64url, within the cap). `None` is a shape violation:
/// anything that is not exactly a `pairing.frame` with `protocolVersion`,
/// `type` and `data` — and nothing else.
fn decode_frame(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    // Exactly the three frozen keys; an unknown fourth field is a 1008.
    if object.len() != 3
        || !object.contains_key("protocolVersion")
        || !object.contains_key("type")
        || !object.contains_key("data")
    {
        return None;
    }
    let parsed: WsClientMessage = serde_json::from_value(value).ok()?;
    let WsClientMessage::PairingFrame {
        protocol_version: _,
        data,
    } = parsed;
    // The cap applies to the decoded frame. Checking the base64 length
    // first keeps oversized payloads from being decoded at all; the exact
    // length check after decoding rejects padding tricks.
    if data.len() > PAIRING_FRAME_MAX_BYTES / 3 * 4 + 4 {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&data)
        .ok()?;
    if decoded.len() > PAIRING_FRAME_MAX_BYTES {
        return None;
    }
    Some(data)
}

fn error_message(code: RelayErrorCode, message: &str) -> Message {
    let body = WsServerMessage::Error {
        protocol_version: RELAY_PROTOCOL_VERSION,
        code,
        message: message.to_owned(),
    };
    Message::Text(
        serde_json::to_string(&body)
            .expect("an error message always serializes")
            .into(),
    )
}

fn close_message(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}
