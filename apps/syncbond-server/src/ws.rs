//! The v1 WebSocket surface: pairing-room frame forwarding (todo.md
//! DSR-21, relay-protocol.md §7).
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
//!
//! Browser clients must present an `Origin` in the configured
//! `allowedOrigins` (403 at the upgrade, before any room state is
//! touched); clients without an `Origin` header are unaffected. Trusted
//! proxy settings (`X-Forwarded-For` and friends) are deliberately absent
//! here: behind a TLS reverse proxy the rate-limit key is the proxy's
//! address until DSR-23 defines the trust policy, per default-server.md.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use syncbond_relay_protocol::dto::{WsClientMessage, WsServerMessage};
use syncbond_relay_protocol::error::RelayErrorCode;
use syncbond_relay_protocol::limits::PAIRING_FRAME_MAX_BYTES;
use syncbond_relay_protocol::RELAY_PROTOCOL_VERSION;

use crate::http::{bearer, unix_now_ms, AppState};
use crate::rooms::JoinRoomError;

/// The wire cap for one WS message: a legitimate `pairing.frame` holds at
/// most `PAIRING_FRAME_MAX_BYTES` bytes as canonical base64url plus the
/// JSON envelope, so anything above this is rejected by the socket layer
/// before user code parses it. Frames between this ceiling and the decoded
/// cap (i.e. oversized but under the socket cap) are closed with 1008 by
/// [`decode_frame`], which is the contract's close code.
const MAX_WS_MESSAGE_BYTES: usize = (PAIRING_FRAME_MAX_BYTES / 3 + 1) * 4 + 4096;

/// Live pairing-room sockets, keyed by room id. The registry in
/// `rooms.rs` decides who gets in; this map is only about reaching the
/// ones who already did.
#[derive(Default)]
pub struct RoomSessions {
    rooms: Mutex<HashMap<String, Vec<Participant>>>,
}

struct Participant {
    id: u64,
    out: tokio::sync::mpsc::Sender<Message>,
}

static PARTICIPANT_IDS: AtomicU64 = AtomicU64::new(1);

impl RoomSessions {
    fn register(&self, room: &str, out: tokio::sync::mpsc::Sender<Message>) -> u64 {
        let id = PARTICIPANT_IDS.fetch_add(1, Ordering::Relaxed);
        self.lock()
            .entry(room.to_owned())
            .or_default()
            .push(Participant { id, out });
        id
    }

    /// Hand `message` to every participant in `room` except `from`.
    fn forward(&self, room: &str, from: u64, message: Message) {
        let guard = self.lock();
        let Some(participants) = guard.get(room) else {
            return;
        };
        for participant in participants.iter().filter(|p| p.id != from) {
            // A send failure means that socket is gone; its own cleanup
            // runs when its reader notices. Nothing to do here.
            let _ = participant.out.try_send(message.clone());
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
                )
                .await;
            })
            .into_response(),
        // Refuse inside the socket: the close code is the only error
        // channel a browser can read (failed upgrades hide their HTTP
        // status), so every rejection completes the upgrade and then
        // sends one error message before the 44xx close.
        Err(error) => {
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
) {
    let (mut sender, mut receiver) = socket.split();
    // The outbound half belongs to a dedicated writer so the reader can
    // block on the peer while forwarded frames flow the other way.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Message>(32);
    let writer = tokio::task::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sender.send(message).await.is_err() {
                break;
            }
        }
        // The queue is drained: flush whatever the closing handshake still
        // owes the peer (the close frame itself, or its echo) so the peer
        // reads the code instead of a reset.
        let _ = sender.close().await;
    });
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
    if out_tx
        .send(Message::Text(
            serde_json::to_string(&greeting)
                .expect("the greeting always serializes")
                .into(),
        ))
        .await
        .is_err()
    {
        writer.abort();
        expiry.abort();
        return;
    }

    let my_id = state.sessions.register(&room_id, out_tx.clone());
    while let Some(incoming) = receiver.next().await {
        let message = match incoming {
            Ok(message) => message,
            Err(_) => break,
        };
        match message {
            Message::Text(text) => {
                let Some(frame) = decode_frame(&text) else {
                    // Wrong type, unknown fields, non-canonical base64url
                    // or an over-cap frame: 1008, per the contract.
                    let _ = out_tx
                        .send(close_message(1008, "invalid pairing message"))
                        .await;
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
                let _ = out_tx
                    .send(close_message(1008, "invalid pairing message"))
                    .await;
                break;
            }
            Message::Close(_) => break,
            // Ping/Pong are transport housekeeping; tungstenite answers
            // pings itself, nothing for the pairing relay to do.
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
    // Leaving: notify the roommate (1001) unless the room already
    // dissolved (expiry or the roommate left first — both remove it).
    state.sessions.peer_gone(&room_id, my_id);
    expiry.abort();
    // Close the queue and let the writer finish: aborting it here could
    // drop the socket before the close frame is flushed, and the peer
    // would see a connection reset where the contract says a close code.
    drop(out_tx);
    let _ = writer.await;
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
