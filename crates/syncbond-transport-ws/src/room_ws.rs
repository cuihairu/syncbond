//! The WebSocket hop: join the pairing room (§7 `GET /v1/pairing/{roomId}`)
//! and read the greeting. The capability rides only in the `Authorization`
//! header, never the URL. The greeting's `peerJoined` decides SPAKE2 roles:
//! whoever joined **first** (peerJoined=false) becomes the responder and
//! waits; whoever joined **second** becomes the initiator and sends pA.
//! Only the second participant's frames can reach a connected peer — the
//! relay drops frames addressed to an absent one — so this assignment is
//! deadlock-free regardless of which device starts first.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use syncbond_relay_protocol::dto::WsServerMessage;
use syncbond_relay_protocol::error::ErrorBody;
use syncbond_relay_protocol::RELAY_PROTOCOL_VERSION;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::error::Error as WsError;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{
    connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream,
};

use crate::bridge::WsTransport;
use crate::error::WsPairingError;
use crate::options::{Invite, RelayLocation, TlsPolicy};
use crate::tls;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) struct JoinedRoom {
    pub transport: WsTransport,
    /// True when this participant joined second, and therefore speaks
    /// first (SPAKE2 initiator).
    pub peer_joined: bool,
}

pub(crate) async fn join_room(
    location: &RelayLocation,
    tls_policy: &TlsPolicy,
    invite: &Invite,
    capacity: usize,
    connect_timeout: Duration,
) -> Result<JoinedRoom, WsPairingError> {
    let room_segment = join_room_segment(&invite.room_id)?;
    let url = format!(
        "{}://{}/v1/pairing/{}",
        location.ws_scheme(),
        location.authority,
        room_segment,
    );
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| WsPairingError::Protocol(format!("join request: {error}")))?;
    let capability = HeaderValue::from_str(&format!("Bearer {}", invite.capability))
        .map_err(|_| WsPairingError::Protocol("capability is not header-safe".into()))?;
    request.headers_mut().insert("authorization", capability);

    let connector = if location.secure {
        Some(Connector::Rustls(Arc::new(tls::client_config(tls_policy)?)))
    } else {
        None
    };

    let (stream, _response) = tokio::time::timeout(
        connect_timeout,
        connect_async_tls_with_config(request, None, false, connector),
    )
    .await
    .map_err(|_| WsPairingError::Timeout)?
    .map_err(classify_handshake)?;

    // The greeting follows the upgrade immediately; the same budget
    // covers it so a relay that accepts but never greets cannot hang us.
    let mut stream: WsStream = stream;
    let text = match tokio::time::timeout(connect_timeout, stream.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        Ok(Some(Ok(_))) => {
            return Err(WsPairingError::Protocol(
                "first server message is not text".into(),
            ))
        }
        Ok(Some(Err(error))) => return Err(classify_handshake(error)),
        Ok(None) => {
            return Err(WsPairingError::Io(
                "socket ended before the room greeting".into(),
            ))
        }
        Err(_elapsed) => return Err(WsPairingError::Timeout),
    };
    let peer_joined = parse_greeting(&text, invite)?;

    Ok(JoinedRoom {
        transport: WsTransport::spawn(stream, capacity),
        peer_joined,
    })
}

/// The greeting decides this side's speaking order: `peerJoined: false`
/// means we are first (responder), `true` means second (initiator).
fn parse_greeting(text: &str, invite: &Invite) -> Result<bool, WsPairingError> {
    match serde_json::from_str::<WsServerMessage>(text) {
        Ok(WsServerMessage::PairingRoomJoined {
            protocol_version,
            room_id,
            peer_joined,
        }) => {
            if protocol_version != RELAY_PROTOCOL_VERSION {
                return Err(WsPairingError::Protocol(format!(
                    "relay speaks protocol {protocol_version}, we speak {RELAY_PROTOCOL_VERSION}"
                )));
            }
            if room_id != invite.room_id {
                return Err(WsPairingError::Protocol(format!(
                    "greeting names room {room_id:?}, we joined {:?}",
                    invite.room_id
                )));
            }
            Ok(peer_joined)
        }
        Ok(WsServerMessage::Error { code, message, .. }) => Err(WsPairingError::Relay {
            code,
            status: code.http_status(),
            message,
        }),
        Ok(_) => Err(WsPairingError::Protocol(format!(
            "expected room.joined, got: {text}"
        ))),
        Err(error) => Err(WsPairingError::Protocol(format!(
            "unparseable greeting: {error}"
        ))),
    }
}

/// The room segment of the join URL. Registry room ids are base64url-ish,
/// but the check stays explicit: anything that could smuggle a path or
/// query into the URL is refused before a socket exists.
fn join_room_segment(room_id: &str) -> Result<&str, WsPairingError> {
    let ok = !room_id.is_empty()
        && room_id.len() <= 128
        && room_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(room_id)
    } else {
        Err(WsPairingError::Protocol(format!(
            "room id is not url-safe: {:?}",
            room_id
        )))
    }
}

/// Map a failed handshake to the typed surface. The relay answers refusals
/// with an HTTP status whose body is the frozen error shape — parse it when
/// it is there, so callers switch on `RelayErrorCode`, not prose.
fn classify_handshake(error: WsError) -> WsPairingError {
    match error {
        WsError::Http(response) => {
            let status = response.status().as_u16();
            if let Ok(parsed) =
                serde_json::from_slice::<ErrorBody>(response.body().as_deref().unwrap_or(&[]))
            {
                return WsPairingError::Relay {
                    code: parsed.error.code,
                    status,
                    message: parsed.error.message,
                };
            }
            WsPairingError::Io(format!("join handshake failed with http {status}"))
        }
        WsError::Tls(tls_error) => WsPairingError::Tls(tls_error.to_string()),
        other => WsPairingError::Io(other.to_string()),
    }
}
