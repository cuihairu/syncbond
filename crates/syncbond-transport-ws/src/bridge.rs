//! The bridge between the async WebSocket world and the sync
//! [`Transport`](syncbond_core::transport::Transport) the core speaks. One
//! [`WsTransport`] owns two bounded queues (one per direction) and two
//! tasks that pump them against the socket:
//!
//! - **outbound**: the core's `send`/`send_async` drops a raw frame into a
//!   bounded mpsc; the writer task frames it (`pairing.frame`, base64url)
//!   onto the socket. A slow wire backpressures the core instead of
//!   buffering without limit.
//! - **inbound**: the reader task parses server messages — pairing frames
//!   are decoded and queued (`Ok`), a relay `error` or a close frame ends
//!   the queue with the typed failure. The sync face's `recv` and the
//!   async face's `recv_async` share this queue.
//!
//! The two faces differ only in wait style: the async face is for the
//! pairing pump (running on a runtime), the sync face for the completed
//! [`PairingSession`](syncbond_core::pairing::PairingSession), whose
//! methods are blocking — its `send`/`recv` must run outside the runtime
//! (`tokio::task::spawn_blocking`), or tokio panics.
//!
//! Dropping the transport aborts the reader, which drops the socket: the
//! relay closes the peer's side with `1001` and a mid-pairing peer ends
//! promptly instead of waiting out its timeout.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::{SinkExt as _, StreamExt as _};
use syncbond_core::transport::{Transport, TransportError};
use syncbond_relay_protocol::dto::{WsClientMessage, WsServerMessage};
use syncbond_relay_protocol::RELAY_PROTOCOL_VERSION;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::error::WsPairingError;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type InboundQueue = Arc<tokio::sync::Mutex<mpsc::Receiver<Result<Vec<u8>, WsPairingError>>>>;

pub(crate) struct WsTransport {
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: InboundQueue,
    reader: tokio::task::JoinHandle<()>,
}

impl WsTransport {
    /// Split a joined room's socket into the two pump tasks. `capacity` is
    /// the per-direction bound (clamped to at least 1).
    pub(crate) fn spawn(stream: WsStream, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(capacity);
        let (inbound_tx, inbound_rx) = mpsc::channel(capacity);
        let (mut write, mut read) = stream.split();

        // The writer task is detached on purpose: it ends when the
        // transport drops (the outbound queue closes), after saying
        // goodbye on the wire.
        tokio::task::spawn(async move {
            while let Some(frame) = outbound_rx.recv().await {
                let message = WsClientMessage::PairingFrame {
                    protocol_version: RELAY_PROTOCOL_VERSION,
                    data: URL_SAFE_NO_PAD.encode(&frame),
                };
                let text = serde_json::to_string(&message).expect("a closed DTO serializes");
                if write.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            // The transport dropped: say goodbye so the relay closes the
            // peer with 1001 instead of idling the room out.
            let _ = write.close().await;
        });

        let reader = tokio::task::spawn(async move {
            let inbound = inbound_tx;
            while let Some(message) = read.next().await {
                match message {
                    Ok(Message::Text(text)) => match server_frame(&text) {
                        Ok(Some(frame)) => {
                            if inbound.send(Ok(frame)).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let _ = inbound.send(Err(error)).await;
                            break;
                        }
                    },
                    // The relay sends text; a peer speaking binary JSON is
                    // still understandable, so accept it defensively.
                    Ok(Message::Binary(bytes)) => match std::str::from_utf8(&bytes) {
                        Ok(text) => match server_frame(text) {
                            Ok(Some(frame)) => {
                                if inbound.send(Ok(frame)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                let _ = inbound.send(Err(error)).await;
                                break;
                            }
                        },
                        Err(_) => {
                            let _ = inbound
                                .send(Err(WsPairingError::Protocol(
                                    "binary frame is not utf-8".into(),
                                )))
                                .await;
                            break;
                        }
                    },
                    // Client pings are answered by tungstenite's read path.
                    Ok(Message::Ping(_) | Message::Pong(_)) => {}
                    Ok(Message::Close(frame)) => {
                        let code = frame.map(|f| u16::from(f.code)).unwrap_or(1006);
                        let _ = inbound.send(Err(WsPairingError::RoomClosed(code))).await;
                        break;
                    }
                    // Raw frames never surface in reads.
                    Ok(Message::Frame(_)) => {}
                    Err(_) => {
                        let _ = inbound
                            .send(Err(WsPairingError::Io("websocket read failed".into())))
                            .await;
                        break;
                    }
                }
            }
        });

        Self {
            outbound: outbound_tx,
            inbound: Arc::new(tokio::sync::Mutex::new(inbound_rx)),
            reader,
        }
    }

    /// The async face the pairing pump drives.
    pub(crate) async fn send_async(&self, frame: &[u8]) -> Result<(), WsPairingError> {
        self.outbound
            .send(frame.to_vec())
            .await
            .map_err(|_| WsPairingError::Io("websocket writer is gone".into()))
    }

    /// The async face's receive: the next pairing frame, or the terminal
    /// failure (relay error, close, socket end).
    pub(crate) async fn recv_async(&self) -> Result<Vec<u8>, WsPairingError> {
        let mut inbound = self.inbound.lock().await;
        match inbound.recv().await {
            Some(Ok(frame)) => Ok(frame),
            Some(Err(error)) => Err(error),
            None => Err(WsPairingError::Io("websocket closed".into())),
        }
    }
}

impl Drop for WsTransport {
    fn drop(&mut self) {
        // Abort the reader: dropping its read half tears the socket down
        // promptly even if the relay never answers the writer's close.
        self.reader.abort();
    }
}

impl Transport for WsTransport {
    /// Blocking face for the completed session. Panics on a runtime
    /// thread (tokio rule) — call from `spawn_blocking`.
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        self.outbound
            .blocking_send(frame.to_vec())
            .map_err(|_| TransportError::Closed)
    }

    fn recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut inbound = self.inbound.blocking_lock();
        match inbound.blocking_recv() {
            Some(Ok(frame)) => Ok(frame),
            // A queued error or an empty, closed queue are both "the peer
            // is gone"; the sync face has no richer vocabulary.
            Some(Err(_)) | None => Err(TransportError::Closed),
        }
    }

    fn try_recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut inbound = self.inbound.blocking_lock();
        match inbound.try_recv() {
            Ok(Ok(frame)) => Ok(frame),
            Ok(Err(_)) => Err(TransportError::Closed),
            Err(mpsc::error::TryRecvError::Empty) => Err(TransportError::Empty),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(TransportError::Closed),
        }
    }
}

/// Decode one server text message into a pairing frame. `Ok(None)` is a
/// message the pairing pump must not see (the greeting, a re-greet):
/// skipped, never queued.
fn server_frame(text: &str) -> Result<Option<Vec<u8>>, WsPairingError> {
    match serde_json::from_str::<WsServerMessage>(text) {
        Ok(WsServerMessage::PairingFrame { data, .. }) => URL_SAFE_NO_PAD
            .decode(data.as_bytes())
            .map(Some)
            .map_err(|error| WsPairingError::Protocol(format!("pairing.frame data: {error}"))),
        // The greeting arrives once at join; room_ws consumes it. A second
        // one can only be a protocol violation we choose to ride out.
        Ok(WsServerMessage::PairingRoomJoined { .. }) => Ok(None),
        Ok(WsServerMessage::Error { code, message, .. }) => Err(WsPairingError::Relay {
            code,
            status: code.http_status(),
            message,
        }),
        Ok(WsServerMessage::EventsSubscribed { .. } | WsServerMessage::ChannelAppended { .. }) => {
            Err(WsPairingError::Protocol(format!(
                "channel message on the pairing surface: {text}"
            )))
        }
        Err(error) => Err(WsPairingError::Protocol(format!(
            "unparseable server message: {error}"
        ))),
    }
}
