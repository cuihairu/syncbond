//! Minimal TCP transport for the demos: one socket, u32-LE length-prefixed
//! frames. Two clones of the same connection (one for reading, one for
//! writing) keep `send` and blocking `recv` usable concurrently, which the
//! pairing handshake's strict alternation requires.
//!
//! The reader keeps a byte buffer across calls, so `try_recv` preserves
//! partially received frames instead of consuming a fragment and dropping
//! the rest of the frame.
//!
//! Demo-grade only: no TLS, no reconnection. Production transports are the
//! application's job behind the core `Transport` trait.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use syncbond_core::transport::{Transport, TransportError};

/// Refuse absurd advertised lengths before allocating (the pairing protocol
/// caps frames at 16 MiB; this demo bound is deliberately far above that).
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

struct FrameReader {
    stream: TcpStream,
    buffer: VecDeque<u8>,
}

impl FrameReader {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: VecDeque::new(),
        }
    }

    /// Pop one complete frame from the buffered bytes, if any. An advertised
    /// length above the cap is a hard transport error (the peer is broken),
    /// reported directly rather than through an ambiguous sentinel, so a
    /// legitimate zero-length frame (length 0) is still returned as an empty
    /// payload instead of being misread as the oversize error.
    fn extract_frame(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let length_bytes: Vec<u8> = self.buffer.iter().take(4).copied().collect();
        let length = u32::from_le_bytes(length_bytes.try_into().expect("4 bytes")) as usize;
        if length > MAX_FRAME_BYTES {
            self.buffer.clear();
            return Err(TransportError::Send(
                "advertised frame length exceeds the demo cap".into(),
            ));
        }
        if self.buffer.len() < 4 + length {
            return Ok(None);
        }
        self.buffer.drain(..4);
        Ok(Some(self.buffer.drain(..length).collect()))
    }

    /// Blocking read of one full frame; keeps partial data across calls.
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            if let Some(frame) = self.extract_frame()? {
                return Ok(frame);
            }
            let mut chunk = [0u8; 8192];
            let read = self
                .stream
                .read(&mut chunk)
                .map_err(|_| TransportError::Closed)?;
            if read == 0 {
                return Err(TransportError::Closed);
            }
            self.buffer.extend(&chunk[..read]);
        }
    }

    /// Nonblocking read: fills the buffer with whatever arrived and returns
    /// `Empty` until a complete frame is available.
    fn try_read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            if let Some(frame) = self.extract_frame()? {
                return Ok(frame);
            }
            let mut chunk = [0u8; 8192];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(TransportError::Closed),
                Ok(read) => self.buffer.extend(&chunk[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    return Err(TransportError::Empty);
                }
                Err(_) => return Err(TransportError::Closed),
            }
        }
    }
}

pub struct TcpTransport {
    writer: Mutex<TcpStream>,
    reader: Mutex<FrameReader>,
    /// Serializes `send` and `try_recv`: `try_recv` toggles the nonblocking
    /// mode of the socket shared (via the clone) with the writer, and that
    /// toggle must never overlap a write, or `send` would see WouldBlock.
    /// `recv` never touches the mode, so it does not need this lock.
    io_lock: Mutex<()>,
}

impl TcpTransport {
    /// Dial the peer and wrap the connection.
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self::wrap(stream))
    }

    /// Accept one inbound connection on a bound listener.
    pub fn accept(listener: &TcpListener) -> std::io::Result<Self> {
        let (stream, peer) = listener.accept()?;
        eprintln!("[tcp] peer connected from {peer}");
        Ok(Self::wrap(stream))
    }

    fn wrap(stream: TcpStream) -> Self {
        let reader = stream
            .try_clone()
            .expect("cloning the TCP stream always works on supported platforms");
        Self {
            writer: Mutex::new(stream),
            reader: Mutex::new(FrameReader::new(reader)),
            io_lock: Mutex::new(()),
        }
    }
}

impl Transport for TcpTransport {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > u32::MAX as usize {
            return Err(TransportError::Send(format!(
                "frame too large for the demo transport: {} bytes",
                frame.len()
            )));
        }
        let length = (frame.len() as u32).to_le_bytes();
        let _io = self
            .io_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut writer = self
            .writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        writer
            .write_all(&length)
            .and_then(|()| writer.write_all(frame))
            .and_then(|()| writer.flush())
            .map_err(|error| TransportError::Send(error.to_string()))
    }

    fn recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut reader = self
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reader.read_frame()
    }

    fn try_recv(&self) -> Result<Vec<u8>, TransportError> {
        let _io = self
            .io_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut reader = self
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The socket is shared with the writer through the clone, so the
        // nonblocking toggle must be restored even on an early return (or a
        // panic) before the writer can run again. `_io` is released only
        // after this guard drops, keeping the toggle out of any concurrent
        // `send`. The guard owns a *clone* of the socket (the mode flag is
        // shared across clones of the same open file description), so it
        // does not borrow `reader` and can outlive the read.
        let probe = reader
            .stream
            .try_clone()
            .map_err(|error| TransportError::Send(error.to_string()))?;
        let _nonblocking = Nonblocking::new(probe);
        reader.try_read_frame()
    }
}

/// RAII guard that puts a socket clone into nonblocking mode and restores
/// blocking mode on drop, so a `try_recv` can never leave the shared socket
/// nonblocking for a later `send`.
struct Nonblocking {
    stream: TcpStream,
}

impl Nonblocking {
    fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nonblocking(true);
        Self { stream }
    }
}

impl Drop for Nonblocking {
    fn drop(&mut self) {
        let _ = self.stream.set_nonblocking(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn transport_pair() -> (TcpTransport, TcpTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (TcpTransport::wrap(server), TcpTransport::wrap(client))
    }

    #[test]
    fn zero_length_frame_round_trips() {
        let (a, b) = transport_pair();
        a.send(b"").expect("send empty frame");
        assert_eq!(b.recv().expect("recv empty frame"), Vec::<u8>::new());
    }

    #[test]
    fn try_recv_empty_then_send_still_works() {
        let (a, b) = transport_pair();
        // Nothing queued yet: try_recv must report Empty, not Closed.
        assert_eq!(a.try_recv(), Err(TransportError::Empty));
        // The nonblocking toggle must be restored, so a send on the cloned
        // writer still succeeds (blocking mode).
        a.send(b"after-empty").expect("send after try_recv");
        assert_eq!(b.recv().expect("recv"), b"after-empty".to_vec());
    }

    #[test]
    fn oversize_advertised_frame_is_an_error_not_an_empty_frame() {
        let (a, b) = transport_pair();
        // Write a raw oversized length header (MAX_FRAME_BYTES + 1) followed
        // by no payload, then assert the receiver errors rather than
        // delivering an empty frame.
        let mut stream = a.writer.lock().unwrap();
        let length = (MAX_FRAME_BYTES as u32 + 1).to_le_bytes();
        stream.write_all(&length).expect("write oversize header");
        stream.flush().expect("flush");
        drop(stream);
        assert!(matches!(
            b.recv(),
            Err(TransportError::Send(msg)) if msg.contains("exceeds the demo cap")
        ));
    }
}
