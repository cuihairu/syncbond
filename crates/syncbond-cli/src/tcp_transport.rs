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
    /// length above the cap clears the buffer and yields an empty frame,
    /// which the callers surface as a hard transport error.
    fn extract_frame(&mut self) -> Option<Vec<u8>> {
        if self.buffer.len() < 4 {
            return None;
        }
        let length_bytes: Vec<u8> = self.buffer.iter().take(4).copied().collect();
        let length = u32::from_le_bytes(length_bytes.try_into().expect("4 bytes")) as usize;
        if length > MAX_FRAME_BYTES {
            self.buffer.clear();
            return Some(Vec::new());
        }
        if self.buffer.len() < 4 + length {
            return None;
        }
        self.buffer.drain(..4);
        Some(self.buffer.drain(..length).collect())
    }

    /// Blocking read of one full frame; keeps partial data across calls.
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            if let Some(frame) = self.extract_frame() {
                if frame.is_empty() && self.buffer.is_empty() {
                    return Err(TransportError::Send(
                        "advertised frame length exceeds the demo cap".into(),
                    ));
                }
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
            if let Some(frame) = self.extract_frame() {
                if frame.is_empty() && self.buffer.is_empty() {
                    return Err(TransportError::Send(
                        "advertised frame length exceeds the demo cap".into(),
                    ));
                }
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
        let mut reader = self
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reader
            .stream
            .set_nonblocking(true)
            .map_err(|error| TransportError::Send(error.to_string()))?;
        let result = reader.try_read_frame();
        let _ = reader.stream.set_nonblocking(false);
        result
    }
}
