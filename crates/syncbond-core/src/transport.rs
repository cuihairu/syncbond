//! Transport abstraction. The core never touches sockets: pairing and
//! replication exchange opaque frames over this interface. An in-memory
//! loopback is provided; WebSocket/LAN/P2P transports are planned.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum TransportError {
    #[error("transport closed")]
    Closed,
    #[error("send failed: {0}")]
    Send(String),
}

pub trait Transport: Send + Sync {
    /// Send one frame to the peer.
    fn send(&self, frame: &[u8]) -> Result<(), TransportError>;
    /// Block until a frame arrives from the peer.
    fn recv(&self) -> Result<Vec<u8>, TransportError>;
    /// Try to receive without blocking.
    fn try_recv(&self) -> Result<Vec<u8>, TransportError>;
}

struct Shared {
    queue: VecDeque<Vec<u8>>,
    closed: bool,
}

/// In-memory loopback transport for tests and examples.
pub struct MemoryTransport {
    inbox: Arc<Mutex<Shared>>,
    peer_outbox: Arc<Mutex<Shared>>,
    signal: Arc<Condvar>,
}

impl MemoryTransport {
    /// Wire two transports to each other.
    pub fn pair() -> (Arc<MemoryTransport>, Arc<MemoryTransport>) {
        let a_inbox = Arc::new(Mutex::new(Shared {
            queue: VecDeque::new(),
            closed: false,
        }));
        let b_inbox = Arc::new(Mutex::new(Shared {
            queue: VecDeque::new(),
            closed: false,
        }));
        let signal = Arc::new(Condvar::new());
        (
            Arc::new(MemoryTransport {
                inbox: a_inbox.clone(),
                peer_outbox: b_inbox.clone(),
                signal: signal.clone(),
            }),
            Arc::new(MemoryTransport {
                inbox: b_inbox,
                peer_outbox: a_inbox,
                signal,
            }),
        )
    }

    pub fn close_pair(a: &MemoryTransport, b: &MemoryTransport) {
        for inbox in [&a.inbox, &b.inbox] {
            let mut guard = inbox.lock().unwrap();
            guard.closed = true;
        }
        a.signal.notify_all();
        b.signal.notify_all();
    }
}

impl Transport for MemoryTransport {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        let mut peer = self.peer_outbox.lock().unwrap();
        if peer.closed {
            return Err(TransportError::Closed);
        }
        peer.queue.push_back(frame.to_vec());
        drop(peer);
        self.signal.notify_all();
        Ok(())
    }

    fn recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut inbox = self.inbox.lock().unwrap();
        loop {
            if let Some(frame) = inbox.queue.pop_front() {
                return Ok(frame);
            }
            if inbox.closed {
                return Err(TransportError::Closed);
            }
            inbox = self.signal.wait(inbox).unwrap();
        }
    }

    fn try_recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut inbox = self.inbox.lock().unwrap();
        inbox.queue.pop_front().ok_or(TransportError::Closed)
    }
}
