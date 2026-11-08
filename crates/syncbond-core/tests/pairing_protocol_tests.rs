//! Protocol-frame robustness: the pairing handshake and the encrypted app
//! channel must reject mis-typed, truncated, tampered and replayed frames on
//! the wire with explicit protocol errors instead of undefined behavior.

use std::sync::{Arc, Mutex};

use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::{accept, pair};
use syncbond_core::transport::{MemoryTransport, Transport, TransportError};

const CODE: &str = "K7Q2M4";

const FRAME_CONFIRM_A: u8 = 0x03;
const FRAME_IDENTITY_A: u8 = 0x05;
const FRAME_IDENTITY_B: u8 = 0x06;
const FRAME_APP: u8 = 0x08;

/// One wire-frame rewrite.
type FrameTransform = Box<dyn Fn(&mut Vec<u8>) + Send + Sync>;

/// A pass-through transport that rewrites every frame the local end
/// receives, simulating an attacker or a broken link on the wire.
struct TamperingTransport {
    inner: Arc<dyn Transport>,
    transform: FrameTransform,
}

impl Transport for TamperingTransport {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        self.inner.send(frame)
    }

    fn recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut frame = self.inner.recv()?;
        (self.transform)(&mut frame);
        Ok(frame)
    }

    fn try_recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut frame = self.inner.try_recv()?;
        (self.transform)(&mut frame);
        Ok(frame)
    }
}

fn tampered(
    inner: Arc<dyn Transport>,
    transform: impl Fn(&mut Vec<u8>) + Send + Sync + 'static,
) -> Arc<dyn Transport> {
    Arc::new(TamperingTransport {
        inner,
        transform: Box::new(transform),
    })
}

fn flip_identity_signature(frame: &mut [u8]) {
    if matches!(
        frame.first(),
        Some(&FRAME_IDENTITY_A) | Some(&FRAME_IDENTITY_B)
    ) {
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
    }
}

#[test]
fn recv_and_open_rejects_non_app_frames() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    std::thread::scope(|s| {
        let tb_for_accept = tb.clone();
        let responder = s.spawn(move || {
            accept(CODE, &ib, tb_for_accept as Arc<dyn Transport>).expect("responder pairing")
        });
        let initiator =
            pair(CODE, &ia, ta.clone() as Arc<dyn Transport>).expect("initiator pairing");
        responder.join().expect("responder thread");

        // A control frame smuggled onto the app channel is not an envelope;
        // send it peer-to-initiator so the initiator's receive path sees it.
        tb.send(&[0x7F, 0x01]).expect("raw frame delivered");
        let err = initiator
            .recv_and_open()
            .expect_err("non-app frame must fail");
        assert!(
            err.to_string().contains("expected application frame"),
            "{err}"
        );
    });
}

#[test]
fn recv_and_open_rejects_replayed_wire_frames() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let recorder = {
        let captured = Arc::clone(&captured);
        tampered(tb as Arc<dyn Transport>, move |frame| {
            if frame.first() == Some(&FRAME_APP) {
                *captured.lock().unwrap() = Some(frame.clone());
            }
        })
    };
    std::thread::scope(|s| {
        let responder = s.spawn(move || accept(CODE, &ib, recorder).expect("responder pairing"));
        let initiator =
            pair(CODE, &ia, ta.clone() as Arc<dyn Transport>).expect("initiator pairing");
        let responder = responder.join().expect("responder thread");

        initiator.seal_and_send(b"hello").expect("seal and send");
        assert_eq!(responder.recv_and_open().expect("first delivery"), b"hello");

        // Redeliver the exact same wire frame: its message id is spent.
        let frame = captured
            .lock()
            .unwrap()
            .clone()
            .expect("app frame captured");
        ta.send(&frame).expect("replayed frame delivered");
        let err = responder.recv_and_open().expect_err("replay must fail");
        assert!(err.to_string().contains("replayed message id"), "{err}");
    });
}

/// Drive a handshake whose responder-side confirm frame is rewritten; the
/// responder must fail with the expected protocol error and the initiator
/// must learn of it through the abort frame.
fn handshake_with_tampered_confirm(
    transform: impl Fn(&mut Vec<u8>) + Send + Sync + 'static,
    needle: &str,
) {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let proxy = tampered(tb as Arc<dyn Transport>, transform);
    std::thread::scope(|s| {
        let responder = s.spawn(move || {
            accept(CODE, &ib, proxy)
                .err()
                .map(|error| error.to_string())
        });
        let initiator = pair(CODE, &ia, ta as Arc<dyn Transport>);
        let responder_err = responder
            .join()
            .expect("responder thread")
            .expect("responder must fail");
        assert!(responder_err.contains(needle), "{responder_err}");
        let initiator_err = initiator.err().expect("initiator must fail").to_string();
        assert!(initiator_err.contains("aborted"), "{initiator_err}");
    });
}

#[test]
fn handshake_rejects_truncated_confirm_frame() {
    handshake_with_tampered_confirm(
        |frame| {
            if frame.first() == Some(&FRAME_CONFIRM_A) {
                frame.truncate(1);
            }
        },
        "frame too short",
    );
}

#[test]
fn handshake_rejects_mistyped_confirm_frame() {
    handshake_with_tampered_confirm(
        |frame| {
            if frame.first() == Some(&FRAME_CONFIRM_A) {
                *frame = vec![0x7A, 0x01];
            }
        },
        "expected cA frame",
    );
}

#[test]
fn handshake_rejects_truncated_identity_frame() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let proxy = tampered(tb as Arc<dyn Transport>, |frame| {
        if frame.first() == Some(&FRAME_IDENTITY_A) {
            frame.truncate(3);
        }
    });
    std::thread::scope(|s| {
        let responder = s.spawn(move || {
            accept(CODE, &ib, proxy)
                .err()
                .map(|error| error.to_string())
        });
        // The initiator's own identity frame is untouched, so its handshake
        // completes; only the responder sees a truncated identity frame.
        let initiator = pair(CODE, &ia, ta as Arc<dyn Transport>).expect("initiator pairing");
        let responder_err = responder
            .join()
            .expect("responder thread")
            .expect("responder must fail");
        assert!(
            responder_err.contains("identity frame too short"),
            "{responder_err}"
        );
        assert!(!initiator.is_invalidated());
    });
}

#[test]
fn corrupted_identity_signatures_fail_the_handshake_on_both_sides() {
    let (ta, tb) = MemoryTransport::pair();
    let ia = DeviceIdentity::generate();
    let ib = DeviceIdentity::generate();
    let flip = |frame: &mut Vec<u8>| flip_identity_signature(frame);
    let proxy_a = tampered(ta as Arc<dyn Transport>, flip);
    let proxy_b = tampered(tb as Arc<dyn Transport>, flip);
    std::thread::scope(|s| {
        let responder = s.spawn(move || accept(CODE, &ib, proxy_b));
        let initiator = pair(CODE, &ia, proxy_a);
        let initiator_err = match initiator {
            Ok(_) => panic!("corrupted identity must fail the initiator handshake"),
            Err(error) => error.to_string(),
        };
        let responder_err = responder
            .join()
            .expect("responder thread")
            .err()
            .expect("responder must fail");
        assert!(
            initiator_err.to_string().contains("identity"),
            "{initiator_err}"
        );
        assert!(
            responder_err.to_string().contains("identity"),
            "{responder_err}"
        );
    });
}

#[test]
fn handshake_rejects_corrupted_confirm_frame() {
    // A well-formed but wrong confirmation proves the code mismatch (wrong
    // password or active MITM) and must abort instead of completing.
    handshake_with_tampered_confirm(
        |frame| {
            if frame.first() == Some(&FRAME_CONFIRM_A) && frame.len() == 34 {
                let last = frame.len() - 1;
                frame[last] ^= 0xFF;
            }
        },
        "key confirmation failed",
    );
}
