//! The non-blocking pairing driver (todo.md DSR-25): the SPAKE2 + identity
//! exchange of [`crate::pairing`] sequenced as a push/pull state machine an
//! external event loop can drive one frame at a time — a WebSocket reader,
//! a GUI loop, an FFI host — without blocking anywhere and without
//! duplicating any cryptographic step.
//!
//! The shape, for an event loop:
//!
//! ```ignore
//! let mut driver = PairingDriver::initiator(&code, &identity, transport)?;
//! loop {
//!     // 1. Everything the machine wants on the wire.
//!     while let Some(frame) = driver.pop_outgoing() { wire.send(frame).await; }
//!     // 2. Done, or failed (with one abort frame queued for the wire).
//!     match driver.poll() {
//!         Some(DriverEvent::Completed(session)) => break Ok(session),
//!         Some(DriverEvent::Failed(error)) => break Err(error),
//!         None => {}
//!     }
//!     // 3. The only wait in the whole pairing is the host's own.
//!     let frame = wire.recv().await;
//!     driver.push(&frame)?;
//! }
//! ```
//!
//! Ownership of the protocol lives in exactly one place: the state machine
//! below calls [`crate::pairing_spake2`] and [`crate::pairing`]'s frame
//! helpers, and the blocking [`crate::pairing::pair`]/[`crate::pairing::accept`]
//! are pumps over this same machine, so the two entry points cannot drift.
//!
//! Failure behavior mirrors the blocking path: any protocol violation
//! (wrong type, wrong version, oversize frame, peer abort, failed key
//! confirmation) fails the driver, queues exactly one abort frame for the
//! wire, and reports [`DriverEvent::Failed`] once. A host that gives up for
//! transport reasons queues the same goodbye itself via
//! [`PairingDriver::abort`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::identity::{DeviceIdentity, PublicIdentity};
use crate::pairing::{
    check_version, frame_bytes, identity_payload, parse_identity_payload, PairingError,
    PairingSession, Role, FRAME_ABORT, FRAME_CONFIRM_A, FRAME_CONFIRM_B, FRAME_IDENTITY_A,
    FRAME_IDENTITY_B, FRAME_P_A, FRAME_P_B, MAX_FRAME_BYTES,
};
use crate::pairing_spake2::{Spake2Initiator, Spake2Responder, Spake2Secrets};
use crate::transport::Transport;

/// What a poll found. `Completed` hands over the session; `Failed` ends the
/// exchange (the abort frame for the peer is already in the outbox). Each
/// event is delivered exactly once; afterwards the driver refuses input.
/// Not `Debug`: a session holds live keys, and a debug print must never be
/// the thing that leaks them.
#[allow(clippy::large_enum_variant)] // delivered one at a time, never stored
pub enum DriverEvent {
    Completed(PairingSession),
    Failed(PairingError),
}

/// The exchange stages, per role. Variants hold exactly the SPAKE2 state
/// the next step needs; nothing is ever recomputed or re-derived.
enum Stage {
    /// pA is in the outbox; pB is owed.
    InitiatorWaitPb(Spake2Initiator),
    /// pB processed, cA sent; cB is owed. The initiator stays around for
    /// the confirmation check, the secrets for the transcript.
    InitiatorWaitCb(Spake2Initiator, Spake2Secrets),
    /// cB verified, identity sent; the peer's signed identity is owed.
    InitiatorWaitIdentityB(Spake2Secrets),
    /// The peer's pA is owed before anything can be derived.
    ResponderWaitPa,
    /// pA processed, pB sent; cA is owed. The responder stays for the cA
    /// check; `confirm_b` is what goes out once cA verifies.
    ResponderWaitCa(Spake2Responder, Spake2Secrets, [u8; 32]),
    /// cA verified, cB and identity sent; the peer's signed identity is owed.
    ResponderWaitIdentityA(Spake2Secrets),
    /// Terminal: `event` holds the one and only outcome.
    Done,
}

/// One pairing exchange, driven from outside. See the module docs.
pub struct PairingDriver {
    role: Role,
    code: String,
    identity: DeviceIdentity,
    transport: Arc<dyn Transport>,
    outbox: VecDeque<Vec<u8>>,
    stage: Stage,
    /// The terminal outcome; `poll` takes it.
    event: Option<DriverEvent>,
    /// Set the moment an abort frame is queued, so a failure and a later
    /// explicit [`PairingDriver::abort`] never put two on the wire.
    abort_queued: bool,
    /// True from the terminal transition on: pushes are refused.
    finished: AtomicBool,
}

impl PairingDriver {
    /// The side that shows the code and sends the first frame.
    ///
    /// The code is format-checked and normalized here, exactly as the
    /// blocking [`crate::pairing::pair`] has always done, so a mistyped
    /// code fails before any frame exists and a lower-case entry pairs
    /// with the upper-case issued one. The first frame (pA) is already in
    /// the outbox when this returns.
    pub fn initiator(
        code: &str,
        identity: &DeviceIdentity,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, PairingError> {
        let code = crate::codes::PairingCodeBoard::normalize(code).map_err(PairingError::Code)?;
        let mut initiator = Spake2Initiator::new(code.as_bytes());
        let p_a = initiator.generate_message();
        Ok(Self {
            role: Role::Initiator,
            code,
            identity: identity.clone(),
            transport,
            outbox: VecDeque::from([frame_bytes(FRAME_P_A, &p_a)]),
            stage: Stage::InitiatorWaitPb(initiator),
            event: None,
            abort_queued: false,
            finished: AtomicBool::new(false),
        })
    }

    /// The side that types the code in. Nothing goes on the wire until the
    /// peer's pA arrives.
    pub fn responder(
        code: &str,
        identity: &DeviceIdentity,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, PairingError> {
        let code = crate::codes::PairingCodeBoard::normalize(code).map_err(PairingError::Code)?;
        Ok(Self {
            role: Role::Responder,
            code,
            identity: identity.clone(),
            transport,
            outbox: VecDeque::new(),
            stage: Stage::ResponderWaitPa,
            event: None,
            abort_queued: false,
            finished: AtomicBool::new(false),
        })
    }

    /// The role this driver plays, for hosts that route by side.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Feed one frame received from the wire. Ok even when the frame is a
    /// protocol violation — the violation becomes [`DriverEvent::Failed`]
    /// plus one queued abort frame, so the host's drain-send-poll loop
    /// delivers the goodbye without special-casing. Err means the driver
    /// was already finished: the frame arrived too late, which is a host
    /// bug, not a peer one.
    pub fn push(&mut self, frame: &[u8]) -> Result<(), PairingError> {
        if self.finished.load(Ordering::SeqCst) {
            return Err(PairingError::Protocol(
                "pairing already finished: late frame refused".into(),
            ));
        }
        if let Err(error) = self.advance(frame) {
            self.fail(error);
        }
        Ok(())
    }

    /// Take the next frame to put on the wire, if any.
    pub fn pop_outgoing(&mut self) -> Option<Vec<u8>> {
        self.outbox.pop_front()
    }

    /// Report the terminal event once: the session, or the failure. `None`
    /// means the exchange needs more input — keep looping.
    pub fn poll(&mut self) -> Option<DriverEvent> {
        self.event.take()
    }

    /// Queue the goodbye frame (best effort, once). A host calls this when
    /// *it* gives up for transport reasons; a protocol failure has already
    /// queued exactly one, and a completed pairing never sends one.
    pub fn abort(&mut self) {
        if self.abort_queued || self.finished.load(Ordering::SeqCst) {
            return;
        }
        self.outbox.push_back(frame_bytes(FRAME_ABORT, &[]));
        self.abort_queued = true;
    }

    /// Whether a terminal event is still waiting in `poll`.
    pub fn has_event(&self) -> bool {
        self.event.is_some()
    }

    /// Run one step of the machine; a protocol error here ends the driver.
    /// The drain-and-refuse discipline is the blocking path's: oversize
    /// first, peer abort second, expected type third, version last.
    fn advance(&mut self, frame: &[u8]) -> Result<(), PairingError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(PairingError::Protocol(format!(
                "frame too large: {} bytes (max {MAX_FRAME_BYTES})",
                frame.len()
            )));
        }
        if frame.first() == Some(&FRAME_ABORT) {
            return Err(PairingError::Protocol("peer aborted the pairing".into()));
        }
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::InitiatorWaitPb(initiator) => {
                let payload = expect_payload(frame, FRAME_P_B, "pB")?;
                let (secrets, confirm_a) = initiator.process_response(&payload)?;
                self.outbox
                    .push_back(frame_bytes(FRAME_CONFIRM_A, &confirm_a));
                self.stage = Stage::InitiatorWaitCb(initiator, secrets);
                Ok(())
            }
            Stage::InitiatorWaitCb(initiator, secrets) => {
                let payload = expect_payload(frame, FRAME_CONFIRM_B, "cB")?;
                let confirm_b: [u8; 32] = payload
                    .try_into()
                    .map_err(|_| PairingError::Protocol("cB must be 32 bytes".into()))?;
                initiator.verify_confirmation(&secrets, &confirm_b)?;
                self.outbox.push_back(frame_bytes(
                    FRAME_IDENTITY_A,
                    &identity_payload(&self.identity, "initiator", &secrets.transcript),
                ));
                self.stage = Stage::InitiatorWaitIdentityB(secrets);
                Ok(())
            }
            Stage::InitiatorWaitIdentityB(secrets) => {
                let payload = expect_payload(frame, FRAME_IDENTITY_B, "identity(B)")?;
                let peer = parse_identity_payload(&payload, "responder", &secrets.transcript)?;
                self.complete(peer, &secrets.ke);
                Ok(())
            }
            Stage::ResponderWaitPa => {
                let payload = expect_payload(frame, FRAME_P_A, "pA")?;
                let mut responder = Spake2Responder::new(self.code.as_bytes());
                let (p_b, secrets, confirm_b) = responder.process_intro(&payload)?;
                self.outbox.push_back(frame_bytes(FRAME_P_B, &p_b));
                self.stage = Stage::ResponderWaitCa(responder, secrets, confirm_b);
                Ok(())
            }
            Stage::ResponderWaitCa(responder, secrets, confirm_b) => {
                let payload = expect_payload(frame, FRAME_CONFIRM_A, "cA")?;
                let confirm_a: [u8; 32] = payload
                    .try_into()
                    .map_err(|_| PairingError::Protocol("cA must be 32 bytes".into()))?;
                responder.verify_confirmation(&secrets, &confirm_a)?;
                // cB and the responder identity ride together, exactly as
                // the blocking path sent them after cA verified.
                self.outbox
                    .push_back(frame_bytes(FRAME_CONFIRM_B, &confirm_b));
                self.outbox.push_back(frame_bytes(
                    FRAME_IDENTITY_B,
                    &identity_payload(&self.identity, "responder", &secrets.transcript),
                ));
                self.stage = Stage::ResponderWaitIdentityA(secrets);
                Ok(())
            }
            Stage::ResponderWaitIdentityA(secrets) => {
                let payload = expect_payload(frame, FRAME_IDENTITY_A, "identity(A)")?;
                let peer = parse_identity_payload(&payload, "initiator", &secrets.transcript)?;
                self.complete(peer, &secrets.ke);
                Ok(())
            }
            Stage::Done => Err(PairingError::Protocol(
                "pairing already finished: late frame refused".into(),
            )),
        }
    }

    fn complete(&mut self, peer: PublicIdentity, ke: &[u8; 16]) {
        let session =
            PairingSession::new(&self.identity, peer, self.role, ke, self.transport.clone());
        self.stage = Stage::Done;
        self.finished.store(true, Ordering::SeqCst);
        self.event = Some(DriverEvent::Completed(session));
    }

    fn fail(&mut self, error: PairingError) {
        if !self.abort_queued {
            self.outbox.push_back(frame_bytes(FRAME_ABORT, &[]));
            self.abort_queued = true;
        }
        self.stage = Stage::Done;
        self.finished.store(true, Ordering::SeqCst);
        self.event = Some(DriverEvent::Failed(error));
    }
}

/// The frame-shape checks every stage shares: type, version, payload slice.
/// Mirrors the blocking path's per-frame validation.
fn expect_payload(frame: &[u8], want: u8, what: &str) -> Result<Vec<u8>, PairingError> {
    if frame.first() != Some(&want) {
        return Err(PairingError::Protocol(format!(
            "expected {what} frame, got type 0x{:02x}",
            frame.first().copied().unwrap_or(0)
        )));
    }
    check_version(frame)?;
    Ok(frame[2..].to_vec())
}
