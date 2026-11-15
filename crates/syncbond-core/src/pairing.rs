//! Pairing orchestration: turn a shared short display code into an
//! authenticated, encrypted session plus a sync group.
//!
//! Frame layout on the wire: [type: u8][protocol_version: u8][payload].
//!   0x01 pA, 0x02 pB, 0x03 cA, 0x04 cB, 0x05 identity(A),
//!   0x06 identity(B), 0x07 abort, 0x08 application envelope (JSON).
//! Order per RFC 9382 §3.1: pA, pB, cA, cB — then identity exchange with
//! signatures bound to the transcript hash. Full requirements and the
//! SPAKE2/RFC 9382 selection live in docs/design/PROTOCOL.md.

use crate::codes::{CodeError, PairingCodeBoard};
use crate::crypto::{self, KeyRing, SessionKey, PROTOCOL_VERSION};
use crate::identity::{group_id_from_public_keys, DeviceIdentity, PublicIdentity};
use crate::pairing_spake2::Spake2Error;
use crate::transport::{Transport, TransportError};
use ed25519_dalek::Signature;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub(crate) const FRAME_P_A: u8 = 0x01;
pub(crate) const FRAME_P_B: u8 = 0x02;
pub(crate) const FRAME_CONFIRM_A: u8 = 0x03;
pub(crate) const FRAME_CONFIRM_B: u8 = 0x04;
pub(crate) const FRAME_IDENTITY_A: u8 = 0x05;
pub(crate) const FRAME_IDENTITY_B: u8 = 0x06;
pub(crate) const FRAME_ABORT: u8 = 0x07;
pub(crate) const FRAME_APP: u8 = 0x08;

const SESSION_KEY_INFO: &[u8] = b"syncbond/v1/session-key";
/// Epoch used for envelopes inside a freshly paired session; epoch rotation
/// afterwards is the application's job via `KeyRing::rotate`.
pub const SESSION_EPOCH: u64 = 1;
/// Upper bound on a received frame (app envelope JSON included). Far above
/// any legitimate payload; a hostile authenticated peer's oversized frame
/// becomes a clean protocol error instead of an unbounded decode.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Conservative plaintext bound used to reject obvious over-sized sends
/// before encryption. Frame encoding adds envelope metadata, a 16-byte tag,
/// and base64url expansion, so for this protocol's fixed id lengths the
/// largest plaintext that can still fit in a `MAX_FRAME_BYTES` frame is
/// 12,582,728 bytes (~11.9998 MiB). Any plaintext at or above this hint is
/// guaranteed to be rejected by the exact `MAX_FRAME_BYTES` check below, so
/// rejecting here avoids paying the seal + JSON cost for payloads that cannot
/// possibly fit.
const MAX_PLAINTEXT_HINT_BYTES: usize = 12 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum PairingError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("spake2: {0}")]
    Spake2(#[from] Spake2Error),
    #[error("identity: {0}")]
    Identity(#[from] crate::identity::IdentityError),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("pairing code: {0}")]
    Code(#[from] CodeError),
    #[error("{0}")]
    Protocol(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// An authenticated, encrypted pairing session ready to replicate.
pub struct PairingSession {
    pub device_id: String,
    pub peer_identity: PublicIdentity,
    pub group_id: String,
    pub session_key: SessionKey,
    pub keyring: KeyRing,
    pub role: Role,
    transport: Arc<dyn Transport>,
    seen_message_ids: Mutex<HashSet<String>>,
    invalidated: AtomicBool,
}

impl PairingSession {
    /// Assemble a session from a completed exchange. Crate-internal: the
    /// blocking [`pair`]/[`accept`] and the non-blocking
    /// [`crate::pairing_driver::PairingDriver`] both end here, so a session
    /// always carries a live transport, a fresh replay set, and no
    /// invalidation.
    pub(crate) fn new(
        identity: &DeviceIdentity,
        peer_identity: PublicIdentity,
        role: Role,
        ke: &[u8; 16],
        transport: Arc<dyn Transport>,
    ) -> Self {
        let group_id = group_id_from_public_keys(&[identity.public_key, peer_identity.public_key]);
        Self {
            device_id: identity.device_id.clone(),
            peer_identity,
            group_id: group_id.clone(),
            session_key: session_key_from(ke),
            keyring: KeyRing::new(group_id),
            role,
            transport,
            seen_message_ids: Mutex::new(HashSet::new()),
            invalidated: AtomicBool::new(false),
        }
    }

    /// Encrypt and send an application payload over the session channel.
    pub fn seal_and_send(&self, plaintext: &[u8]) -> Result<(), PairingError> {
        self.assert_live()?;
        // Reject at/above the hint before sealing or allocating. For this
        // protocol's fixed id lengths (24-hex group, 16-hex device, 32-hex
        // message id, b64url nonce/tag) the largest plaintext that can still
        // fit in a MAX_FRAME_BYTES frame is 12,582,728 bytes (~11.9998 MiB);
        // a 12 MiB plaintext always expands past the cap. So any plaintext at
        // or above the 12 MiB hint is guaranteed to be rejected by the exact
        // post-encode check below anyway, and rejecting here avoids paying the
        // full seal + JSON cost for payloads that cannot possibly fit. The
        // narrow band just under the hint (a few hundred bytes) is caught by
        // the exact post-encode check.
        if plaintext.len() >= MAX_PLAINTEXT_HINT_BYTES {
            return Err(PairingError::Protocol(format!(
                "frame too large: plaintext {} bytes exceeds max frame {MAX_FRAME_BYTES}",
                plaintext.len()
            )));
        }
        let envelope = crypto::seal(
            &self.session_key,
            &self.group_id,
            &self.device_id,
            SESSION_EPOCH,
            plaintext,
        );
        let mut frame = vec![FRAME_APP, PROTOCOL_VERSION as u8];
        frame.extend_from_slice(
            &serde_json::to_vec(&envelope)
                .map_err(|e| PairingError::Protocol(format!("envelope encoding: {e}")))?,
        );
        if frame.len() > MAX_FRAME_BYTES {
            return Err(PairingError::Protocol(format!(
                "frame too large: {} bytes (max {MAX_FRAME_BYTES})",
                frame.len()
            )));
        }
        self.transport.send(&frame)?;
        Ok(())
    }

    /// Receive the next application payload, verifying and opening its
    /// envelope (version, group, epoch, replay, and AEAD checks all apply).
    pub fn recv_and_open(&self) -> Result<Vec<u8>, PairingError> {
        self.assert_live()?;
        let frame = self.transport.recv()?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err(PairingError::Protocol(format!(
                "frame too large: {} bytes (max {MAX_FRAME_BYTES})",
                frame.len()
            )));
        }
        if frame.len() < 2 || frame[0] != FRAME_APP {
            return Err(PairingError::Protocol(format!(
                "expected application frame, got type 0x{:02x}",
                frame.first().copied().unwrap_or(0)
            )));
        }
        check_version(&frame)?;
        let envelope: crypto::EncryptedEnvelope = serde_json::from_slice(&frame[2..])
            .map_err(|e| PairingError::Protocol(format!("envelope decoding: {e}")))?;
        let mut seen = self
            .seen_message_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let plaintext = crypto::open(
            &self.session_key,
            &envelope,
            &mut crypto::EnvelopeContext {
                group_id: &self.group_id,
                current_key_epoch: SESSION_EPOCH,
                seen_message_ids: &mut seen,
            },
        )?;
        Ok(plaintext)
    }

    /// Invalidate the session: further sends/receives are refused. A replay
    /// of a previously captured frame therefore cannot revive it.
    pub fn invalidate(&self) {
        self.invalidated.store(true, Ordering::SeqCst);
    }

    pub fn is_invalidated(&self) -> bool {
        self.invalidated.load(Ordering::SeqCst)
    }

    fn assert_live(&self) -> Result<(), PairingError> {
        if self.invalidated.load(Ordering::SeqCst) {
            Err(PairingError::Protocol("session invalidated".into()))
        } else {
            Ok(())
        }
    }
}

pub(crate) fn check_version(frame: &[u8]) -> Result<(), PairingError> {
    match frame.get(1) {
        Some(&v) if u16::from(v) == PROTOCOL_VERSION => Ok(()),
        Some(&v) => Err(PairingError::Protocol(format!(
            "protocol version mismatch: peer sent {v}, we speak {PROTOCOL_VERSION}"
        ))),
        None => Err(PairingError::Protocol("frame too short".into())),
    }
}

pub(crate) fn frame_bytes(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 2);
    frame.push(kind);
    frame.push(PROTOCOL_VERSION as u8);
    frame.extend_from_slice(payload);
    frame
}

/// Identity frame payload: JSON public identity || 64-byte signature.
pub(crate) fn identity_payload(
    identity: &DeviceIdentity,
    role: &str,
    transcript: &[u8],
) -> Vec<u8> {
    let public = PublicIdentity::from(identity);
    let mut payload = serde_json::to_vec(&public).expect("public identity serialization");
    payload.extend_from_slice(&identity.sign_transcript(role, transcript).to_bytes());
    payload
}

pub(crate) fn parse_identity_payload(
    payload: &[u8],
    role: &str,
    transcript: &[u8],
) -> Result<PublicIdentity, PairingError> {
    if payload.len() < 65 {
        return Err(PairingError::Protocol("identity frame too short".into()));
    }
    let (json, sig_bytes) = payload.split_at(payload.len() - 64);
    let public: PublicIdentity = serde_json::from_slice(json)
        .map_err(|e| PairingError::Protocol(format!("identity decoding: {e}")))?;
    let sig = Signature::from_bytes(sig_bytes.try_into().expect("64 bytes"));
    public
        .verify_transcript(role, transcript, &sig)
        .map_err(PairingError::Identity)?;
    Ok(public)
}

pub(crate) fn session_key_from(ke: &[u8; 16]) -> SessionKey {
    let hk = Hkdf::<Sha256>::new(None, ke);
    let mut key = [0u8; 32];
    hk.expand(SESSION_KEY_INFO, &mut key)
        .expect("32 bytes is a valid HKDF length");
    key
}

/// Initiator side: display a code, connect a transport, pair against the
/// peer running `accept()` with the same code.
///
/// Throws when the codes differ (key confirmation fails), when the peer
/// speaks a different protocol version, or when identity signatures do not
/// verify. On any failure an abort frame is sent so the peer does not wait
/// forever.
///
/// The protocol sequencing lives in [`crate::pairing_driver`]; this is the
/// blocking pump over it, for callers whose event loop is a thread.
pub fn pair(
    code: &str,
    identity: &DeviceIdentity,
    transport: Arc<dyn Transport>,
) -> Result<PairingSession, PairingError> {
    let driver =
        crate::pairing_driver::PairingDriver::initiator(code, identity, transport.clone())?;
    pump_to_completion(driver, &transport)
}

/// Responder side: type in the code shown by the peer.
pub fn accept(
    code: &str,
    identity: &DeviceIdentity,
    transport: Arc<dyn Transport>,
) -> Result<PairingSession, PairingError> {
    let driver =
        crate::pairing_driver::PairingDriver::responder(code, identity, transport.clone())?;
    pump_to_completion(driver, &transport)
}

/// Responder side behind the code board's policy (todo.md DSR-26): the gate
/// ([`PairingCodeBoard::admit`]) runs before any frame exists, so a code
/// that is malformed, unknown, expired, consumed, or locked by failed
/// attempts never starts an exchange; a completed pairing consumes the
/// code (single use); a wire-level failure burns one attempt against the
/// window. A transport error — a flaky network, not a guess — burns
/// nothing and leaves the window open.
pub fn accept_gated(
    board: &mut PairingCodeBoard,
    code: &str,
    identity: &DeviceIdentity,
    transport: Arc<dyn Transport>,
) -> Result<PairingSession, PairingError> {
    let normalized = board.admit(code)?;
    match accept(&normalized, identity, transport) {
        Ok(session) => {
            board.consume(&normalized)?;
            Ok(session)
        }
        Err(error @ PairingError::Transport(_)) => Err(error),
        Err(error) => {
            let _ = board.register_failure(&normalized);
            Err(error)
        }
    }
}

/// Drive a pairing driver to completion over a blocking transport: drain
/// the outbox, await one frame, feed it, repeat. The event-loop contract
/// ([`crate::pairing_driver`]) blocks nowhere; this pump blocks exactly
/// where the old `pair`/`accept` did.
fn pump_to_completion(
    mut driver: crate::pairing_driver::PairingDriver,
    transport: &Arc<dyn Transport>,
) -> Result<PairingSession, PairingError> {
    let result = (|| loop {
        while let Some(frame) = driver.pop_outgoing() {
            transport.send(&frame)?;
        }
        match driver.poll() {
            Some(crate::pairing_driver::DriverEvent::Completed(session)) => return Ok(session),
            Some(crate::pairing_driver::DriverEvent::Failed(error)) => return Err(error),
            None => {}
        }
        let frame = transport.recv()?;
        driver.push(&frame)?;
    })();
    if result.is_err() {
        // The best-effort goodbye the old pair/accept always attempted;
        // `abort` does not double-queue after a protocol failure, which
        // already queued exactly one abort frame.
        driver.abort();
        while let Some(frame) = driver.pop_outgoing() {
            let _ = transport.send(&frame);
        }
    }
    result
}
