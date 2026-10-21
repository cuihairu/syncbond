//! Pairing orchestration: turn a shared short display code into an
//! authenticated, encrypted session plus a sync group.
//!
//! Frame layout on the wire: [type: u8][protocol_version: u8][payload].
//!   0x01 pA, 0x02 pB, 0x03 cA, 0x04 cB, 0x05 identity(A),
//!   0x06 identity(B), 0x07 abort, 0x08 application envelope (JSON).
//! Order per RFC 9382 §3.1: pA, pB, cA, cB — then identity exchange with
//! signatures bound to the transcript hash. Full requirements and the
//! SPAKE2/RFC 9382 selection live in docs/design/PROTOCOL.md.

use crate::crypto::{self, KeyRing, SessionKey, PROTOCOL_VERSION};
use crate::identity::{group_id_from_public_keys, DeviceIdentity, PublicIdentity};
use crate::pairing_spake2::{Spake2Error, Spake2Initiator, Spake2Responder};
use crate::transport::{Transport, TransportError};
use ed25519_dalek::Signature;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;

const FRAME_P_A: u8 = 0x01;
const FRAME_P_B: u8 = 0x02;
const FRAME_CONFIRM_A: u8 = 0x03;
const FRAME_CONFIRM_B: u8 = 0x04;
const FRAME_IDENTITY_A: u8 = 0x05;
const FRAME_IDENTITY_B: u8 = 0x06;
const FRAME_ABORT: u8 = 0x07;
const FRAME_APP: u8 = 0x08;

const SESSION_KEY_INFO: &[u8] = b"syncbond/v1/session-key";
/// Epoch used for envelopes inside a freshly paired session; epoch rotation
/// afterwards is the application's job via `KeyRing::rotate`.
pub const SESSION_EPOCH: u64 = 1;

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
    /// Encrypt and send an application payload over the session channel.
    pub fn seal_and_send(&self, plaintext: &[u8]) -> Result<(), PairingError> {
        self.assert_live()?;
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
        self.transport.send(&frame)?;
        Ok(())
    }

    /// Receive the next application payload, verifying and opening its
    /// envelope (version, group, epoch, replay, and AEAD checks all apply).
    pub fn recv_and_open(&self) -> Result<Vec<u8>, PairingError> {
        self.assert_live()?;
        let frame = self.transport.recv()?;
        if frame.len() < 2 || frame[0] != FRAME_APP {
            return Err(PairingError::Protocol(format!(
                "expected application frame, got type 0x{:02x}",
                frame.first().copied().unwrap_or(0)
            )));
        }
        check_version(&frame)?;
        let envelope: crypto::EncryptedEnvelope = serde_json::from_slice(&frame[2..])
            .map_err(|e| PairingError::Protocol(format!("envelope decoding: {e}")))?;
        let mut seen = self.seen_message_ids.lock().unwrap();
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

fn check_version(frame: &[u8]) -> Result<(), PairingError> {
    match frame.get(1) {
        Some(&v) if u16::from(v) == PROTOCOL_VERSION => Ok(()),
        Some(&v) => Err(PairingError::Protocol(format!(
            "protocol version mismatch: peer sent {v}, we speak {PROTOCOL_VERSION}"
        ))),
        None => Err(PairingError::Protocol("frame too short".into())),
    }
}

fn frame_bytes(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 2);
    frame.push(kind);
    frame.push(PROTOCOL_VERSION as u8);
    frame.extend_from_slice(payload);
    frame
}

fn expect_frame(
    transport: &Arc<dyn Transport>,
    want: u8,
    what: &str,
) -> Result<Vec<u8>, PairingError> {
    let frame = transport.recv()?;
    if frame.first() == Some(&FRAME_ABORT) {
        return Err(PairingError::Protocol("peer aborted the pairing".into()));
    }
    if frame.first() != Some(&want) {
        return Err(PairingError::Protocol(format!(
            "expected {what} frame, got type 0x{:02x}",
            frame.first().copied().unwrap_or(0)
        )));
    }
    check_version(&frame)?;
    Ok(frame[2..].to_vec())
}

fn abort_quietly(transport: &Arc<dyn Transport>) {
    let _ = transport.send(&frame_bytes(FRAME_ABORT, &[]));
}

/// Identity frame payload: JSON public identity || 64-byte signature.
fn identity_payload(identity: &DeviceIdentity, role: &str, transcript: &[u8]) -> Vec<u8> {
    let public = PublicIdentity::from(identity);
    let mut payload = serde_json::to_vec(&public).expect("public identity serialization");
    payload.extend_from_slice(&identity.sign_transcript(role, transcript).to_bytes());
    payload
}

fn parse_identity_payload(
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

fn session_key_from(ke: &[u8; 16]) -> SessionKey {
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
pub fn pair(
    code: &str,
    identity: &DeviceIdentity,
    transport: Arc<dyn Transport>,
) -> Result<PairingSession, PairingError> {
    let result = pair_inner(code, identity, &transport);
    if result.is_err() {
        abort_quietly(&transport);
    }
    result
}

fn pair_inner(
    code: &str,
    identity: &DeviceIdentity,
    transport: &Arc<dyn Transport>,
) -> Result<PairingSession, PairingError> {
    crate::codes::PairingCodeBoard::validate_format(code)
        .map_err(|e| PairingError::Protocol(format!("pairing code format: {e}")))?;
    let mut initiator = Spake2Initiator::new(code.as_bytes());
    transport.send(&frame_bytes(FRAME_P_A, &initiator.generate_message()))?;

    let p_b = expect_frame(transport, FRAME_P_B, "pB")?;
    let (secrets, confirm_a) = initiator.process_response(&p_b)?;
    transport.send(&frame_bytes(FRAME_CONFIRM_A, &confirm_a))?;

    let confirm_b: [u8; 32] = expect_frame(transport, FRAME_CONFIRM_B, "cB")?
        .try_into()
        .map_err(|_| PairingError::Protocol("cB must be 32 bytes".into()))?;
    initiator.verify_confirmation(&secrets, &confirm_b)?;

    transport.send(&frame_bytes(
        FRAME_IDENTITY_A,
        &identity_payload(identity, "initiator", &secrets.transcript),
    ))?;
    let peer = parse_identity_payload(
        &expect_frame(transport, FRAME_IDENTITY_B, "identity(B)")?,
        "responder",
        &secrets.transcript,
    )?;

    let group_id = group_id_from_public_keys(&[identity.public_key, peer.public_key]);
    Ok(PairingSession {
        device_id: identity.device_id.clone(),
        peer_identity: peer,
        group_id: group_id.clone(),
        session_key: session_key_from(&secrets.ke),
        keyring: KeyRing::new(group_id),
        role: Role::Initiator,
        transport: transport.clone(),
        seen_message_ids: Mutex::new(HashSet::new()),
        invalidated: AtomicBool::new(false),
    })
}

/// Responder side: type in the code shown by the peer.
pub fn accept(
    code: &str,
    identity: &DeviceIdentity,
    transport: Arc<dyn Transport>,
) -> Result<PairingSession, PairingError> {
    let result = accept_inner(code, identity, &transport);
    if result.is_err() {
        abort_quietly(&transport);
    }
    result
}

fn accept_inner(
    code: &str,
    identity: &DeviceIdentity,
    transport: &Arc<dyn Transport>,
) -> Result<PairingSession, PairingError> {
    crate::codes::PairingCodeBoard::validate_format(code)
        .map_err(|e| PairingError::Protocol(format!("pairing code format: {e}")))?;
    let p_a = expect_frame(transport, FRAME_P_A, "pA")?;
    let mut responder = Spake2Responder::new(code.as_bytes());
    let (p_b, secrets, confirm_b) = responder.process_intro(&p_a)?;
    transport.send(&frame_bytes(FRAME_P_B, &p_b))?;

    let confirm_a: [u8; 32] = expect_frame(transport, FRAME_CONFIRM_A, "cA")?
        .try_into()
        .map_err(|_| PairingError::Protocol("cA must be 32 bytes".into()))?;
    responder.verify_confirmation(&secrets, &confirm_a)?;
    transport.send(&frame_bytes(FRAME_CONFIRM_B, &confirm_b))?;

    transport.send(&frame_bytes(
        FRAME_IDENTITY_B,
        &identity_payload(identity, "responder", &secrets.transcript),
    ))?;
    let peer = parse_identity_payload(
        &expect_frame(transport, FRAME_IDENTITY_A, "identity(A)")?,
        "initiator",
        &secrets.transcript,
    )?;

    let group_id = group_id_from_public_keys(&[identity.public_key, peer.public_key]);
    Ok(PairingSession {
        device_id: identity.device_id.clone(),
        peer_identity: peer,
        group_id: group_id.clone(),
        session_key: session_key_from(&secrets.ke),
        keyring: KeyRing::new(group_id),
        role: Role::Responder,
        transport: transport.clone(),
        seen_message_ids: Mutex::new(HashSet::new()),
        invalidated: AtomicBool::new(false),
    })
}
