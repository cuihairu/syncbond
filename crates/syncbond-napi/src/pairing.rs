use crate::napi_error;
use napi::Result;
use napi_derive::napi;
use std::sync::Arc;
use syncbond_core::{
    codes::generate_code,
    identity::DeviceIdentity,
    pairing::{accept, pair, PairingSession},
    transport::{MemoryTransport, Transport},
};

/// Both authenticated sessions produced by one pairing handshake.
#[napi]
pub struct NativePairingResult {
    initiator: Arc<PairingSession>,
    responder: Arc<PairingSession>,
    code: String,
}

#[napi]
impl NativePairingResult {
    #[napi]
    pub fn initiator_session(&self) -> NativePairingSession {
        NativePairingSession::new(Arc::clone(&self.initiator))
    }

    #[napi]
    pub fn responder_session(&self) -> NativePairingSession {
        NativePairingSession::new(Arc::clone(&self.responder))
    }

    #[napi(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }
}

/// One authenticated, encrypted session end. Holds its end behind an `Arc`
/// so a sync exchange can keep using it across thread boundaries without
/// aliasing tricks.
#[napi]
pub struct NativePairingSession {
    inner: Arc<PairingSession>,
}

impl NativePairingSession {
    pub fn new(inner: Arc<PairingSession>) -> Self {
        Self { inner }
    }

    pub fn arc_clone(&self) -> Arc<PairingSession> {
        Arc::clone(&self.inner)
    }
}

#[napi]
impl NativePairingSession {
    #[napi(getter)]
    pub fn group_id(&self) -> String {
        self.inner.group_id.clone()
    }

    #[napi(getter)]
    pub fn peer_device_id(&self) -> String {
        self.inner.peer_identity.device_id.clone()
    }

    #[napi]
    pub fn invalidate(&self) {
        self.inner.invalidate();
    }

    #[napi(getter)]
    pub fn invalidated(&self) -> bool {
        self.inner.is_invalidated()
    }
}

/// Run the SPAKE2 pairing handshake over an in-memory loopback between two
/// freshly generated device identities. Blocking; the initiator side runs on
/// a worker thread while the responder runs on the calling thread.
#[napi]
#[allow(dead_code)] // reached through the generated N-API module export
pub fn pair_memory(code: Option<String>) -> Result<NativePairingResult> {
    let code = code.unwrap_or_else(generate_code);
    let (left_transport, right_transport) = MemoryTransport::pair();
    let left_identity = DeviceIdentity::generate();
    let right_identity = DeviceIdentity::generate();

    let left_code = code.clone();
    let left_handle = std::thread::spawn(move || {
        pair(
            &left_code,
            &left_identity,
            left_transport as Arc<dyn Transport>,
        )
    });
    let right_result = accept(
        &code,
        &right_identity,
        right_transport as Arc<dyn Transport>,
    );
    let left_result = left_handle
        .join()
        .map_err(|_| napi_error("pairing thread panicked"))?;

    Ok(NativePairingResult {
        initiator: Arc::new(left_result.map_err(napi_error)?),
        responder: Arc::new(right_result.map_err(napi_error)?),
        code,
    })
}
