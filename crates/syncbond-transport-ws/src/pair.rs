//! The public pairing entries, over a relay pairing room. The roles stay
//! straight by construction:
//!
//! - The **host** (device that created the room) holds the code board. It
//!   issues the code, shows it via `on_code` before any socket exists,
//!   then joins and pumps. Its settle discipline mirrors
//!   [`syncbond_core::pairing::accept_gated`]: a completed pairing
//!   consumes the code, a wire-level failure (`DriverEvent::Failed`)
//!   burns one attempt, a transport error (timeout, close, TLS, relay
//!   refusal) burns nothing.
//! - The **joiner** typed the code; the driver's constructor normalizes it
//!   exactly like the host's side, so a lower-case entry pairs with the
//!   upper-case issued one.
//!
//! SPAKE2 speaking order follows the greeting, not the entry names: the
//! participant that joined **first** is the responder (it waits — its
//! frames could not reach anyone anyway), the one that joined **second**
//! is the initiator. This stays deadlock-free whichever device starts
//! first, and it never moves the board: the host gates on the code
//! outcome whichever SPAKE2 role it ended up playing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use syncbond_core::codes::{PairingCodeBoard, PairingPolicy};
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::PairingSession;
use syncbond_core::pairing_driver::{DriverEvent, PairingDriver};
use syncbond_relay_protocol::dto::RoomCreated;

use crate::bridge::WsTransport;
use crate::error::WsPairingError;
use crate::options::{Invite, RelayLocation, WsPairingOptions};
use crate::{rest, room_ws};

/// Create a pairing room and return the invite facts (room id +
/// capability) to hand the joiner out-of-band. The capability is a secret
/// for the room's lifetime only; the short code never touches the relay.
pub async fn create_invite(options: &WsPairingOptions) -> Result<Invite, WsPairingError> {
    let location = RelayLocation::parse(&options.relay_url)?;
    let created: RoomCreated = rest::create_room(
        &location,
        &options.tls,
        Duration::from_millis(options.connect_timeout_ms),
    )
    .await?;
    Ok(Invite {
        room_id: created.room_id,
        capability: created.capability,
    })
}

/// Host entry: issue the code (shown through `on_code` before any socket
/// exists), join the room, run the exchange, settle the board. Returns
/// the completed session or the typed failure.
pub async fn pair_as_host(
    options: &WsPairingOptions,
    identity: &DeviceIdentity,
    invite: &Invite,
    mut on_code: impl FnMut(&str),
) -> Result<PairingSession, WsPairingError> {
    let location = RelayLocation::parse(&options.relay_url)?;
    let mut board = PairingCodeBoard::new(PairingPolicy::default());
    let code = board.issue();
    on_code(&code);

    let joined = room_ws::join_room(
        &location,
        &options.tls,
        invite,
        options.bridge_queue_frames,
        Duration::from_millis(options.connect_timeout_ms),
    )
    .await?;

    // The board's settle rules ride with the host regardless of which
    // SPAKE2 role the greeting handed it. The transport lives in an Arc:
    // the driver (and later the session) hold the sync face, the pump
    // drives the async face of the same instance.
    let transport = Arc::new(joined.transport);
    let driver = driver_for_role(&code, identity, transport.clone(), joined.peer_joined)?;
    // The settle discipline, accept_gated's shape pumped async: success
    // consumes the code, a protocol failure burns one attempt, a transport
    // error burns nothing (the window stays open for the real pairing).
    match pump_to_session(driver, &transport, options).await {
        Ok(session) => {
            board.consume(&code)?;
            Ok(session)
        }
        Err(error @ WsPairingError::Core(_)) => {
            let _ = board.register_failure(&code);
            Err(error)
        }
        Err(error) => Err(error),
    }
}

/// Joiner entry: join the room with the invite, run the exchange with the
/// typed code. No board here — the code was never issued through one.
pub async fn pair_as_joiner(
    options: &WsPairingOptions,
    identity: &DeviceIdentity,
    code: &str,
    invite: &Invite,
) -> Result<PairingSession, WsPairingError> {
    let location = RelayLocation::parse(&options.relay_url)?;
    let joined = room_ws::join_room(
        &location,
        &options.tls,
        invite,
        options.bridge_queue_frames,
        Duration::from_millis(options.connect_timeout_ms),
    )
    .await?;

    let transport = Arc::new(joined.transport);
    let driver = driver_for_role(code, identity, transport.clone(), joined.peer_joined)?;
    pump_to_session(driver, &transport, options).await
}

/// First joiner waits (responder), second speaks first (initiator). The
/// sync-face clone the driver (and then the session) holds points at the
/// same bridge instance the pump drives.
fn driver_for_role(
    code: &str,
    identity: &DeviceIdentity,
    transport: Arc<WsTransport>,
    peer_joined: bool,
) -> Result<PairingDriver, WsPairingError> {
    let sync_face: Arc<dyn syncbond_core::transport::Transport> = transport.clone();
    let driver = if peer_joined {
        PairingDriver::initiator(code, identity, sync_face)?
    } else {
        PairingDriver::responder(code, identity, sync_face)?
    };
    Ok(driver)
}

/// Drive the driver against the bridge until the session or the failure.
/// The only wait in the whole loop is the host's own `recv_async`; the
/// overall budget (`pairingTimeoutMs`) bounds it.
async fn pump_to_session(
    mut driver: PairingDriver,
    transport: &WsTransport,
    options: &WsPairingOptions,
) -> Result<PairingSession, WsPairingError> {
    let deadline = Instant::now() + Duration::from_millis(options.pairing_timeout_ms);
    loop {
        // 1. Everything the machine wants on the wire.
        while let Some(frame) = driver.pop_outgoing() {
            transport.send_async(&frame).await?;
        }
        // 2. Terminal, or still working.
        match driver.poll() {
            Some(DriverEvent::Completed(session)) => return Ok(session),
            Some(DriverEvent::Failed(error)) => return Err(WsPairingError::Core(error)),
            None => {}
        }
        // 3. The one wait: the next inbound frame, or the budget runs out.
        let now = Instant::now();
        if now >= deadline {
            send_goodbye(&mut driver, transport).await;
            return Err(WsPairingError::Timeout);
        }
        match tokio::time::timeout(deadline - now, transport.recv_async()).await {
            Ok(Ok(frame)) => driver.push(&frame)?,
            Ok(Err(error)) => {
                // A transport-level death (close, relay error, socket
                // end) is not a protocol verdict: queue the goodbye and
                // surface the transport error as-is. Callers mapping the
                // code board must not burn an attempt for it.
                send_goodbye(&mut driver, transport).await;
                return Err(error);
            }
            Err(_elapsed) => {
                send_goodbye(&mut driver, transport).await;
                return Err(WsPairingError::Timeout);
            }
        }
    }
}

/// Queue the goodbye frame and push whatever is now in the outbox,
/// best effort: a dead wire must not turn a clean exit into an error
/// loop.
async fn send_goodbye(driver: &mut PairingDriver, transport: &WsTransport) {
    driver.abort();
    while let Some(frame) = driver.pop_outgoing() {
        let _ = transport.send_async(&frame).await;
    }
}
