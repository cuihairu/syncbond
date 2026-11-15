//! Short-term pairing rooms (todo.md DSR-20, relay-protocol.md §7).
//!
//! A room is the meeting point for exactly one pairing handshake:
//! [`PairingRooms::create`] mints a room id plus a 128-bit capability,
//! [`PairingRooms::join`] admits bearers of that capability, and the TTL
//! plus the join-attempt budget bound how long either can be probed. The
//! relay never sees the short code — the code stays device-side as the
//! SPAKE2 input. Nothing here accepts, stores, or logs one: the create
//! route's DTO rejects unknown fields (a body carrying `code` is a
//! `bad_request`), and [`Room`] has no field a code could land in.
//!
//! Two decisions this module owns, because the contract leaves them open:
//!
//! - **Rooms are memory-only.** They are 120-second ephemera; persisting
//!   them would outlive their usefulness while putting a bearer capability
//!   on disk. A restart forgets every room, which is the correct failure
//!   mode: the devices simply pair again.
//! - **Participants only ever grow.** A disconnected device cannot rejoin
//!   (its seat is not freed); it creates a new room. Freeing seats would
//!   let a third device slip into a live handshake — worse than making the
//!   honest peer re-pair.
//!
//! The capability is stored as its SHA-256 digest, mirroring how channel
//! credentials are stored: the plaintext exists once, in the create
//! response. Sweeping is lazy — every create and join first drops every
//! expired room, so the table never holds rooms older than the TTL window,
//! and creation is itself rate-limited per source IP. A periodic sweeper,
//! if one is ever wanted, belongs with the resource caps (DSR-23).

use std::collections::HashMap;
use std::net::IpAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use syncbond_relay_protocol::error::RelayErrorCode;
use syncbond_relay_protocol::limits::{
    MAX_ROOM_CREATES_PER_MINUTE_PER_IP, MAX_ROOM_JOIN_ATTEMPTS, MAX_ROOM_PARTICIPANTS,
    ROOM_CREATE_RATE_WINDOW_MS, ROOM_TTL_MS,
};

/// One pairing room. The capability is here only as a digest; the id, the
/// participant count, the attempt count and the deadline are the rest.
struct Room {
    capability_digest: [u8; 32],
    participants: usize,
    join_attempts: usize,
    expires_at_ms: u64,
}

/// In-memory room table plus the per-source-IP creation windows.
#[derive(Default)]
struct Inner {
    rooms: HashMap<String, Room>,
    /// Create instants (unix ms) inside the sliding rate window, per IP.
    creates: HashMap<IpAddr, Vec<u64>>,
}

/// A room that now exists: its id, its capability (shown exactly once),
/// and the instant after which it is dead.
#[derive(Debug)]
pub struct CreatedRoom {
    pub room_id: String,
    pub capability: String,
    pub expires_at_ms: u64,
}

/// The pairing-room registry. Cheap to clone behind an `Arc` — the state
/// lives behind a mutex, like the SQLite store.
#[derive(Default)]
pub struct PairingRooms {
    inner: std::sync::Mutex<Inner>,
}

impl PairingRooms {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a room for `peer`. Every call first sweeps expired rooms, so
    /// the table only ever holds rooms inside their TTL window.
    pub fn create(&self, peer: IpAddr, now_ms: u64) -> Result<CreatedRoom, CreateRoomError> {
        let mut inner = self.lock();
        inner.sweep(now_ms);
        let window = inner.creates.entry(peer).or_default();
        window.retain(|at| now_ms.saturating_sub(*at) < ROOM_CREATE_RATE_WINDOW_MS);
        if window.len() >= MAX_ROOM_CREATES_PER_MINUTE_PER_IP {
            return Err(CreateRoomError::RateLimited);
        }
        window.push(now_ms);
        let capability = random_capability();
        let room_id = random_room_id();
        let expires_at_ms = now_ms.saturating_add(ROOM_TTL_MS);
        inner.rooms.insert(
            room_id.clone(),
            Room {
                capability_digest: Sha256::digest(capability.as_bytes()).into(),
                participants: 0,
                join_attempts: 0,
                expires_at_ms,
            },
        );
        Ok(CreatedRoom {
            room_id,
            capability,
            expires_at_ms,
        })
    }

    /// Admit a bearer of `capability` to the room. Returns whether this
    /// join completed the pair (`peerJoined` for the first `room.joined`
    /// message). Every attempt counts — wrong capability, full room, or a
    /// successful join — and the sixteenth attempt is the last one served:
    /// a seventeenth finds the room dead, per the frozen contract.
    ///
    /// Consumed by the WebSocket join route (DSR-21); unit-tested here.
    #[allow(dead_code)]
    pub fn join(
        &self,
        room_id: &str,
        capability: &str,
        now_ms: u64,
    ) -> Result<bool, JoinRoomError> {
        let mut inner = self.lock();
        if !inner.rooms.contains_key(room_id) {
            return Err(JoinRoomError::RoomNotFound);
        }
        // The room being joined is checked before the sweep: sweeping first
        // would drop it and hand back `room_not_found` where the contract
        // asks for `room_expired` — a stale capability holder must hear
        // "expired", not "never existed".
        if now_ms >= inner.rooms.get(room_id).unwrap().expires_at_ms {
            inner.rooms.remove(room_id);
            return Err(JoinRoomError::Expired);
        }
        let attempts = inner.rooms.get(room_id).unwrap().join_attempts;
        if attempts >= MAX_ROOM_JOIN_ATTEMPTS {
            inner.rooms.remove(room_id);
            return Err(JoinRoomError::Expired);
        }
        inner.sweep(now_ms);
        let room = inner.rooms.get_mut(room_id).unwrap();
        room.join_attempts += 1;
        let presented: [u8; 32] = Sha256::digest(capability.as_bytes()).into();
        if !constant_time_digest_eq(&room.capability_digest, &presented) {
            // A wrong capability must never learn anything else about the
            // room — not its fullness, not its remaining budget. It burned
            // one attempt, which is all it gets to know.
            return Err(JoinRoomError::CapabilityMismatch);
        }
        if room.participants >= MAX_ROOM_PARTICIPANTS {
            return Err(JoinRoomError::Full);
        }
        room.participants += 1;
        Ok(room.participants == MAX_ROOM_PARTICIPANTS)
    }

    /// Drop every expired room; returns how many went. Laziness covers the
    /// steady state (create and join both sweep), this is the explicit hook
    /// for a periodic sweeper (DSR-23); tests drive it until then.
    #[allow(dead_code)]
    pub fn sweep(&self, now_ms: u64) -> usize {
        let mut inner = self.lock();
        inner.sweep(now_ms)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// The registry's Debug stays silent about room contents: there is nothing
// secret in the table (digests only), but a redacted Debug keeps the
// "capabilities never leak through logging" property structural.
impl std::fmt::Debug for PairingRooms {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingRooms")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateRoomError {
    /// This source IP has filled its sliding one-minute window.
    RateLimited,
}

impl CreateRoomError {
    pub fn code(&self) -> RelayErrorCode {
        match self {
            Self::RateLimited => RelayErrorCode::RateLimited,
        }
    }
}

/// Why a join was refused. `code()` is the wire mapping the WebSocket join
/// route (DSR-21) turns into close-code 4401/4404/4409/4410 territory.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum JoinRoomError {
    /// No such room — never created, already swept, or already dead.
    RoomNotFound,
    /// TTL elapsed or the attempt budget exhausted; the room is gone.
    Expired,
    /// Two participants are inside. Only a valid capability can see this.
    Full,
    /// The presented capability is not this room's; it burned one attempt.
    CapabilityMismatch,
}

impl JoinRoomError {
    #[allow(dead_code)]
    pub fn code(&self) -> RelayErrorCode {
        match self {
            Self::RoomNotFound => RelayErrorCode::RoomNotFound,
            Self::Expired => RelayErrorCode::RoomExpired,
            Self::Full => RelayErrorCode::RoomFull,
            // The capability is a bearer secret presented in the
            // Authorization header; failing it is an authentication
            // failure, exactly like a wrong channel token.
            Self::CapabilityMismatch => RelayErrorCode::Unauthorized,
        }
    }
}

impl Inner {
    fn sweep(&mut self, now_ms: u64) -> usize {
        let before = self.rooms.len();
        self.rooms.retain(|_, room| now_ms < room.expires_at_ms);
        before - self.rooms.len()
    }
}

/// 128 bits of fresh randomness, base64url without padding — 22 chars,
/// shown exactly once, independent of the short code by construction (the
/// code never enters this module).
fn random_capability() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `rm_` plus 12 random bytes in lowercase hex — the same shape and
/// collision margin as channel ids (`ch_…`).
fn random_room_id() -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    format!("rm_{}", hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Digest comparison without an early exit, matching the admin-credential
/// comparison in the store. Timing leakage on a digest reveals no usable
/// information about the capability itself; the fold is for house style.
fn constant_time_digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// RFC 3339 UTC without fractional seconds — the exact wire shape of the
/// frozen `expiresAt` example (`2026-11-14T12:02:00Z`). Civil-date math is
/// Howard Hinnant's days-from-civil inverse; no calendar dependency.
pub fn rfc3339_utc(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncbond_relay_protocol::limits::ROOM_TTL_MS;

    fn ip(octet: u8) -> IpAddr {
        std::net::IpAddr::from([127, 0, 0, octet])
    }

    #[test]
    fn capability_is_128_bits_of_base64url_and_never_repeats() {
        let rooms = PairingRooms::new();
        let first = rooms.create(ip(1), 1_000).unwrap();
        let second = rooms.create(ip(1), 1_001).unwrap();
        for capability in [&first.capability, &second.capability] {
            let decoded = URL_SAFE_NO_PAD
                .decode(capability)
                .expect("capability is canonical base64url");
            assert_eq!(
                decoded.len(),
                16,
                "a capability is 128 bits: got {} bytes",
                decoded.len()
            );
            assert_eq!(capability.len(), 22, "16 bytes encode to 22 chars");
            assert!(
                capability
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "base64url alphabet only: {capability}"
            );
        }
        assert_ne!(first.capability, second.capability);
        assert_ne!(first.room_id, second.room_id);
    }

    #[test]
    fn room_ids_are_shaped_like_channel_ids() {
        let rooms = PairingRooms::new();
        for offset in 0..8 {
            let created = rooms.create(ip(1), 1_000 + offset).unwrap();
            assert!(created.room_id.starts_with("rm_"));
            let hex = &created.room_id[3..];
            assert_eq!(hex.len(), 24, "12 random bytes as hex");
            assert!(
                hex.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "lowercase hex only: {hex}"
            );
        }
    }

    #[test]
    fn expires_at_is_exactly_one_ttl_ahead() {
        let rooms = PairingRooms::new();
        let created = rooms.create(ip(1), 50_000).unwrap();
        assert_eq!(created.expires_at_ms, 50_000 + ROOM_TTL_MS);
    }

    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000_000), "2001-09-09T01:46:40Z");
        // Leap day: 2024-02-29 exists and renders.
        assert_eq!(rfc3339_utc(1_709_164_800_000), "2024-02-29T00:00:00Z");
        // Year rollover.
        assert_eq!(rfc3339_utc(1_704_067_199_000), "2023-12-31T23:59:59Z");
        assert_eq!(rfc3339_utc(1_704_067_200_000), "2024-01-01T00:00:00Z");
        // The frozen example instant from relay-protocol.md §7.
        assert_eq!(rfc3339_utc(1_794_657_720_000), "2026-11-14T12:02:00Z");
    }

    #[test]
    fn the_17th_create_from_one_ip_is_rate_limited() {
        let rooms = PairingRooms::new();
        for offset in 0..16 {
            rooms
                .create(ip(1), 1_000 + offset)
                .expect("16 creates per minute are allowed");
        }
        assert_eq!(
            rooms.create(ip(1), 2_000).unwrap_err(),
            CreateRoomError::RateLimited
        );
    }

    #[test]
    fn the_rate_window_slides() {
        let rooms = PairingRooms::new();
        for offset in 0..16 {
            rooms.create(ip(1), 1_000 + offset).unwrap();
        }
        assert!(rooms.create(ip(1), 2_000).is_err());
        // 61 s after the first create, its slot has left the window.
        assert!(rooms.create(ip(1), 61_001).is_ok());
    }

    #[test]
    fn the_rate_limit_is_per_source_ip() {
        let rooms = PairingRooms::new();
        for offset in 0..16 {
            rooms.create(ip(1), 1_000 + offset).unwrap();
        }
        assert_eq!(
            rooms.create(ip(1), 2_000).unwrap_err(),
            CreateRoomError::RateLimited
        );
        // A different IP is on its own window.
        assert!(rooms.create(ip(2), 2_000).is_ok());
    }

    #[test]
    fn an_expired_room_refuses_join_and_is_removed() {
        let rooms = PairingRooms::new();
        let created = rooms.create(ip(1), 1_000).unwrap();
        let deadline = created.expires_at_ms;
        // Exactly at the deadline the room is gone.
        assert_eq!(
            rooms
                .join(&created.room_id, &created.capability, deadline)
                .unwrap_err(),
            JoinRoomError::Expired
        );
        // Swept, not kept: the next join is a plain miss.
        assert_eq!(
            rooms
                .join(&created.room_id, &created.capability, deadline + 1)
                .unwrap_err(),
            JoinRoomError::RoomNotFound
        );
    }

    #[test]
    fn two_devices_join_then_the_room_is_full() {
        let rooms = PairingRooms::new();
        let created = rooms.create(ip(1), 1_000).unwrap();
        let first = rooms
            .join(&created.room_id, &created.capability, 1_001)
            .unwrap();
        assert!(!first, "the first join is alone");
        let second = rooms
            .join(&created.room_id, &created.capability, 1_002)
            .unwrap();
        assert!(second, "the second join completes the pair");
        assert_eq!(
            rooms
                .join(&created.room_id, &created.capability, 1_003)
                .unwrap_err(),
            JoinRoomError::Full
        );
    }

    #[test]
    fn a_wrong_capability_burns_an_attempt_and_learns_nothing() {
        let rooms = PairingRooms::new();
        let created = rooms.create(ip(1), 1_000).unwrap();
        assert_eq!(
            rooms
                .join(&created.room_id, "not-the-capability", 1_001)
                .unwrap_err(),
            JoinRoomError::CapabilityMismatch
        );
        // The right capability still works after a failed probe — and reads
        // `peerJoined: false`, because this device is alone so far.
        assert!(!rooms
            .join(&created.room_id, &created.capability, 1_002)
            .unwrap());
    }

    #[test]
    fn a_wrong_capability_never_reveals_fullness() {
        let rooms = PairingRooms::new();
        let created = rooms.create(ip(1), 1_000).unwrap();
        rooms
            .join(&created.room_id, &created.capability, 1_001)
            .unwrap();
        rooms
            .join(&created.room_id, &created.capability, 1_002)
            .unwrap();
        assert_eq!(
            rooms.join(&created.room_id, "wrong", 1_003).unwrap_err(),
            JoinRoomError::CapabilityMismatch,
            "fullness is only ever visible to a capability holder"
        );
    }

    #[test]
    fn the_16th_attempt_is_served_and_the_17th_kills_the_room() {
        let rooms = PairingRooms::new();
        let created = rooms.create(ip(1), 1_000).unwrap();
        for attempt in 0..14 {
            assert_eq!(
                rooms
                    .join(&created.room_id, "wrong", 1_001 + attempt)
                    .unwrap_err(),
                JoinRoomError::CapabilityMismatch
            );
        }
        // Attempts 15 and 16: both devices join for real.
        assert!(!rooms
            .join(&created.room_id, &created.capability, 2_000)
            .unwrap());
        assert!(rooms
            .join(&created.room_id, &created.capability, 2_001)
            .unwrap());
        // Attempt 17 — the room dies on contact, even for a capability
        // holder: the contract caps total join attempts per room.
        assert_eq!(
            rooms
                .join(&created.room_id, &created.capability, 2_002)
                .unwrap_err(),
            JoinRoomError::Expired
        );
        assert_eq!(
            rooms
                .join(&created.room_id, &created.capability, 2_003)
                .unwrap_err(),
            JoinRoomError::RoomNotFound
        );
    }

    #[test]
    fn sweep_drops_only_expired_rooms() {
        let rooms = PairingRooms::new();
        let early = rooms.create(ip(1), 1_000).unwrap();
        let late = rooms.create(ip(1), 2_000).unwrap();
        assert_eq!(
            rooms.sweep(early.expires_at_ms),
            1,
            "only the early room went"
        );
        // The late room survives and still joins.
        assert!(!rooms
            .join(&late.room_id, &late.capability, early.expires_at_ms + 1)
            .unwrap());
    }

    #[test]
    fn debug_output_never_contains_a_capability() {
        let rooms = PairingRooms::new();
        let created = rooms.create(ip(1), 1_000).unwrap();
        let rendered = format!("{rooms:?}");
        assert!(!rendered.contains(&created.capability));
        assert!(!rendered.contains(&created.room_id));
    }
}
