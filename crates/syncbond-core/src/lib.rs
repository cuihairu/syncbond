//! syncbond-core: accountless, embeddable, end-to-end encrypted device
//! pairing and data synchronization core.
//!
//! The SDK never interprets business data: payloads are opaque bytes and
//! merge behavior is a pluggable strategy. See docs/design/ for the
//! protocol and design decisions.

pub mod codes;
pub mod conflict;
pub mod crypto;
pub mod discovery;
pub mod hlc;
pub mod identity;
pub mod member_crypto;
pub mod pairing;
pub mod pairing_spake2;
pub mod relay;
pub mod replication;
pub mod storage;
pub mod transport;

pub use codes::{PairingCodeBoard, PairingPolicy};
pub use crypto::{CryptoError, EncryptedEnvelope, EnvelopeContext, KeyRing, PROTOCOL_VERSION};
pub use discovery::pair_with_candidate;
pub use discovery::PROTOCOL_VERSION as LAN_PROTOCOL_VERSION;
pub use discovery::{
    CandidateConnector, Discovery, DiscoveryCandidate, DiscoveryError, DiscoverySession,
    MockDiscoveryProvider, ServiceRecord, CAPABILITY_PAIRING,
};
pub use hlc::{compare_stamps, HlcStamp, HybridClock};
pub use identity::{DeviceIdentity, IdentityError};
pub use member_crypto::{MemberCryptoError, MemberKeyRing, Rotation, RotationResult};
pub use pairing::{PairingError, PairingSession};
pub use replication::{GcReport, ReplicationError, Replicator};
pub use storage::{MemoryStorage, SyncState, SyncStorage};
pub use transport::{MemoryTransport, Transport, TransportError};

#[cfg(feature = "lan")]
pub use discovery::MdnsDiscoveryProvider;
