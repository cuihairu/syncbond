//! syncbond-core: accountless, embeddable, end-to-end encrypted device
//! pairing and data synchronization core.
//!
//! The SDK never interprets business data: payloads are opaque bytes and
//! merge behavior is a pluggable strategy. See docs/design/ for the
//! protocol and design decisions.

pub mod batch;
pub mod codes;
pub mod conflict;
pub mod crypto;
pub mod discovery;
pub mod hlc;
pub mod identity;
pub mod member_crypto;
pub mod member_distribution;
pub mod outbox;
pub mod pairing;
pub mod pairing_driver;
pub mod pairing_spake2;
pub mod receive;
pub mod relay;
pub mod replication;
pub mod storage;
pub mod sync_driver;
pub mod transport;

pub use batch::{from_wire, open_operations, seal_operations, to_wire, BatchError};
pub use codes::{CodeError, PairingCodeBoard, PairingPolicy};
pub use crypto::{CryptoError, EncryptedEnvelope, EnvelopeContext, KeyRing, PROTOCOL_VERSION};
pub use discovery::pair_with_candidate;
pub use discovery::PROTOCOL_VERSION as LAN_PROTOCOL_VERSION;
pub use discovery::{
    CandidateConnector, Discovery, DiscoveryCandidate, DiscoveryError, DiscoverySession,
    MockDiscoveryProvider, ServiceRecord, CAPABILITY_PAIRING,
};
pub use hlc::{compare_stamps, HlcStamp, HybridClock};
pub use identity::{DeviceIdentity, IdentityError};
pub use member_crypto::{Admission, MemberCryptoError, MemberKeyRing, Rotation, RotationResult};
pub use member_distribution::{
    deliver_rotation, deliver_to_members, DeliveryError, MemberChannel, MemberChannelError,
};
pub use outbox::{
    drain, stage_operations, DrainFailure, MemoryOutboxStore, OutboxBatch, OutboxError,
    OutboxStore, StageError,
};
pub use pairing::{PairingError, PairingSession, Role};
pub use pairing_driver::{DriverEvent, PairingDriver};
pub use receive::{
    apply_page, commit_receive, cursor_key, load_receive, ApplyReport, ReceiveError, ReceiveState,
    ReceivedPage, ServerCursor,
};
pub use replication::{GcReport, ReplicationError, Replicator};
pub use storage::{MemoryStorage, SyncState, SyncStorage};
pub use sync_driver::{
    run_sync, ChannelTransport, CycleReport, DriverConfig, DriverError, StopReason, SyncDriver,
    TransportFailure,
};
pub use transport::{MemoryTransport, Transport, TransportError};

#[cfg(feature = "lan")]
pub use discovery::MdnsDiscoveryProvider;
