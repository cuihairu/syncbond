//! LAN discovery integration: candidate collection, pairability filtering,
//! and connection into the existing short-code pairing flow. Network I/O is
//! injected, so the suite is green without a real multicast environment.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use syncbond_core::discovery::{
    pair_with_candidate, CandidateConnector, DiscoveryCandidate, DiscoveryError, DiscoverySession,
    MockDiscoveryProvider, ServiceRecord, CAPABILITY_PAIRING, PROTOCOL_VERSION,
};
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::accept;
use syncbond_core::transport::{MemoryTransport, Transport, TransportError};

struct MemoryConnector {
    transport: Arc<MemoryTransport>,
}

impl CandidateConnector for MemoryConnector {
    fn connect(
        &self,
        _candidate: &DiscoveryCandidate,
    ) -> Result<Arc<dyn Transport>, TransportError> {
        Ok(self.transport.clone())
    }
}

fn candidate(device_name: &str, port: u16) -> DiscoveryCandidate {
    DiscoveryCandidate {
        instance_name: device_name.into(),
        device_name: device_name.into(),
        capabilities: vec![CAPABILITY_PAIRING.into()],
        addresses: vec![IpAddr::from([127, 0, 0, 1])],
        port,
        protocol_version: PROTOCOL_VERSION.into(),
    }
}

#[test]
fn mock_provider_supplies_candidates_through_session() {
    let provider = MockDiscoveryProvider::new();
    provider.add_candidate(candidate("phone", 48000));
    let session = DiscoverySession::new(Arc::new(provider));
    let found = session.browse(Duration::from_millis(10)).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].device_name, "phone");
    assert!(found[0].is_pairable());
    assert_eq!(
        found[0].socket_addr(),
        Some("127.0.0.1:48000".parse().unwrap())
    );
}

#[test]
fn discovered_candidate_completes_existing_pairing_flow() {
    let (ta, tb) = MemoryTransport::pair();
    let candidate = candidate("responder", 48000);
    let connector = MemoryConnector {
        transport: ta.clone(),
    };
    let identity_a = DeviceIdentity::generate();
    let identity_b = DeviceIdentity::generate();
    let identity_b_clone = identity_b.clone();
    let responder = std::thread::spawn({
        let tb = tb.clone();
        move || accept("K7Q2M4", &identity_b_clone, tb as Arc<dyn Transport>)
    });

    let session_a = pair_with_candidate("K7Q2M4", &identity_a, &candidate, &connector)
        .expect("initiator paired over discovered candidate");
    let session_b = responder
        .join()
        .expect("responder thread")
        .expect("responder paired");
    assert_eq!(session_a.group_id, session_b.group_id);
    assert_eq!(session_a.session_key, session_b.session_key);
    assert_eq!(session_a.peer_identity.public_key, identity_b.public_key);
}

#[test]
fn incompatible_candidate_is_rejected_before_connecting() {
    let mut incompatible = candidate("old", 48000);
    incompatible.protocol_version = "spake2-v0".into();
    let connector = MemoryConnector {
        // Deliberately unconnected: the connector must never run.
        transport: MemoryTransport::pair().0,
    };
    let result = pair_with_candidate(
        "CODE5",
        &DeviceIdentity::generate(),
        &incompatible,
        &connector,
    );
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("incompatible candidate must be rejected"),
    };
    assert!(err.to_string().contains("not pairable"));
}

#[test]
fn service_record_validates_wire_limits() {
    assert_eq!(
        ServiceRecord::new("", 48000).validate(),
        Err(DiscoveryError::InvalidRecord(
            "device name must be 1..=255 bytes".into()
        ))
    );
    assert_eq!(
        ServiceRecord::new("device", 0).validate(),
        Err(DiscoveryError::InvalidRecord(
            "port must be non-zero".into()
        ))
    );
    let mut oversized = ServiceRecord::new("device", 48000);
    oversized.capabilities = vec!["x".repeat(256)];
    assert_eq!(
        oversized.validate(),
        Err(DiscoveryError::InvalidRecord(
            "capabilities exceed 255 bytes".into()
        ))
    );
}
