//! Extra discovery coverage: candidate address preference, pairability
//! filtering, service-record validation, publish through the session, and
//! unpublish idempotence.

use std::sync::Arc;
use std::time::Duration;

use syncbond_core::discovery::{
    pair_with_candidate, CandidateConnector, DiscoveryCandidate, DiscoveryError, DiscoverySession,
    MockDiscoveryProvider, ServiceRecord, CAPABILITY_PAIRING, PROTOCOL_VERSION,
};
use syncbond_core::identity::DeviceIdentity;
use syncbond_core::Discovery;

/// The `Default` impl must yield the same usable empty provider as `new`.
#[test]
fn default_mock_provider_starts_empty() {
    let provider = MockDiscoveryProvider::default();
    assert!(provider
        .browse(Duration::from_millis(1))
        .expect("browse")
        .is_empty());
}
use syncbond_core::transport::{Transport, TransportError};

fn candidate() -> DiscoveryCandidate {
    DiscoveryCandidate {
        instance_name: "phone".into(),
        device_name: "Phone".into(),
        capabilities: vec![CAPABILITY_PAIRING.into()],
        addresses: vec!["10.0.0.2".parse().unwrap()],
        port: 48000,
        protocol_version: PROTOCOL_VERSION.into(),
    }
}

struct FailConnector;
impl CandidateConnector for FailConnector {
    fn connect(
        &self,
        _candidate: &DiscoveryCandidate,
    ) -> Result<Arc<dyn Transport>, TransportError> {
        Err(TransportError::Closed)
    }
}

#[test]
fn service_record_validation_covers_each_rule() {
    let mut service = ServiceRecord::new("phone", 48000);
    service.validate().unwrap();
    service.device_name.clear();
    assert!(matches!(
        service.validate(),
        Err(DiscoveryError::InvalidRecord(_))
    ));
    service.device_name = "x".repeat(256);
    assert!(matches!(
        service.validate(),
        Err(DiscoveryError::InvalidRecord(_))
    ));
    let service = ServiceRecord::new("phone", 0);
    assert!(matches!(
        service.validate(),
        Err(DiscoveryError::InvalidRecord(_))
    ));
    let mut service = ServiceRecord::new("phone", 1);
    service.capabilities = vec!["x".repeat(256)];
    assert!(matches!(
        service.validate(),
        Err(DiscoveryError::InvalidRecord(_))
    ));
    assert_eq!(service.capabilities, vec!["x".repeat(256)]);
    service.capabilities.clear();
    service.capabilities.push(CAPABILITY_PAIRING.into());
    service.validate().unwrap();
}

#[test]
fn candidate_pairability_and_address_selection() {
    let c = candidate();
    assert!(c.is_pairable());
    assert_eq!(c.host(), Some("10.0.0.2".parse().unwrap()));
    assert_eq!(c.socket_addr().unwrap().port(), 48000);
    assert!(c.socket_addr().is_some());

    let mut bad = candidate();
    bad.protocol_version = "other".into();
    assert!(!bad.is_pairable());
    bad = candidate();
    bad.capabilities.clear();
    assert!(!bad.is_pairable());
    bad = candidate();
    bad.addresses.clear();
    assert!(!bad.is_pairable());
    bad = candidate();
    bad.port = 0;
    assert!(!bad.is_pairable());

    let mut v6 = candidate();
    v6.addresses = vec!["::1".parse().unwrap(), "10.0.0.3".parse().unwrap()];
    assert_eq!(v6.host(), Some("10.0.0.3".parse().unwrap()));
    let v6_only = candidate();
    let mut v6_only = v6_only;
    v6_only.addresses = vec!["::1".parse().unwrap()];
    assert_eq!(v6_only.host(), Some("::1".parse().unwrap()));
}

#[test]
fn pair_with_candidate_rejects_unpairable_and_connector_failure() {
    let identity = DeviceIdentity::generate();
    let mut c = candidate();
    c.protocol_version = "other".into();
    let error = pair_with_candidate("code", &identity, &c, &FailConnector);
    assert!(error.is_err());
    let error = pair_with_candidate("code", &identity, &candidate(), &FailConnector);
    assert!(error.is_err());
}

#[test]
fn session_publish_browse_unpublish_round_trip() {
    let service = ServiceRecord::new("phone", 48000);
    let provider = MockDiscoveryProvider::new();
    provider.add_candidate(candidate());
    let session = DiscoverySession::new(Arc::new(provider));
    session.publish(&service).unwrap();
    let candidates = session.browse(Duration::from_millis(1)).unwrap();
    assert_eq!(candidates.len(), 1);
    session.unpublish().unwrap();
    session.unpublish().unwrap();
    assert_eq!(session.browse(Duration::from_millis(1)).unwrap().len(), 1);
}
