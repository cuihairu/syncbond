//! mDNS-backed provider coverage for the `lan` feature: construction,
//! validation before any network touch, unpublish/drop without state, and
//! register/unregister round trips over the real loopback multicast stack.

#![cfg(feature = "lan")]

use std::time::Duration;
use syncbond_core::discovery::{
    Discovery, DiscoveryError, MdnsDiscoveryProvider, ServiceRecord, CAPABILITY_PAIRING,
    PROTOCOL_VERSION,
};

fn valid_service() -> ServiceRecord {
    ServiceRecord::new("probe-device", 48001)
}

#[test]
fn construction_defaults_and_builder_render_host_name() {
    let provider = MdnsDiscoveryProvider::new();
    assert!(format!("{provider:?}").contains("syncbond.local."));

    let provider = MdnsDiscoveryProvider::default();
    assert!(format!("{provider:?}").contains("syncbond.local."));

    let provider = MdnsDiscoveryProvider::new().with_host_name("phone.local.");
    assert!(format!("{provider:?}").contains("phone.local."));
}

#[test]
fn publish_rejects_invalid_record_before_creating_daemon() {
    let provider = MdnsDiscoveryProvider::new();

    let error = provider
        .publish(&ServiceRecord::new("", 48001))
        .expect_err("empty device name must be rejected");
    assert_eq!(
        error,
        DiscoveryError::InvalidRecord("device name must be 1..=255 bytes".into())
    );

    let error = provider
        .publish(&ServiceRecord::new("probe", 0))
        .expect_err("zero port must be rejected");
    assert_eq!(
        error,
        DiscoveryError::InvalidRecord("port must be non-zero".into())
    );

    let mut oversized = ServiceRecord::new("probe", 48001);
    oversized.capabilities = vec!["x".repeat(256)];
    let error = provider
        .publish(&oversized)
        .expect_err("oversized TXT must be rejected");
    assert_eq!(
        error,
        DiscoveryError::InvalidRecord("capabilities exceed 255 bytes".into())
    );
}

#[test]
fn unpublish_without_publish_stays_ok() {
    let provider = MdnsDiscoveryProvider::new();
    provider
        .unpublish()
        .expect("unpublish with no daemon must stay ok");
}

#[test]
fn drop_without_published_state_does_not_panic() {
    drop(MdnsDiscoveryProvider::new());
    drop(MdnsDiscoveryProvider::new().with_host_name("tmp.local."));
}

#[test]
fn publish_then_unpublish_round_trip() {
    let provider = MdnsDiscoveryProvider::new();
    provider
        .publish(&valid_service())
        .expect("publish on the loopback multicast stack");
    provider.unpublish().expect("unpublish after publish");
    provider.unpublish().expect("second unpublish stays ok");
}

#[test]
fn republish_reuses_daemon_and_replaces_record() {
    let provider = MdnsDiscoveryProvider::new();
    provider.publish(&valid_service()).expect("first publish");
    let renamed = ServiceRecord::new("probe-device-2", 48002);
    provider
        .publish(&renamed)
        .expect("second publish reuses the daemon");
    provider.unpublish().expect("unpublish after republish");
}

#[test]
fn drop_after_publish_unregisters_and_shuts_down() {
    let provider = MdnsDiscoveryProvider::new();
    provider
        .publish(&valid_service())
        .expect("publish before drop");
    drop(provider);
}

#[test]
fn browse_completes_without_own_publication() {
    let provider = MdnsDiscoveryProvider::new();
    let found = provider
        .browse(Duration::from_millis(200))
        .expect("browse must not error without own publication");
    // Sibling tests may be announcing on the same host, so only well-formed
    // decoding is asserted rather than an empty result.
    for candidate in &found {
        assert!(!candidate.instance_name.is_empty());
    }
}

#[test]
fn browse_resolves_own_published_service() {
    let provider = MdnsDiscoveryProvider::new();
    let service = ServiceRecord::new("browse-resolve-probe", 48004);
    provider.publish(&service).expect("publish before browse");

    // Sibling tests publish concurrently on the same host, so match our own
    // record by name and retry: resolution is fast on a healthy host but
    // must survive scheduler contention.
    let mut resolved = None;
    for _ in 0..5 {
        let found = provider
            .browse(Duration::from_secs(2))
            .expect("browse after publish");
        if let Some(candidate) = found
            .iter()
            .find(|candidate| candidate.device_name == "browse-resolve-probe")
        {
            resolved = Some(candidate.clone());
            break;
        }
    }
    provider.unpublish().expect("unpublish after browse");

    let candidate = resolved.expect("own announcement must resolve on loopback");
    assert_eq!(candidate.port, 48004);
    assert_eq!(candidate.protocol_version, PROTOCOL_VERSION);
    assert!(candidate
        .capabilities
        .contains(&CAPABILITY_PAIRING.to_string()));
    assert!(candidate.is_pairable());
    assert_eq!(candidate.socket_addr().map(|addr| addr.port()), Some(48004));
    assert!(!candidate.instance_name.is_empty());
}
