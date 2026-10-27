//! Local-network discovery for the existing short-code pairing flow.
//!
//! Discovery metadata is unauthenticated by design: the result is only a
//! candidate list, and identity verification remains the responsibility of the
//! authenticated pairing exchange. Core paths never create network I/O;
//! applications inject discovery providers and transport factories.

use crate::identity::DeviceIdentity;
use crate::pairing::{pair, PairingError, PairingSession};
use crate::transport::{Transport, TransportError};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

#[cfg(feature = "lan")]
use std::collections::HashMap;
#[cfg(feature = "lan")]
use std::time::Instant;

/// DNS-SD service type used by the mDNS adapter.
pub const SERVICE_TYPE: &str = "_syncbond-pair._udp.local.";
pub const TXT_PROTOCOL_VERSION: &str = "protocol_version";
pub const TXT_CAPABILITIES: &str = "capabilities";
pub const PROTOCOL_VERSION: &str = "spake2-p256-sha256-v1";
pub const CAPABILITY_PAIRING: &str = "pairing";

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DiscoveryError {
    #[error("invalid service record: {0}")]
    InvalidRecord(String),
    #[error("discovery provider unavailable")]
    Unavailable,
    #[error("discovery provider timed out")]
    Timeout,
}

/// Metadata a device advertises on the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    pub device_name: String,
    pub capabilities: Vec<String>,
    pub port: u16,
    pub protocol_version: String,
}

impl ServiceRecord {
    pub fn new(device_name: impl Into<String>, port: u16) -> Self {
        Self {
            device_name: device_name.into(),
            capabilities: vec![CAPABILITY_PAIRING.into()],
            port,
            protocol_version: PROTOCOL_VERSION.into(),
        }
    }

    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.device_name.is_empty() || self.device_name.len() > 255 {
            return Err(DiscoveryError::InvalidRecord(
                "device name must be 1..=255 bytes".into(),
            ));
        }
        if self.port == 0 {
            return Err(DiscoveryError::InvalidRecord(
                "port must be non-zero".into(),
            ));
        }
        if self.capabilities.join(",").len() > 255 {
            return Err(DiscoveryError::InvalidRecord(
                "capabilities exceed 255 bytes".into(),
            ));
        }
        Ok(())
    }
}

/// A reachable peer discovered by a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryCandidate {
    pub instance_name: String,
    pub device_name: String,
    pub capabilities: Vec<String>,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    pub protocol_version: String,
}

impl DiscoveryCandidate {
    pub fn is_pairable(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
            && self
                .capabilities
                .iter()
                .any(|cap| cap == CAPABILITY_PAIRING)
            && !self.addresses.is_empty()
            && self.port != 0
    }

    /// First advertised address, preferring IPv4 for reachability.
    pub fn host(&self) -> Option<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(IpAddr::is_ipv4)
            .or_else(|| self.addresses.first().copied())
    }

    /// Socket endpoint if the candidate advertises at least one address.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.host().map(|host| SocketAddr::new(host, self.port))
    }
}

/// Pluggable LAN discovery. Implementations must not block the core sync
/// path; `browse` is the only interface that waits, and callers choose how
/// long to wait.
pub trait Discovery: Send + Sync {
    fn publish(&self, service: &ServiceRecord) -> Result<(), DiscoveryError>;

    fn unpublish(&self) -> Result<(), DiscoveryError> {
        Ok(())
    }

    fn browse(&self, timeout: Duration) -> Result<Vec<DiscoveryCandidate>, DiscoveryError>;
}

/// Connects a discovered peer to the existing `Transport` abstraction.
pub trait CandidateConnector: Send + Sync {
    fn connect(&self, candidate: &DiscoveryCandidate)
        -> Result<Arc<dyn Transport>, TransportError>;
}

/// Pair against a discovered peer after connecting through `connector`.
pub fn pair_with_candidate(
    code: &str,
    identity: &DeviceIdentity,
    candidate: &DiscoveryCandidate,
    connector: &dyn CandidateConnector,
) -> Result<PairingSession, PairingError> {
    if !candidate.is_pairable() {
        return Err(PairingError::Protocol(
            "discovered candidate is not pairable".into(),
        ));
    }
    let transport = connector.connect(candidate)?;
    pair(code, identity, transport)
}

/// In-memory provider for tests and offline examples.
pub struct MockDiscoveryProvider {
    candidates: Mutex<Vec<DiscoveryCandidate>>,
    state: Mutex<MockState>,
}

#[derive(Debug, Default)]
struct MockState {
    published: bool,
}

impl MockDiscoveryProvider {
    pub fn new() -> Self {
        Self {
            candidates: Mutex::new(Vec::new()),
            state: Mutex::new(MockState::default()),
        }
    }

    pub fn add_candidate(&self, candidate: DiscoveryCandidate) {
        self.candidates.lock().unwrap().push(candidate);
    }
}

impl Default for MockDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery for MockDiscoveryProvider {
    fn publish(&self, service: &ServiceRecord) -> Result<(), DiscoveryError> {
        service.validate()?;
        self.state.lock().unwrap().published = true;
        Ok(())
    }

    fn browse(&self, _timeout: Duration) -> Result<Vec<DiscoveryCandidate>, DiscoveryError> {
        self.candidates
            .lock()
            .map(|candidates| candidates.clone())
            .map_err(|_| DiscoveryError::Unavailable)
    }
}

#[cfg(feature = "lan")]
struct MdnsState {
    daemon: mdns_sd::ServiceDaemon,
    published: Option<mdns_sd::ServiceInfo>,
}

/// mDNS-backed implementation of [`Discovery`], gated behind `feature = "lan"`.
#[cfg(feature = "lan")]
pub struct MdnsDiscoveryProvider {
    host_name: String,
    state: Mutex<Option<MdnsState>>,
}

#[cfg(feature = "lan")]
impl MdnsDiscoveryProvider {
    pub fn new() -> Self {
        Self {
            host_name: "syncbond.local.".into(),
            state: Mutex::new(None),
        }
    }

    pub fn with_host_name(mut self, host_name: impl Into<String>) -> Self {
        self.host_name = host_name.into();
        self
    }

    fn daemon(&self) -> Result<mdns_sd::ServiceDaemon, DiscoveryError> {
        let mut state = self.state.lock().map_err(|_| DiscoveryError::Unavailable)?;
        match state.as_mut() {
            Some(existing) => Ok(existing.daemon.clone()),
            None => {
                let daemon =
                    mdns_sd::ServiceDaemon::new().map_err(|_| DiscoveryError::Unavailable)?;
                *state = Some(MdnsState {
                    daemon: daemon.clone(),
                    published: None,
                });
                Ok(daemon)
            }
        }
    }

    fn service_info(
        &self,
        service: &ServiceRecord,
    ) -> Result<mdns_sd::ServiceInfo, DiscoveryError> {
        service.validate()?;
        let host_name = if self.host_name.ends_with(".local.") {
            self.host_name.clone()
        } else {
            format!("{}.", self.host_name)
        };
        mk_service_info(service, &host_name)
    }
}

#[cfg(feature = "lan")]
impl Default for MdnsDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "lan")]
impl Drop for MdnsDiscoveryProvider {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(existing) = state.as_mut() {
                if let Some(info) = existing.published.take() {
                    let _ = existing.daemon.unregister(info.get_fullname());
                }
                let _ = existing.daemon.shutdown();
            }
        }
    }
}

#[cfg(feature = "lan")]
impl Discovery for MdnsDiscoveryProvider {
    fn publish(&self, service: &ServiceRecord) -> Result<(), DiscoveryError> {
        let info = self.service_info(service)?;
        let mut state = self.state.lock().map_err(|_| DiscoveryError::Unavailable)?;
        let daemon = match state.as_mut() {
            Some(existing) => existing.daemon.clone(),
            None => {
                let daemon =
                    mdns_sd::ServiceDaemon::new().map_err(|_| DiscoveryError::Unavailable)?;
                *state = Some(MdnsState {
                    daemon: daemon.clone(),
                    published: None,
                });
                daemon
            }
        };
        daemon
            .register(info)
            .map_err(|_| DiscoveryError::Unavailable)?;
        let info = self.service_info(service)?;
        state.as_mut().unwrap().published = Some(info);
        Ok(())
    }

    fn unpublish(&self) -> Result<(), DiscoveryError> {
        let mut state = self.state.lock().map_err(|_| DiscoveryError::Unavailable)?;
        if let Some(existing) = state.as_mut() {
            if let Some(info) = existing.published.take() {
                let _ = existing.daemon.unregister(info.get_fullname());
            }
        }
        Ok(())
    }

    fn browse(&self, timeout: Duration) -> Result<Vec<DiscoveryCandidate>, DiscoveryError> {
        let daemon = self.daemon()?;
        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|_| DiscoveryError::Unavailable)?;
        let deadline = Instant::now() + timeout;
        let mut resolved: HashMap<String, DiscoveryCandidate> = HashMap::new();
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            match receiver.recv_timeout(deadline - now) {
                Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                    if let Some(candidate) = candidate_from_mdns(&info) {
                        resolved.insert(candidate.instance_name.clone(), candidate);
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = daemon.stop_browse(SERVICE_TYPE);
        Ok(resolved.into_values().collect())
    }
}

#[cfg(feature = "lan")]
fn mk_service_info(
    service: &ServiceRecord,
    host_name: &str,
) -> Result<mdns_sd::ServiceInfo, DiscoveryError> {
    let mut properties = std::collections::HashMap::new();
    properties.insert(
        TXT_PROTOCOL_VERSION.to_owned(),
        service.protocol_version.clone(),
    );
    properties.insert(TXT_CAPABILITIES.to_owned(), service.capabilities.join(","));
    mdns_sd::ServiceInfo::new(
        SERVICE_TYPE,
        &service.device_name,
        host_name,
        (),
        service.port,
        properties,
    )
    .map(|info| info.enable_addr_auto())
    .map_err(|err| DiscoveryError::InvalidRecord(err.to_string()))
}

#[cfg(feature = "lan")]
fn candidate_from_mdns(resolved: &mdns_sd::ResolvedService) -> Option<DiscoveryCandidate> {
    if !resolved.is_valid() {
        return None;
    }
    let instance_name = resolved
        .fullname
        .strip_suffix(&format!(".{SERVICE_TYPE}"))?
        .to_string();
    let capabilities = resolved
        .get_property_val_str(TXT_CAPABILITIES)
        .unwrap_or_default()
        .split(',')
        .filter(|cap| !cap.is_empty())
        .map(str::to_owned)
        .collect();
    Some(DiscoveryCandidate {
        instance_name: instance_name.clone(),
        device_name: instance_name,
        capabilities,
        addresses: resolved
            .get_addresses()
            .iter()
            .map(|ip| ip.to_ip_addr())
            .collect(),
        port: resolved.port,
        protocol_version: resolved
            .get_property_val_str(TXT_PROTOCOL_VERSION)
            .unwrap_or(PROTOCOL_VERSION)
            .to_owned(),
    })
}

#[cfg(feature = "lan")]
impl std::fmt::Debug for MdnsDiscoveryProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MdnsDiscoveryProvider")
            .field("host_name", &self.host_name)
            .finish_non_exhaustive()
    }
}

/// Bounded discovery helper. Publishing and browsing live on the same
/// provider so a device can act as both advertiser and browser.
pub struct DiscoverySession {
    provider: Arc<dyn Discovery>,
}

impl DiscoverySession {
    pub fn new(provider: Arc<dyn Discovery>) -> Self {
        Self { provider }
    }

    pub fn publish(&self, service: &ServiceRecord) -> Result<(), DiscoveryError> {
        self.provider.publish(service)
    }

    pub fn unpublish(&self) -> Result<(), DiscoveryError> {
        self.provider.unpublish()
    }

    pub fn browse(&self, timeout: Duration) -> Result<Vec<DiscoveryCandidate>, DiscoveryError> {
        self.provider.browse(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_provider_returns_candidates() {
        let provider = MockDiscoveryProvider::new();
        provider.add_candidate(DiscoveryCandidate {
            instance_name: "phone".into(),
            device_name: "Phone".into(),
            capabilities: vec![CAPABILITY_PAIRING.into()],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            port: 48000,
            protocol_version: PROTOCOL_VERSION.into(),
        });
        let candidates = provider.browse(Duration::from_millis(10)).unwrap();
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].is_pairable());
    }
}
