//! Trusted-proxy policy for the pairing-room surface (todo.md DSR-21,
//! default-server.md §4: "define trusted proxy settings").
//!
//! The rate limit for room creation is keyed by client IP. Directly
//! exposed, that key is the peer socket address. Behind the recommended
//! TLS reverse proxy every peer is the proxy, so the deployer lists the
//! proxy addresses (IP or CIDR) in `trustedProxies`; for a peer on that
//! list the client address is taken from `X-Forwarded-For` — scanning
//! from the right, exactly one hop past the trusted proxies. Anything
//! further left was written by the client itself and is never trusted,
//! which is why a plain header without a trusted peer is ignored
//! completely: a loopback caller cannot mint new rate-limit budgets by
//! sending `X-Forwarded-For`.

use serde::ser::Serializer;
use serde::{Deserialize, Deserializer};
use std::net::IpAddr;
use std::str::FromStr;

/// One trusted proxy network, parsed once at config load and never
/// re-parsed per request. Keeps the deployer's original spelling so the
/// config file round-trips unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxy {
    raw: String,
    net: TrustedNet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustedNet {
    addr: IpAddr,
    prefix: u8,
}

#[derive(Debug, thiserror::Error)]
#[error("not an IP or CIDR: {0:?}")]
pub struct TrustedProxyError(String);

impl TrustedProxy {
    /// Parse a bare IP (`10.0.0.1`, `::1`) or CIDR (`10.0.0.0/8`,
    /// `2001:db8::/32`). Prefix bounds follow the address family.
    pub fn parse(entry: &str) -> Result<Self, TrustedProxyError> {
        let invalid = || TrustedProxyError(entry.to_owned());
        let (addr_part, prefix) = match entry.split_once('/') {
            Some((addr_part, prefix)) => {
                let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;
                let addr = IpAddr::from_str(addr_part).map_err(|_| invalid())?;
                let max = match addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                if prefix > max {
                    return Err(invalid());
                }
                (addr, prefix)
            }
            None => {
                let addr = IpAddr::from_str(entry).map_err(|_| invalid())?;
                (
                    addr,
                    match addr {
                        IpAddr::V4(_) => 32,
                        IpAddr::V6(_) => 128,
                    },
                )
            }
        };
        Ok(Self {
            raw: entry.to_owned(),
            net: TrustedNet {
                addr: addr_part,
                prefix,
            },
        })
    }

    /// Whether `ip` falls inside this network. Address families must
    /// match: an IPv4 network never contains an IPv6 address.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let net = u32::from(net);
                let ip = u32::from(ip);
                let mask = v4_mask(self.net.prefix);
                ip & mask == net & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net = u128::from(net);
                let ip = u128::from(ip);
                let mask = v6_mask(self.net.prefix);
                ip & mask == net & mask
            }
            _ => false,
        }
    }

    /// Whether any listed network contains `ip`.
    pub fn list_contains(list: &[Self], ip: IpAddr) -> bool {
        list.iter().any(|proxy| proxy.contains(ip))
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl serde::Serialize for TrustedProxy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for TrustedProxy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Resolve the client IP a rate limit may be keyed on: the peer socket
/// address, unless the peer is a trusted proxy and its `X-Forwarded-For`
/// chain yields a client — then the rightmost entry that is *not* itself
/// a trusted proxy (the last hop the trusted proxy chain actually saw).
/// A chain entry that is not a valid IP stops the scan: garbage cannot
/// be skipped in search of a better answer, the honest fallback is the
/// proxy's own address.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &[TrustedProxy]) -> IpAddr {
    if !TrustedProxy::list_contains(trusted, peer) {
        return peer;
    }
    let Some(chain) = forwarded_for else {
        return peer;
    };
    for entry in chain.split(',').rev().map(str::trim) {
        let Ok(ip) = IpAddr::from_str(entry) else {
            break;
        };
        if !TrustedProxy::list_contains(trusted, ip) {
            return ip;
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted(entries: &[&str]) -> Vec<TrustedProxy> {
        entries
            .iter()
            .map(|entry| TrustedProxy::parse(entry).unwrap())
            .collect()
    }

    #[test]
    fn a_bare_ip_matches_itself_only() {
        let list = trusted(&["10.0.0.1", "::1"]);
        assert!(TrustedProxy::list_contains(
            &list,
            "10.0.0.1".parse().unwrap()
        ));
        assert!(!TrustedProxy::list_contains(
            &list,
            "10.0.0.2".parse().unwrap()
        ));
        assert!(TrustedProxy::list_contains(&list, "::1".parse().unwrap()));
        assert!(!TrustedProxy::list_contains(&list, "::2".parse().unwrap()));
    }

    #[test]
    fn cidrs_match_across_the_host_bits() {
        let list = trusted(&["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"]);
        assert!(TrustedProxy::list_contains(
            &list,
            "10.255.3.7".parse().unwrap()
        ));
        assert!(!TrustedProxy::list_contains(
            &list,
            "11.0.0.1".parse().unwrap()
        ));
        assert!(TrustedProxy::list_contains(
            &list,
            "192.168.1.200".parse().unwrap()
        ));
        assert!(!TrustedProxy::list_contains(
            &list,
            "192.168.2.1".parse().unwrap()
        ));
        assert!(TrustedProxy::list_contains(
            &list,
            "2001:db8:ffff::9".parse().unwrap()
        ));
        assert!(!TrustedProxy::list_contains(
            &list,
            "2001:db9::1".parse().unwrap()
        ));
    }

    #[test]
    fn a_host_net_of_one_family_never_contains_the_other() {
        let list = trusted(&["10.0.0.0/8"]);
        assert!(!TrustedProxy::list_contains(
            &list,
            "::10:0:0:1".parse().unwrap()
        ));
    }

    #[test]
    fn prefixes_out_of_range_and_garbage_are_rejected() {
        assert!(TrustedProxy::parse("10.0.0.0/33").is_err());
        assert!(TrustedProxy::parse("::1/129").is_err());
        assert!(TrustedProxy::parse("10.0.0.0/").is_err());
        assert!(TrustedProxy::parse("proxy.internal").is_err());
        assert!(TrustedProxy::parse("10.0.0.0/8/8").is_err());
        assert!(TrustedProxy::parse("").is_err());
    }

    #[test]
    fn the_config_file_spelling_survives_a_round_trip() {
        let parsed = TrustedProxy::parse("10.0.0.1/8").unwrap();
        let raw = serde_json::to_string(&parsed).unwrap();
        assert_eq!(raw, r#""10.0.0.1/8""#);
        assert_eq!(serde_json::from_str::<TrustedProxy>(&raw).unwrap(), parsed);
    }

    #[test]
    fn an_untrusted_peer_ignores_the_forwarded_header() {
        let list = trusted(&["10.0.0.0/8"]);
        let peer = "127.0.0.1".parse().unwrap();
        assert_eq!(
            client_ip(peer, Some("198.51.100.7"), &list),
            peer,
            "without a trusted peer the header is worth nothing"
        );
    }

    #[test]
    fn a_trusted_proxy_yields_the_rightmost_untrusted_entry() {
        let list = trusted(&["10.0.0.0/8"]);
        let peer = "10.0.0.1".parse().unwrap();
        // proxy -> edge proxy -> client: both hops 10.x are trusted.
        assert_eq!(
            client_ip(peer, Some("203.0.113.9, 10.0.0.2"), &list),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // A spoofed entry on the left of a trusted hop changes nothing.
        assert_eq!(
            client_ip(peer, Some("8.8.8.8, 198.51.100.7, 10.0.0.2"), &list),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn an_all_trusted_chain_falls_back_to_the_proxy_address() {
        let list = trusted(&["10.0.0.0/8"]);
        let peer = "10.0.0.1".parse().unwrap();
        assert_eq!(client_ip(peer, Some("10.0.0.9, 10.0.0.2"), &list), peer);
    }

    #[test]
    fn a_garbage_entry_stops_the_scan_at_the_proxy() {
        let list = trusted(&["10.0.0.0/8"]);
        let peer = "10.0.0.1".parse().unwrap();
        assert_eq!(
            client_ip(peer, Some("198.51.100.7, not-an-ip"), &list),
            peer,
            "garbage cannot be skipped in search of a nicer answer"
        );
    }

    #[test]
    fn an_empty_or_missing_header_never_leaves_the_proxy() {
        let list = trusted(&["10.0.0.0/8"]);
        let peer = "10.0.0.1".parse().unwrap();
        assert_eq!(client_ip(peer, None, &list), peer);
        assert_eq!(client_ip(peer, Some(""), &list), peer);
    }
}
