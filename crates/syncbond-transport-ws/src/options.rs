//! What a pairing transport needs beyond the core: where the relay is,
//! how strictly to validate TLS, and the budgets. Defaults are the safe
//! ones: TLS validated against the webpki roots, generous but finite
//! timeouts, a bounded bridge.

/// Where to reach the relay: `http://host:port`, `https://`, `ws://`, or
/// `wss://` — the scheme only picks the transport per hop; the REST room
/// creation and the WebSocket join always agree on security.
#[derive(Debug, Clone)]
pub struct WsPairingOptions {
    pub relay_url: String,
    /// TLS validation for `https`/`wss` hops. Validation is on by
    /// default ([`TlsPolicy::Validate`] against the webpki roots); a
    /// private CA is pinned by bytes; [`TlsPolicy::AcceptInvalid`] is the
    /// explicit opt-out and never the default.
    pub tls: TlsPolicy,
    /// Budget for each connect step (TCP+TLS, room creation POST,
    /// WebSocket join), in milliseconds.
    pub connect_timeout_ms: u64,
    /// Budget for the whole pairing exchange from entry to session, in
    /// milliseconds. The room TTL is 120 s; the default budget matches
    /// it, so an exchange that outruns the room is a timeout, not a hang.
    pub pairing_timeout_ms: u64,
    /// The bounded bridge's per-direction frame capacity. A slow sync
    /// core backpressures here instead of buffering without limit;
    /// values below 1 are clamped to 1.
    pub bridge_queue_frames: usize,
}

impl Default for WsPairingOptions {
    fn default() -> Self {
        Self {
            relay_url: String::new(),
            tls: TlsPolicy::default(),
            connect_timeout_ms: 10_000,
            pairing_timeout_ms: 120_000,
            bridge_queue_frames: 64,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum TlsPolicy {
    /// Require a valid certificate chain against the webpki roots (the
    /// public CA set). The default.
    #[default]
    Validate,
    /// Require a valid certificate chain to a single pinned CA (DER
    /// bytes), which replaces the public roots: the self-hosted
    /// deployment that trusts only what it pinned.
    ValidateCa(Vec<u8>),
    /// Trust any server certificate. For tests and explicitly unsafe
    /// local setups; never a default.
    AcceptInvalid,
}

/// A pairing room's address: what the creating device hands to the other
/// one out-of-band (QR, link, paste). The capability authorizes the room
/// join and is independent of the short code (§7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub room_id: String,
    pub capability: String,
}

/// The relay URL parsed once and reused by both hops.
#[derive(Debug, Clone)]
pub(crate) struct RelayLocation {
    /// True for `https`/`wss`.
    pub secure: bool,
    /// `host:port` for the TCP connect and the Host header.
    pub authority: String,
    /// The host part, used for SNI and TLS server-name verification.
    pub host: String,
}

impl RelayLocation {
    pub fn parse(relay_url: &str) -> Result<Self, crate::error::WsPairingError> {
        use crate::error::WsPairingError;
        let (scheme, rest) = relay_url.split_once("://").ok_or_else(|| {
            WsPairingError::Protocol(format!("relay url needs a scheme: {relay_url:?}"))
        })?;
        let secure = match scheme {
            "http" | "ws" => false,
            "https" | "wss" => true,
            other => {
                return Err(WsPairingError::Protocol(format!(
                    "unsupported relay url scheme {other:?}"
                )))
            }
        };
        // Strip any path/query — the relay root is where both hops live.
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .to_owned();
        if authority.is_empty() {
            return Err(WsPairingError::Protocol(format!(
                "relay url has no host: {relay_url:?}"
            )));
        }
        let host = match authority.rsplit_once(':') {
            // IPv6 literals keep their colons; the port is after the
            // last one only when it follows a `]`.
            Some((h, p)) if !h.ends_with('[') && p.parse::<u16>().is_ok() => {
                h.trim_start_matches('[').trim_end_matches(']').to_owned()
            }
            _ => authority
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
        };
        Ok(Self {
            secure,
            authority,
            host,
        })
    }

    /// Scheme for the WebSocket hop (the REST hop needs none: it writes
    /// a relative request path under the Host header).
    pub fn ws_scheme(&self) -> &'static str {
        if self.secure {
            "wss"
        } else {
            "ws"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: &str) -> RelayLocation {
        RelayLocation::parse(url).unwrap()
    }

    #[test]
    fn both_schemes_of_both_hops_agree_on_security() {
        let plain = parse("http://127.0.0.1:8080");
        assert!(!plain.secure);
        assert_eq!(plain.ws_scheme(), "ws");
        assert_eq!(plain.authority, "127.0.0.1:8080");
        assert_eq!(plain.host, "127.0.0.1");

        let secure = parse("wss://relay.example.com");
        assert!(secure.secure);
        assert_eq!(secure.ws_scheme(), "wss");
        assert_eq!(secure.authority, "relay.example.com");
        assert_eq!(secure.host, "relay.example.com");
    }

    #[test]
    fn paths_queries_and_ipv6_literals_are_handled() {
        let url = parse("ws://[::1]:9000/base");
        assert_eq!(url.authority, "[::1]:9000");
        assert_eq!(url.host, "::1");
        let url = parse("https://relay.example.com:8443/prefix?x=1");
        assert_eq!(url.authority, "relay.example.com:8443");
        assert_eq!(url.host, "relay.example.com");
    }

    #[test]
    fn garbage_urls_are_protocol_errors() {
        assert!(RelayLocation::parse("relay.example.com").is_err());
        assert!(RelayLocation::parse("ftp://relay.example.com").is_err());
        assert!(RelayLocation::parse("http://").is_err());
    }
}
