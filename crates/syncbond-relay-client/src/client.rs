//! The relay channel client: provisioning, append, pull. Each method is
//! one frozen v1 request shape; every failure arrives typed.

use std::time::Duration;

use syncbond_relay_protocol::dto::{
    AppendAck, AppendRequest, ChannelCreated, CredentialIssued, CredentialScope, Envelope,
    IssueCredentialRequest, PullRequest, PullResponse,
};
use syncbond_relay_protocol::RELAY_PROTOCOL_VERSION;

use crate::error::RelayClientError;
use crate::http;
use crate::tls::TlsPolicy;

/// Where the relay serves: `https://host:port`, `http://host:port`, or a
/// bare `host:port` (plain HTTP — the local development shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLocation {
    pub host: String,
    pub port: u16,
    pub secure: bool,
}

impl RelayLocation {
    /// `host:port` as TCP connect and the `Host` header use it.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn parse(relay_url: &str) -> Result<Self, RelayClientError> {
        let trimmed = relay_url.trim();
        let (secure, rest) = if let Some(rest) = trimmed.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = trimmed.strip_prefix("http://") {
            (false, rest)
        } else {
            (false, trimmed)
        };
        let rest = rest.trim_end_matches('/');
        if rest.is_empty() {
            return Err(RelayClientError::Protocol(format!(
                "relay location has no host: {relay_url}"
            )));
        }
        // IPv6 literals are out of scope: the relay contract's examples
        // are host names and IPv4.
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => {
                if host.is_empty() {
                    return Err(RelayClientError::Protocol(format!(
                        "relay location has no host: {relay_url}"
                    )));
                }
                let port = port.parse::<u16>().map_err(|_| {
                    RelayClientError::Protocol(format!("relay port is not a number: {port}"))
                })?;
                (host.to_owned(), port)
            }
            None => (rest.to_owned(), if secure { 443 } else { 80 }),
        };
        Ok(Self { host, port, secure })
    }
}

/// The HTTP client for the relay's channel contract.
#[derive(Debug, Clone)]
pub struct RelayClient {
    location: RelayLocation,
    tls: TlsPolicy,
    timeout: Duration,
}

impl RelayClient {
    pub fn new(
        relay_url: &str,
        tls: TlsPolicy,
        timeout: Duration,
    ) -> Result<Self, RelayClientError> {
        Ok(Self {
            location: RelayLocation::parse(relay_url)?,
            tls,
            timeout,
        })
    }

    /// `POST /v1/channels` (admin): one channel, its id.
    pub async fn create_channel(
        &self,
        admin_token: &str,
        request_id: &str,
    ) -> Result<ChannelCreated, RelayClientError> {
        // The relay's create-channel body is not in the shared DTO set;
        // the shape is frozen on both ends.
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CreateChannelBody<'a> {
            protocol_version: u16,
            request_id: &'a str,
        }
        let body = serde_json::to_vec(&CreateChannelBody {
            protocol_version: RELAY_PROTOCOL_VERSION,
            request_id,
        })
        .expect("a closed-shape body always serializes");
        let response = http::request(
            &self.location,
            &self.tls,
            "POST",
            "/v1/channels",
            Some(admin_token),
            Some(&body),
            self.timeout,
        )
        .await?;
        http::expect_json(&self.location, response, 201, "channel creation")
    }

    /// `POST /v1/channels/{channel_id}/credentials` (admin): the token
    /// is shown exactly once — the relay keeps only its digest.
    pub async fn issue_credential(
        &self,
        admin_token: &str,
        channel_id: &str,
        scopes: &[CredentialScope],
        label: Option<&str>,
        request_id: &str,
    ) -> Result<CredentialIssued, RelayClientError> {
        let body = serde_json::to_vec(&IssueCredentialRequest {
            protocol_version: RELAY_PROTOCOL_VERSION,
            request_id: request_id.to_owned(),
            scopes: scopes.to_vec(),
            label: label.map(str::to_owned),
        })
        .expect("a closed-shape DTO always serializes");
        let response = http::request(
            &self.location,
            &self.tls,
            "POST",
            &format!("/v1/channels/{channel_id}/credentials"),
            Some(admin_token),
            Some(&body),
            self.timeout,
        )
        .await?;
        http::expect_json(&self.location, response, 201, "credential issuance")
    }

    /// `POST /v1/channels/{channel_id}/append`: acks come back only for
    /// envelopes the relay made durable; a retry of the same envelope
    /// hits the `(channel, messageId)` idempotency record.
    pub async fn append(
        &self,
        channel_token: &str,
        channel_id: &str,
        envelopes: &[Envelope],
        request_id: &str,
    ) -> Result<AppendAck, RelayClientError> {
        let body = serde_json::to_vec(&AppendRequest {
            protocol_version: RELAY_PROTOCOL_VERSION,
            request_id: request_id.to_owned(),
            envelopes: envelopes.to_vec(),
        })
        .expect("a closed-shape DTO always serializes");
        let response = http::request(
            &self.location,
            &self.tls,
            "POST",
            &format!("/v1/channels/{channel_id}/append"),
            Some(channel_token),
            Some(&body),
            self.timeout,
        )
        .await?;
        http::expect_json(&self.location, response, 200, "append")
    }

    /// `POST /v1/channels/{channel_id}/pull`: entries after the caller's
    /// committed cursor, ascending and contiguous; an empty page
    /// preserves the input cursor.
    pub async fn pull(
        &self,
        channel_token: &str,
        channel_id: &str,
        after: u64,
        limit: Option<u16>,
        max_bytes: Option<u64>,
        request_id: &str,
    ) -> Result<PullResponse, RelayClientError> {
        let body = serde_json::to_vec(&PullRequest {
            protocol_version: RELAY_PROTOCOL_VERSION,
            request_id: request_id.to_owned(),
            after,
            limit,
            max_bytes,
        })
        .expect("a closed-shape DTO always serializes");
        let response = http::request(
            &self.location,
            &self.tls,
            "POST",
            &format!("/v1/channels/{channel_id}/pull"),
            Some(channel_token),
            Some(&body),
            self.timeout,
        )
        .await?;
        http::expect_json(&self.location, response, 200, "pull")
    }
}
