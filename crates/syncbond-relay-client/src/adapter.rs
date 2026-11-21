//! The bridge from the async relay client to the core driver's sync
//! seam. The driver loop is synchronous; every call hops into an
//! existing tokio runtime. Run the driver on a plain thread, never
//! inside the runtime itself — `block_on` may not nest.

use syncbond_core::sync_driver::{ChannelTransport, TransportFailure};
use syncbond_relay_protocol::dto::{Envelope, EnvelopeAck, PullResponse};
use tokio::runtime::Handle;

use crate::client::RelayClient;
use crate::error::RelayClientError;

/// One bound (client, channel, token) serving the core driver.
#[derive(Clone)]
pub struct DriverTransport {
    client: RelayClient,
    channel_id: String,
    channel_token: String,
    runtime: Handle,
}

impl DriverTransport {
    pub fn new(
        client: RelayClient,
        channel_id: impl Into<String>,
        channel_token: impl Into<String>,
        runtime: Handle,
    ) -> Self {
        Self {
            client,
            channel_id: channel_id.into(),
            channel_token: channel_token.into(),
            runtime,
        }
    }
}

/// The relay echoes request ids; the driver never correlates by them, so
/// one stable literal is honest here.
const REQUEST_ID: &str = "r-driver-00000001";

impl ChannelTransport for DriverTransport {
    fn append(&self, envelopes: &[Envelope]) -> Result<Vec<EnvelopeAck>, TransportFailure> {
        let client = self.client.clone();
        let (token, channel) = (self.channel_token.clone(), self.channel_id.clone());
        let envelopes = envelopes.to_vec();
        self.runtime
            .block_on(async move {
                client
                    .append(&token, &channel, &envelopes, REQUEST_ID)
                    .await
            })
            .map(|ack| ack.acks)
            .map_err(classify)
    }

    fn pull(&self, after: u64, limit: u16) -> Result<PullResponse, TransportFailure> {
        let client = self.client.clone();
        let (token, channel) = (self.channel_token.clone(), self.channel_id.clone());
        self.runtime
            .block_on(async move {
                client
                    .pull(&token, &channel, after, Some(limit), None, REQUEST_ID)
                    .await
            })
            .map_err(classify)
    }
}

/// Timeouts and refused connections are worth a bounded retry; a refused
/// credential or a broken contract is not.
fn classify(error: RelayClientError) -> TransportFailure {
    match &error {
        RelayClientError::Timeout | RelayClientError::Io(_) => {
            TransportFailure::Transient(error.to_string())
        }
        RelayClientError::Relay { status, .. } if *status >= 500 => {
            TransportFailure::Transient(error.to_string())
        }
        _ => TransportFailure::Fatal(error.to_string()),
    }
}
