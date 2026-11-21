//! Getting member-set records to exactly the devices that may hold them.
//!
//! A rotation distribution carries the new group key, and the removed
//! member still holds the old one — so it must never ride the group
//! channel, where the removed member could read it. The seam hands each
//! recipient's bytes to a channel bound to that one device; which
//! transport that is (a pairwise session, a push service, a courier) is
//! the application's choice, never core's.

use crate::member_crypto::RotationResult;
use thiserror::Error;

/// A channel carrying member-set records to devices that may hold them.
/// The implementation is the application's routing to its per-device
/// pairwise channels; it must refuse a target it has no safe channel for
/// — that refusal is what keeps a record off a channel the removed member
/// can read.
pub trait MemberChannel {
    /// Deliver bytes to `device_id`. Refuse with
    /// [`MemberChannelError::NotRecipient`] when the channel is not bound
    /// to that device.
    fn deliver(&self, device_id: &str, bytes: &[u8]) -> Result<(), MemberChannelError>;
}

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum MemberChannelError {
    #[error("channel is bound to {bound}, not recipient {asked}")]
    NotRecipient { bound: String, asked: String },
    #[error("channel to {0} failed: {1}")]
    Delivery(String, String),
}

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DeliveryError {
    #[error("delivery to {recipient} failed after delivering to {delivered:?}: {error}")]
    Partial {
        recipient: String,
        delivered: Vec<String>,
        error: MemberChannelError,
    },
}

/// Hand bytes to every named recipient over its own channel. Stops at the
/// first failure and reports both the acknowledged deliveries and the
/// failed recipient, so the caller can retry the rest.
pub fn deliver_to_members(
    channel: &dyn MemberChannel,
    recipients: &[String],
    bytes: &[u8],
) -> Result<Vec<String>, DeliveryError> {
    let mut delivered = Vec::new();
    for recipient in recipients {
        match channel.deliver(recipient, bytes) {
            Ok(()) => delivered.push(recipient.clone()),
            Err(error) => {
                return Err(DeliveryError::Partial {
                    recipient: recipient.clone(),
                    delivered,
                    error,
                });
            }
        }
    }
    Ok(delivered)
}

/// Hand one rotation distribution to every surviving member, each over
/// that device's own channel. The removed device is never a recipient —
/// it is absent from `member_ids` by construction — and the group channel
/// is never touched: the removed member still holds the pre-rotation key,
/// so a distribution byte there would be readable by it.
pub fn deliver_rotation(
    channel: &dyn MemberChannel,
    result: &RotationResult,
) -> Result<Vec<String>, DeliveryError> {
    deliver_to_members(channel, &result.member_ids, &result.distribution)
}
