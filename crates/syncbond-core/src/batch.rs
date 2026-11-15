//! Bounded operation batches (todo.md DSR-28): oplog operations cross the
//! relay **only** as encrypted envelopes, packed into batches that satisfy
//! the relay contract's network limits — at most 16 envelopes per batch,
//! 4 MiB on the wire each, 8 MiB per batch total
//! ([`syncbond_relay_protocol::limits`]).
//!
//! The packing rules, pinned here so callers cannot get them wrong:
//!
//! - **One operation = one envelope.** Operations are never split across
//!   envelopes (a half-operation is not a deduplicable unit) and never
//!   merged (a tampered or reordered batch must corrupt at most the
//!   envelopes it touches). A log larger than one batch becomes several
//!   batches; a single operation that cannot fit one envelope on the wire
//!   is a typed error, not a silent truncation.
//! - **Measured, not guessed.** Each envelope's wire size is measured by
//!   serializing the exact wire JSON (the base64url expansion and the
//!   field overhead are real bytes), so the cap checks are against the
//!   truth; the final batches are re-checked with the contract's own
//!   `check_batch` as defense in depth.
//! - **Nothing plaintext leaves.** The only wire shape is
//!   [`syncbond_relay_protocol::dto::Envelope`]; its nonce and ciphertext
//!   are base64url text and the relay never sees keys or payloads.

use std::collections::HashSet;

use crate::crypto::{b64url_decode, b64url_encode, CryptoError, EncryptedEnvelope, KeyRing};
use crate::replication::Operation;
use syncbond_relay_protocol::dto::Envelope as WireEnvelope;
use syncbond_relay_protocol::limits::{
    check_batch, MAX_BATCH_BYTES, MAX_BATCH_COUNT, MAX_ENVELOPE_BYTES,
};

/// Typed failures of the batch codec. Send-side failures name the
/// operation that could not ship; receive-side failures carry the core's
/// crypto verdicts verbatim.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum BatchError {
    /// The operation's encrypted envelope cannot fit one wire envelope,
    /// and an operation is never split. Ship smaller payloads.
    #[error("operation #{index} does not fit one envelope: {payload_len}-byte payload serializes to {wire_len} bytes on the wire (cap {wire_cap})")]
    OperationTooLarge {
        index: usize,
        payload_len: usize,
        wire_len: usize,
        wire_cap: usize,
    },
    #[error("batch encoding: {0}")]
    Encoding(String),
    #[error("envelope decode: {0}")]
    Decode(String),
    /// The contract's own batch check refused a packed batch — a packing
    /// bug, surfaced honestly rather than shipped.
    #[error("wire batch rejected: {0}")]
    Wire(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The envelope names a key epoch this keyring does not hold (a
    /// rotation this device has not been told about). It must not be
    /// opened with a guessed key.
    #[error("no key for envelope key epoch {0}")]
    MissingKeyEpoch(u64),
}

/// Seal operations into wire batches under the contract's limits. Each
/// batch passes [`check_batch`]; the concatenation of opening every batch
/// yields exactly the input operations, in order. An empty log yields no
/// batches — the relay rejects empty batches, so none are produced.
pub fn seal_operations(
    operations: &[Operation],
    keyring: &KeyRing,
    sender_device_id: &str,
) -> Result<Vec<Vec<WireEnvelope>>, BatchError> {
    let key = keyring.current_key();
    let epoch = keyring.current_epoch();
    let group_id = &keyring.group_id;

    let mut batches: Vec<Vec<WireEnvelope>> = Vec::new();
    let mut batch: Vec<WireEnvelope> = Vec::new();
    let mut batch_bytes = 0usize;

    for (index, operation) in operations.iter().enumerate() {
        let plaintext = serde_json::to_vec(operation)
            .map_err(|error| BatchError::Encoding(error.to_string()))?;
        let envelope = crate::crypto::seal(key, group_id, sender_device_id, epoch, &plaintext);
        let wire = to_wire(&envelope);
        // Measure the real wire JSON: base64url expansion and field
        // overhead included. No constant arithmetic to drift.
        let serialized =
            serde_json::to_vec(&wire).map_err(|error| BatchError::Encoding(error.to_string()))?;
        if serialized.len() > MAX_ENVELOPE_BYTES {
            return Err(BatchError::OperationTooLarge {
                index,
                payload_len: operation.payload.len(),
                wire_len: serialized.len(),
                wire_cap: MAX_ENVELOPE_BYTES,
            });
        }
        // Close the current batch when this envelope would break a limit;
        // a fresh batch always accepts one envelope (both caps exceed the
        // per-envelope cap).
        if !batch.is_empty()
            && (batch.len() >= MAX_BATCH_COUNT || batch_bytes + serialized.len() > MAX_BATCH_BYTES)
        {
            batches.push(std::mem::take(&mut batch));
            batch_bytes = 0;
        }
        batch_bytes += serialized.len();
        batch.push(wire);
    }
    if !batch.is_empty() {
        batches.push(batch);
    }

    // Defense in depth: the packing above must satisfy the contract's own
    // check; if it ever does not, fail here rather than on the wire.
    for packed in &batches {
        check_batch(packed).map_err(|error| BatchError::Wire(error.to_string()))?;
    }
    Ok(batches)
}

/// Open a batch of wire envelopes back into operations, verifying each
/// envelope exactly as [`crate::crypto::open`] does (version, group, key
/// epoch possession, replay, AEAD). The replay set is the caller's: a
/// batch delivered twice, or two batches sharing an envelope, cannot
/// revive a message id.
pub fn open_operations(
    envelopes: &[WireEnvelope],
    keyring: &KeyRing,
    seen_message_ids: &mut HashSet<String>,
) -> Result<Vec<Operation>, BatchError> {
    let mut operations = Vec::with_capacity(envelopes.len());
    for envelope in envelopes {
        let core = from_wire(envelope)?;
        let key = keyring
            .key_for(core.key_epoch)
            .ok_or(BatchError::MissingKeyEpoch(core.key_epoch))?;
        let mut ctx = crate::crypto::EnvelopeContext {
            group_id: &keyring.group_id,
            // Possession was the epoch check: open the envelope under the
            // exact key it names.
            current_key_epoch: core.key_epoch,
            seen_message_ids,
        };
        let plaintext = crate::crypto::open(key, &core, &mut ctx)?;
        let operation: Operation = serde_json::from_slice(&plaintext)
            .map_err(|error| BatchError::Decode(format!("operation payload: {error}")))?;
        operations.push(operation);
    }
    Ok(operations)
}

/// Core envelope (raw nonce/ciphertext) to the wire shape (base64url
/// text) the relay stores and forwards.
pub fn to_wire(envelope: &EncryptedEnvelope) -> WireEnvelope {
    WireEnvelope {
        protocol_version: envelope.protocol_version,
        group_id: envelope.group_id.clone(),
        sender_device_id: envelope.sender_device_id.clone(),
        key_epoch: envelope.key_epoch,
        message_id: envelope.message_id.clone(),
        nonce: b64url_encode(&envelope.nonce),
        ciphertext: b64url_encode(&envelope.ciphertext),
    }
}

/// Wire shape back to the core envelope. Only base-level decoding happens
/// here; every protocol check belongs to [`crate::crypto::open`].
pub fn from_wire(envelope: &WireEnvelope) -> Result<EncryptedEnvelope, BatchError> {
    let nonce_bytes = b64url_decode(&envelope.nonce)
        .map_err(|error| BatchError::Decode(format!("nonce: {error}")))?;
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| BatchError::Decode("nonce must decode to 24 bytes".into()))?;
    let ciphertext = b64url_decode(&envelope.ciphertext)
        .map_err(|error| BatchError::Decode(format!("ciphertext: {error}")))?;
    Ok(EncryptedEnvelope {
        protocol_version: envelope.protocol_version,
        group_id: envelope.group_id.clone(),
        sender_device_id: envelope.sender_device_id.clone(),
        key_epoch: envelope.key_epoch,
        message_id: envelope.message_id.clone(),
        nonce,
        ciphertext,
    })
}
