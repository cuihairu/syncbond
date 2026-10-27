//! Pluggable conflict resolution.
//!
//! The SDK never decides what data means: applications pick or implement a
//! `MergeStrategy`. The built-ins (HLC-LWW with tombstones, OR-Set,
//! PN-Counter) are optional conveniences, not imposed semantics. See
//! docs/design/merge.md.

use crate::hlc::{compare_stamps, HlcStamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// A synced record. `payload` is opaque to the SDK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub key: String,
    pub payload: Vec<u8>,
    pub deleted: bool,
    pub stamp: HlcStamp,
    /// Writer's causal witness at write time: node_id -> last-seen stamp.
    pub witness: HashMap<String, HlcStamp>,
    /// Concurrent versions retained for application resolution.
    #[serde(default)]
    pub conflicts: Vec<Record>,
}

impl Record {
    pub fn new(
        key: impl Into<String>,
        payload: Vec<u8>,
        deleted: bool,
        stamp: HlcStamp,
        witness: HashMap<String, HlcStamp>,
    ) -> Self {
        Self {
            key: key.into(),
            payload,
            deleted,
            stamp,
            witness,
            conflicts: Vec::new(),
        }
    }
}

pub struct MergeContext {
    pub now_ms: u64,
    pub max_skew_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MergeError {
    #[error("invalid OR-Set payload: {0}")]
    InvalidOrSet(String),
    #[error("invalid PN-Counter payload: {0}")]
    InvalidPnCounter(String),
}

#[derive(Debug, PartialEq)]
pub struct MergeOutcome {
    pub record: Record,
    /// True when the merge found genuinely concurrent writes (both kept).
    pub concurrent: bool,
    /// True when the incoming stamp claimed a wall time beyond the skew
    /// bound; the write is kept as a flagged concurrent version instead of
    /// silently overwriting local state.
    pub skew_detected: bool,
}

pub trait MergeStrategy: Send + Sync {
    fn merge(
        &self,
        local: Option<&Record>,
        incoming: &Record,
        ctx: &MergeContext,
    ) -> Result<MergeOutcome, MergeError>;
}

/// True when `witness` shows its writer had seen `record` (causally after).
/// The witness stores the last-seen full stamp per node; absence means
/// "never saw that node".
fn saw_version(witness: &HashMap<String, HlcStamp>, record: &Record) -> bool {
    witness
        .get(&record.stamp.id)
        .is_some_and(|seen| compare_stamps(seen, &record.stamp) != std::cmp::Ordering::Less)
}

/// The later of two stamps.
fn max_stamp(a: &HlcStamp, b: &HlcStamp) -> HlcStamp {
    if compare_stamps(a, b) == std::cmp::Ordering::Greater {
        b.clone()
    } else {
        a.clone()
    }
}

/// Union of two witnesses, keeping the later stamp per node. Direction
/// independent, so both replicas of a merge agree on the merged record.
fn union_witness(
    a: &HashMap<String, HlcStamp>,
    b: &HashMap<String, HlcStamp>,
) -> HashMap<String, HlcStamp> {
    let mut out = a.clone();
    for (node, stamp) in b {
        let newer = out
            .get(node)
            .is_none_or(|seen| compare_stamps(seen, stamp) != std::cmp::Ordering::Greater);
        if newer {
            out.insert(node.clone(), stamp.clone());
        }
    }
    out
}

fn dedupe_conflicts(list: Vec<Record>) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    for record in list {
        if !out.iter().any(|r| r.stamp == record.stamp) {
            out.push(record);
        }
    }
    out
}

/// Built-in default: HLC-ordered last-writer-wins with causal tombstones.
///
/// - Causally ordered writes: the descendant wins (an old device reconnecting
///   cannot resurrect a deleted record).
/// - Concurrent writes: kept — the higher stamp becomes primary, the loser is
///   retained in `conflicts` for the application.
/// - Run-ahead clocks: a stamp beyond the skew bound never silently wins.
pub struct LwwHlc;

impl MergeStrategy for LwwHlc {
    fn merge(
        &self,
        local: Option<&Record>,
        incoming: &Record,
        ctx: &MergeContext,
    ) -> Result<MergeOutcome, MergeError> {
        let local = match local {
            None => {
                return Ok(MergeOutcome {
                    record: incoming.clone(),
                    concurrent: false,
                    skew_detected: false,
                });
            }
            Some(local) => local,
        };
        if local.stamp == incoming.stamp {
            return Ok(MergeOutcome {
                record: local.clone(),
                concurrent: false,
                skew_detected: false,
            });
        }

        let local_after = saw_version(&local.witness, incoming);
        let incoming_after = saw_version(&incoming.witness, local);

        if local_after && !incoming_after {
            return Ok(MergeOutcome {
                record: local.clone(),
                concurrent: false,
                skew_detected: false,
            });
        }
        if incoming_after && !local_after {
            return Ok(MergeOutcome {
                record: incoming.clone(),
                concurrent: false,
                skew_detected: false,
            });
        }

        // Concurrent (or causally unrelated). A run-ahead clock must not win.
        let skew_detected = incoming.stamp.pt.saturating_sub(ctx.now_ms) > ctx.max_skew_ms;
        let (primary, loser) = if skew_detected {
            (local, incoming)
        } else if compare_stamps(&incoming.stamp, &local.stamp) > std::cmp::Ordering::Equal {
            (incoming, local)
        } else {
            (local, incoming)
        };
        let mut merged = primary.clone();
        let mut pool = primary.conflicts.clone();
        pool.push(loser.clone());
        pool.extend(loser.conflicts.iter().cloned());
        merged.conflicts = dedupe_conflicts(pool);
        Ok(MergeOutcome {
            record: merged,
            concurrent: true,
            skew_detected,
        })
    }
}

/// OR-Set (observed-remove set) for favorites/tags. Concurrent add wins over
/// a remove that never observed the add. The document is stored as the
/// record payload in its canonical JSON encoding; this strategy interprets
/// only that encoding, not the application meaning of the elements.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OrSetDoc {
    /// element -> observed add tags
    pub adds: HashMap<String, Vec<String>>,
    /// retired tags
    pub rems: Vec<String>,
}

/// Deterministic wire shape: elements and tags sorted, so two replicas that
/// merge the same two documents produce byte-identical payloads.
#[derive(Serialize)]
struct OrSetWire<'a> {
    adds: BTreeMap<&'a str, Vec<&'a str>>,
    rems: Vec<&'a str>,
}

pub struct OrSetStrategy;

impl OrSetStrategy {
    pub fn encode(doc: &OrSetDoc) -> Vec<u8> {
        let adds: BTreeMap<&str, Vec<&str>> = doc
            .adds
            .iter()
            .map(|(element, tags)| {
                let mut tags: Vec<&str> = tags.iter().map(String::as_str).collect();
                tags.sort_unstable();
                tags.dedup();
                (element.as_str(), tags)
            })
            .collect();
        let mut rems: Vec<&str> = doc.rems.iter().map(String::as_str).collect();
        rems.sort_unstable();
        rems.dedup();
        serde_json::to_vec(&OrSetWire { adds, rems })
            .expect("OR-Set doc serialization is infallible")
    }

    pub fn decode(payload: &[u8]) -> Result<OrSetDoc, MergeError> {
        serde_json::from_slice(payload).map_err(|error| MergeError::InvalidOrSet(error.to_string()))
    }

    /// Live elements, sorted so callers see the same order on every replica.
    pub fn live(doc: &OrSetDoc) -> Vec<String> {
        let mut live: Vec<String> = doc
            .adds
            .iter()
            .filter(|(_, tags)| tags.iter().any(|t| !doc.rems.contains(t)))
            .map(|(el, _)| el.clone())
            .collect();
        live.sort();
        live
    }
}

impl MergeStrategy for OrSetStrategy {
    fn merge(
        &self,
        local: Option<&Record>,
        incoming: &Record,
        _ctx: &MergeContext,
    ) -> Result<MergeOutcome, MergeError> {
        let mut doc = local
            .map(|r| Self::decode(&r.payload))
            .transpose()?
            .unwrap_or_default();
        let remote = Self::decode(&incoming.payload)?;
        for (el, tags) in remote.adds {
            let entry = doc.adds.entry(el).or_default();
            for tag in tags {
                if !entry.contains(&tag) {
                    entry.push(tag);
                }
            }
        }
        for tag in remote.rems {
            if !doc.rems.contains(&tag) {
                doc.rems.push(tag);
            }
        }
        let merged = Record {
            key: local
                .as_ref()
                .map_or_else(|| incoming.key.clone(), |r| r.key.clone()),
            payload: Self::encode(&doc),
            deleted: false,
            // The union loses nothing, so no conflict is retained and the
            // merged record sits at the later of the two stamps; both
            // directions of the merge produce the same record.
            stamp: max_stamp(
                local.as_ref().map(|r| &r.stamp).unwrap_or(&incoming.stamp),
                &incoming.stamp,
            ),
            witness: union_witness(
                local
                    .as_ref()
                    .map(|r| &r.witness)
                    .unwrap_or(&HashMap::new()),
                &incoming.witness,
            ),
            conflicts: Vec::new(),
        };
        Ok(MergeOutcome {
            record: merged,
            concurrent: false,
            skew_detected: false,
        })
    }
}

/// Positive-negative counter (two G-Counters), per-slot max merge.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PnCounterDoc {
    pub p: HashMap<String, u64>,
    pub n: HashMap<String, u64>,
}

/// Deterministic wire shape for slot counters; see `OrSetWire`.
#[derive(Serialize)]
struct PnCounterWire {
    n: BTreeMap<String, u64>,
    p: BTreeMap<String, u64>,
}

pub struct PnCounterStrategy;

impl PnCounterStrategy {
    pub fn encode(doc: &PnCounterDoc) -> Vec<u8> {
        // Sorted slot order, like OR-Set: two replicas that merge the same
        // documents must produce byte-identical payloads.
        let slots = |slots: &HashMap<String, u64>| -> BTreeMap<String, u64> {
            slots
                .iter()
                .map(|(slot, value)| (slot.clone(), *value))
                .collect()
        };
        serde_json::to_vec(&PnCounterWire {
            n: slots(&doc.n),
            p: slots(&doc.p),
        })
        .expect("PN-Counter doc serialization is infallible")
    }

    pub fn decode(payload: &[u8]) -> Result<PnCounterDoc, MergeError> {
        serde_json::from_slice(payload)
            .map_err(|error| MergeError::InvalidPnCounter(error.to_string()))
    }

    pub fn value(doc: &PnCounterDoc) -> i64 {
        let p: u64 = doc.p.values().sum();
        let n: u64 = doc.n.values().sum();
        p as i64 - n as i64
    }
}

fn merge_slot_maps(a: &HashMap<String, u64>, b: &HashMap<String, u64>) -> HashMap<String, u64> {
    let mut out = a.clone();
    for (k, v) in b {
        let slot = out.entry(k.clone()).or_insert(0);
        *slot = (*slot).max(*v);
    }
    out
}

impl MergeStrategy for PnCounterStrategy {
    fn merge(
        &self,
        local: Option<&Record>,
        incoming: &Record,
        _ctx: &MergeContext,
    ) -> Result<MergeOutcome, MergeError> {
        let doc = match local {
            Some(local) => {
                let a = Self::decode(&local.payload)?;
                let b = Self::decode(&incoming.payload)?;
                PnCounterDoc {
                    p: merge_slot_maps(&a.p, &b.p),
                    n: merge_slot_maps(&a.n, &b.n),
                }
            }
            None => Self::decode(&incoming.payload)?,
        };
        let local_witness = local
            .as_ref()
            .map_or_else(HashMap::new, |r| r.witness.clone());
        let merged = Record {
            key: local
                .as_ref()
                .map_or_else(|| incoming.key.clone(), |r| r.key.clone()),
            payload: Self::encode(&doc),
            deleted: false,
            // Per-slot max loses nothing, so no conflict is retained and the
            // merged record sits at the later of the two stamps.
            stamp: max_stamp(
                local.as_ref().map(|r| &r.stamp).unwrap_or(&incoming.stamp),
                &incoming.stamp,
            ),
            witness: union_witness(&local_witness, &incoming.witness),
            conflicts: Vec::new(),
        };
        Ok(MergeOutcome {
            record: merged,
            concurrent: false,
            skew_detected: false,
        })
    }
}
