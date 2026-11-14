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
        a.clone()
    } else {
        b.clone()
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

/// Built-in default: HLC-ordered last-writer-wins with causal tombstones.
///
/// Merge is a commutative set operation over the versions each side knows —
/// the local primary with its retained conflicts, and the incoming write
/// with the conflicts it carries:
///
/// 1. Every version whose exact stamp any version in the pool demonstrably
///    observed (per the witness — conflicts ride along with their writers'
///    witnesses) is dominated and drops out.
/// 2. The primary is the highest-stamp survivor; a run-ahead stamp beyond
///    `max_skew_ms` never wins the primary while a normal survivor exists —
///    it stays in the conflict set, flagged via `skew_detected`, so a broken
///    clock neither silently overwrites local state nor loses data.
/// 3. The merged record keeps the primary's witness plus the witnesses of
///    every dominated version: their supersession knowledge must survive
///    the drop, or a later re-delivery of an already-superseded version
///    could resurrect it as a phantom conflict.
/// 4. The conflict set is normalized: deduplicated by stamp and sorted.
///
/// Dominance and ordering read only stamps and witnesses, so every delivery
/// order of the same writes converges to the same primary and the same
/// normalized conflict set.
pub struct LwwHlc;

impl MergeStrategy for LwwHlc {
    fn merge(
        &self,
        local: Option<&Record>,
        incoming: &Record,
        ctx: &MergeContext,
    ) -> Result<MergeOutcome, MergeError> {
        let skew_detected = incoming.stamp.pt.saturating_sub(ctx.now_ms) > ctx.max_skew_ms;
        let Some(local) = local else {
            // The empty-record path runs the same skew policy: the incoming
            // write is adopted (it is the only version) but an anomalous
            // future stamp is flagged instead of silently passing.
            return Ok(MergeOutcome {
                record: incoming.clone(),
                concurrent: false,
                skew_detected,
            });
        };
        if local.stamp == incoming.stamp {
            return Ok(MergeOutcome {
                record: local.clone(),
                concurrent: false,
                skew_detected: false,
            });
        }

        // Collect every version this merge knows about, deduplicated by stamp.
        let mut versions: Vec<Record> = Vec::new();
        let mut push_version = |record: &Record| {
            if !versions.iter().any(|v| v.stamp == record.stamp) {
                versions.push(record.clone());
            }
        };
        push_version(local);
        push_version(incoming);
        for record in &local.conflicts {
            push_version(record);
        }
        for record in &incoming.conflicts {
            push_version(record);
        }

        // Drop dominated versions: a version whose stamp ANY version in the
        // pool demonstrably observed is superseded — including versions
        // riding in either side's conflict set, not just the two exchange
        // endpoints. Reading dominance over the whole pool is what makes
        // the merge a canonical function of the delivered version set: any
        // delivery order produces the same survivors. A writer's witness
        // always contains its own latest stamp, so a version is never
        // dominated by its own witness (older versions by the same writer
        // are not exempt: a newer stamp from that writer dominates them).
        let dominated = |version: &Record| {
            versions
                .iter()
                .any(|other| other.stamp != version.stamp && saw_version(&other.witness, version))
        };
        let mut survivors: Vec<&Record> = versions
            .iter()
            .filter(|version| !dominated(version))
            .collect();
        // Degenerate (mutually cyclic) witnesses could dominate every version;
        // fall back to keeping both writers rather than losing data.
        if survivors.is_empty() {
            survivors.push(local);
            survivors.push(incoming);
        }

        // The primary: the highest-stamp survivor. A run-ahead stamp never
        // wins the primary while a normal survivor exists.
        let skewed = |record: &Record| record.stamp.pt.saturating_sub(ctx.now_ms) > ctx.max_skew_ms;
        let normal: Vec<&&Record> = survivors.iter().filter(|record| !skewed(record)).collect();
        let pool: Vec<&&Record> = if normal.is_empty() {
            survivors.iter().collect()
        } else {
            normal
        };
        let primary = pool
            .iter()
            .max_by(|a, b| compare_stamps(&a.stamp, &b.stamp))
            .expect("the equal-stamp short-circuit leaves at least one survivor");

        // The merged record's witness: the primary's own witness plus the
        // witnesses of every dominated version. Dropped versions must not
        // take their supersession knowledge with them — a re-delivery of an
        // already-superseded version would otherwise survive as a phantom
        // conflict. Survivor conflicts keep their own witnesses inside the
        // conflict set (they are concurrent, not superseded).
        let mut witness = primary.witness.clone();
        for version in &versions {
            if dominated(version) {
                for (node, stamp) in &version.witness {
                    let newer = witness.get(node).is_none_or(|seen| {
                        compare_stamps(seen, stamp) != std::cmp::Ordering::Greater
                    });
                    if newer {
                        witness.insert(node.clone(), stamp.clone());
                    }
                }
            }
        }

        // Normalized conflict set: every surviving non-primary version,
        // sorted by stamp (already deduplicated by stamp).
        let mut conflicts: Vec<Record> = survivors
            .iter()
            .filter(|record| record.stamp != primary.stamp)
            .map(|record| (**record).clone())
            .collect();
        conflicts.sort_by(|a, b| compare_stamps(&a.stamp, &b.stamp));

        Ok(MergeOutcome {
            concurrent: survivors.len() > 1,
            record: Record {
                witness,
                conflicts,
                ..(**primary).clone()
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(pt: u64, ct: u64, id: &str) -> HlcStamp {
        HlcStamp {
            pt,
            ct,
            id: id.into(),
        }
    }

    #[test]
    fn max_stamp_returns_the_later_stamp() {
        let early = stamp(100, 0, "a");
        let late = stamp(200, 0, "b");
        assert_eq!(max_stamp(&early, &late), late);
        assert_eq!(max_stamp(&late, &early), late);
        // Same pt: the higher counter wins.
        assert_eq!(
            max_stamp(&stamp(100, 1, "a"), &stamp(100, 5, "b")),
            stamp(100, 5, "b")
        );
    }
}
