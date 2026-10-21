//! Hybrid Logical Clock (Kulkarni et al. 2014).
//!
//! Used by the built-in LWW strategy; a run-ahead remote clock is refused
//! instead of adopted so a broken device clock cannot silently win.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HlcStamp {
    /// Bound physical time (ms).
    pub pt: u64,
    /// Logical counter within the same pt on this node.
    pub ct: u64,
    /// Node id; makes stamps totally ordered and unique.
    pub id: String,
}

pub fn compare_stamps(a: &HlcStamp, b: &HlcStamp) -> std::cmp::Ordering {
    a.pt.cmp(&b.pt).then(a.ct.cmp(&b.ct)).then(a.id.cmp(&b.id))
}

fn wall_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct HybridClock {
    pub node_id: String,
    /// Maximum accepted run-ahead of a remote clock, in ms.
    pub max_skew_ms: u64,
    pt: u64,
    ct: u64,
    now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for HybridClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridClock")
            .field("node_id", &self.node_id)
            .field("max_skew_ms", &self.max_skew_ms)
            .field("pt", &self.pt)
            .field("ct", &self.ct)
            .finish_non_exhaustive()
    }
}

impl HybridClock {
    pub fn new(node_id: impl Into<String>, max_skew_ms: u64) -> Self {
        Self {
            node_id: node_id.into(),
            max_skew_ms,
            pt: 0,
            ct: 0,
            now_ms: Box::new(wall_now_ms),
        }
    }

    pub fn with_clock(
        node_id: impl Into<String>,
        max_skew_ms: u64,
        now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            max_skew_ms,
            pt: 0,
            ct: 0,
            now_ms,
        }
    }

    /// Timestamp a local event.
    pub fn issue(&mut self) -> HlcStamp {
        let wall = (self.now_ms)();
        if wall > self.pt {
            self.pt = wall;
            self.ct = 0;
        } else {
            self.ct += 1;
        }
        HlcStamp {
            pt: self.pt,
            ct: self.ct,
            id: self.node_id.clone(),
        }
    }

    /// Absorb a remote stamp; returns our next local stamp.
    ///
    /// Errors when the remote stamp claims a wall time more than
    /// `max_skew_ms` ahead of local time: the caller must treat such writes
    /// as concurrent (kept, flagged) instead of letting the runaway clock
    /// overwrite local state.
    pub fn receive(&mut self, remote: &HlcStamp) -> Result<HlcStamp, ClockError> {
        let wall = (self.now_ms)();
        if remote.pt.saturating_sub(wall) > self.max_skew_ms {
            return Err(ClockError::Skew {
                ahead_ms: remote.pt.saturating_sub(wall),
                limit_ms: self.max_skew_ms,
            });
        }
        let pt = self.pt.max(wall).max(remote.pt);
        let ct = if pt == self.pt && pt == remote.pt {
            self.ct.max(remote.ct) + 1
        } else if pt == remote.pt {
            remote.ct + 1
        } else if pt == self.pt {
            self.ct + 1
        } else {
            0
        };
        self.pt = pt;
        self.ct = ct;
        Ok(HlcStamp {
            pt,
            ct,
            id: self.node_id.clone(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    #[error("remote clock runs {ahead_ms}ms ahead (limit {limit_ms}ms); refusing to adopt")]
    Skew { ahead_ms: u64, limit_ms: u64 },
}
