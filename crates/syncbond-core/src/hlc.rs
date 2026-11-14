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

/// Advance a (pt, ct) pair by one logical step. When the counter saturates at
/// u64::MAX (e.g. after absorbing a malicious remote stamp), carry into
/// physical time so the resulting stamp is strictly greater in the (pt, ct)
/// lexicographic order. This keeps every issued stamp totally ordered and
/// unique even under counter saturation, except at the absolute boundary
/// pt == ct == u64::MAX where no strictly greater stamp is representable and
/// the pair saturates in place (never regressing in the ordering).
fn advance(pt: u64, ct: u64) -> (u64, u64) {
    if ct == u64::MAX {
        if pt == u64::MAX {
            // Both fields are at the absolute maximum: no strictly greater
            // stamp is representable, so saturate in place rather than rolling
            // ct back to 0, which would regress in the (pt, ct) lexicographic
            // order and break the monotonic ordering invariant.
            (pt, ct)
        } else {
            (pt + 1, 0)
        }
    } else {
        (pt, ct + 1)
    }
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
            // A remote stamp can drive ct to u64::MAX; carry into pt so the
            // stamp remains strictly greater than everything issued before.
            let (pt, ct) = advance(self.pt, self.ct);
            self.pt = pt;
            self.ct = ct;
        }
        HlcStamp {
            pt: self.pt,
            ct: self.ct,
            id: self.node_id.clone(),
        }
    }

    /// Rebuild a clock from a persisted high-water state (crash restart).
    ///
    /// `pt`/`ct` must be the greatest stamp this node knows about — the
    /// snapshot's own high-water and the maximum over its persisted oplog.
    /// Every stamp `issue` then returns is strictly greater than that
    /// state (a wall time above it resets the counter, at or below it
    /// advances it), so a same-millisecond restart, a wall-clock rollback
    /// or a future-dated op in the log cannot repeat a stamp.
    pub fn restored(
        node_id: impl Into<String>,
        max_skew_ms: u64,
        now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
        pt: u64,
        ct: u64,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            max_skew_ms,
            pt,
            ct,
            now_ms,
        }
    }

    /// Persisted high-water state: `(pt, ct)`.
    pub fn hlc_state(&self) -> (u64, u64) {
        (self.pt, self.ct)
    }

    /// Absorb a remote stamp without issuing a local one (receive path).
    ///
    /// Errors — leaving the clock untouched — when the stamp claims a wall
    /// time more than `max_skew_ms` ahead of local time: a broken remote
    /// clock must not pollute the local one.
    pub fn observe(&mut self, remote: &HlcStamp) -> Result<(), ClockError> {
        let wall = (self.now_ms)();
        if remote.pt.saturating_sub(wall) > self.max_skew_ms {
            return Err(ClockError::Skew {
                ahead_ms: remote.pt.saturating_sub(wall),
                limit_ms: self.max_skew_ms,
            });
        }
        let pt = self.pt.max(wall).max(remote.pt);
        let (pt, ct) = if pt == self.pt && pt == remote.pt {
            advance(pt, self.ct.max(remote.ct))
        } else if pt == remote.pt {
            advance(pt, remote.ct)
        } else if pt == self.pt {
            advance(pt, self.ct)
        } else {
            (pt, 0)
        };
        self.pt = pt;
        self.ct = ct;
        Ok(())
    }

    /// Absorb a remote stamp; returns our next local stamp.
    ///
    /// Errors when the remote stamp claims a wall time more than
    /// `max_skew_ms` ahead of local time: the caller must treat such writes
    /// as concurrent (kept, flagged) instead of letting the runaway clock
    /// overwrite local state.
    pub fn receive(&mut self, remote: &HlcStamp) -> Result<HlcStamp, ClockError> {
        self.observe(remote)?;
        Ok(HlcStamp {
            pt: self.pt,
            ct: self.ct,
            id: self.node_id.clone(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    #[error("remote clock runs {ahead_ms}ms ahead (limit {limit_ms}ms); refusing to adopt")]
    Skew { ahead_ms: u64, limit_ms: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_carries_at_max_counter() {
        let mut clock = HybridClock::with_clock("node-a", 1_000, Box::new(|| 10_000));
        let remote = HlcStamp {
            pt: 10_000,
            ct: u64::MAX,
            id: "node-b".into(),
        };
        let stamp = clock.receive(&remote).expect("max ct must not overflow");
        assert_eq!(stamp.ct, 0);
        assert_eq!(stamp.pt, 10_001);
    }

    /// A malicious remote stamp at u64::MAX must not make a later local
    /// `issue` overflow or repeat a stamp: carry into pt keeps every issued
    /// stamp strictly increasing and unique.
    #[test]
    fn issue_after_saturated_receive_stays_unique() {
        let mut clock = HybridClock::with_clock("node-a", 1_000, Box::new(|| 10_000));
        let remote = HlcStamp {
            pt: 10_000,
            ct: u64::MAX,
            id: "node-b".into(),
        };
        clock.receive(&remote).expect("receive succeeds");
        // Receive already carried into (pt+1, ct=0); the first issue bumps ct,
        // the second continues. All stamps must be distinct and increasing.
        let first = clock.issue();
        let second = clock.issue();
        assert_ne!(first, second);
        assert_eq!(compare_stamps(&first, &second), std::cmp::Ordering::Less);
        assert_eq!(first.pt, 10_001);
        assert_eq!(first.ct, 1);
    }

    #[test]
    fn advance_saturates_at_absolute_max() {
        assert_eq!(advance(u64::MAX - 1, u64::MAX), (u64::MAX, 0));
        assert_eq!(advance(u64::MAX, u64::MAX), (u64::MAX, u64::MAX));
        assert_eq!(advance(10, 10), (10, 11));
    }

    /// A remote stamp already at the absolute maximum must not roll the
    /// counter back to 0, which would produce a stamp smaller than everything
    /// issued before and break the monotonic ordering invariant.
    #[test]
    fn advance_at_absolute_max_never_regresses() {
        let mut clock = HybridClock::with_clock("node-a", 1_000, Box::new(|| u64::MAX));
        let first = clock.issue();
        assert_eq!((first.pt, first.ct), (u64::MAX, 0));

        let remote = HlcStamp {
            pt: u64::MAX,
            ct: u64::MAX,
            id: "node-b".into(),
        };
        let received = clock.receive(&remote).expect("max receive succeeds");
        assert_eq!((received.pt, received.ct), (u64::MAX, u64::MAX));
        assert_eq!(compare_stamps(&first, &received), std::cmp::Ordering::Less);

        // Further local issues at the same wall ms must never produce a stamp
        // smaller than the previous one (monotonic non-regression).
        let mut prev = received;
        for _ in 0..3 {
            let next = clock.issue();
            assert_ne!(compare_stamps(&next, &prev), std::cmp::Ordering::Less);
            prev = next;
        }
    }
}
