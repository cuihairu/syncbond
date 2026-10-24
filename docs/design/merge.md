# Merge design: pluggable strategies (v1)

Status: implemented in `crates/syncbond-core/src/conflict.rs` and `src/replication.rs`.

## Principle

The SDK does not know what the data means. Merge behavior is an application choice behind one trait:

```rust
pub trait MergeStrategy: Send + Sync {
    fn merge(&self, local: Option<&Record>, incoming: &Record, ctx: &MergeContext) -> MergeOutcome;
}
```

A `Record` carries: opaque `payload`, `deleted` flag, `stamp` (HLC), `witness` (node → last-seen full HLC stamp at write time), and retained `conflicts`. The built-ins below are conveniences, never imposed semantics.

## Causality: full-stamp witness

A write's `witness` records, per node, the complete last-seen `HlcStamp` (pt, ct, id) — not just a counter. Counters reset when the HLC physical component advances, so counter-only witnesses would silently lose "has seen" facts across clock-seconds boundaries. With full stamps:

- `A` causally follows `B` iff `A.witness[B.stamp.id] >= B.stamp` (stamp ordering);
- neither-follows → concurrent.

Causally ordered merges are unambiguous and monotone; only concurrent writes reach strategy policy.

## Built-in strategies

| Strategy | Semantics | Why it is a default |
|---|---|---|
| `LwwHlc` | HLC-ordered last-writer-wins, causal tombstones, concurrent versions retained | cheapest correct default for plain attributes |
| `OrSetStrategy` | OR-Set over a canonical JSON doc (adds = element → tags, removes = retired tags) | favorites/tags: concurrent add wins over an unobserved remove |
| `PnCounterStrategy` | two G-Counters (inc/dec), per-node max merge | counters that must not lose increments offline |

### LwwHlc rules (the default)

1. Causally ordered: the descendant wins. An old device reconnecting with a stale edit cannot resurrect a deleted record — the tombstone's witness dominates (test: `old_device_reconnect_cannot_resurrect_a_delete`).
2. Concurrent writes: both kept. The higher stamp becomes primary; the loser is appended to `conflicts` (deduplicated by stamp) for the application to resolve (test: `example_2_note_documents_with_offline_conflict`).
3. Run-ahead clock: if the incoming stamp claims a wall time more than `max_skew_ms` (default 5 min) ahead, it is treated as concurrent regardless of causality — a broken device clock cannot silently overwrite local state; the skewed write is retained and flagged (test: `large_clock_skew_does_not_silently_overwrite`). The local HLC additionally refuses to adopt run-ahead remote stamps (`HybridClock::receive`).

## Tombstone garbage collection (implemented)

`Replicator::gc_tombstones(now_ms, older_than_ms)` collects a tombstone only
when **both** conditions hold:

1. **Time**: `now_ms - tombstone.stamp.pt >= older_than_ms`, and
2. **Causal dominance**: every known replica's witness dominates the
   tombstone's stamp. The witness map the replicator accumulates from op
   witnesses *is* the replica vector — no separate heartbeat protocol, it
   travels with relay sync. A replica we have no evidence about simply blocks
   collection until it is heard from again.

A collected tombstone is **not deleted**. It is compacted into a barrier
entry (`gc_barriers`, payload and retained conflicts stripped, stamp and
witness kept) and the key's oplog history collapses to its single tombstone
op. The barrier is what keeps the guarantee: a pre-delete write redelivered
after GC is rejected by the barrier instead of resurrecting the delete
(`stale_put_cannot_resurrect_a_collected_delete`). The retained tombstone op
means a fresh replica still learns about the delete, so the compacted form
costs O(1) per deleted key and never downgrades a peer's view.

Two consequences worth noting:

- Garbage-collected state is safe to restart from: barriers are part of
  `SyncState` (`#[serde(default)]`, so pre-GC snapshots load unchanged) and
  replay reproduces the compacted form (`gc_compacts_the_oplog_and_survives_a_restart`).
- A compacted peer converges with an uncompacted peer; the tombstone travels,
  the payload does not (`compacted_peer_converges_with_an_uncompacted_peer`).

The time-threshold-only degraded mode is deliberately **not** part of the
public API or the FFI surface: it waives the evidence requirement and can
re-materialize a collected key from a peer still carrying the pre-delete
history. It exists as a crate-internal test switch only
(`GcMode::TimeOnly`, exercised by `degraded_time_only_mode_skips_the_evidence_check`),
off by default and not documented as an application option.

## Convergence argument

- LWW merge is commutative and idempotent on records (same-stamp short-circuit, dedupe on conflicts).
- OR-Set union of adds/removes is a semilattice; observed-remove gives add-wins for unobserved tags.
- PN-Counter per-node max is a semilattice.
- Op delivery is idempotent (op-id dedup) and order-free for the strategies above, hence out-of-order + duplicate delivery converges (tests: `out_of_order_and_duplicate_delivery_converge`, `example_3_arbitrary_binary_records`).
