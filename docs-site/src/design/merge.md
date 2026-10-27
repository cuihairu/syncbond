# Merge design: pluggable strategies (v1)

Status: implemented in `crates/syncbond-core/src/conflict.rs` and `src/replication.rs`.

## Principle

The SDK does not know what the data means. Merge behavior is an application choice behind one trait:

```rust
pub trait MergeStrategy: Send + Sync {
    fn merge(
        &self,
        local: Option<&Record>,
        incoming: &Record,
        ctx: &MergeContext,
    ) -> Result<MergeOutcome, MergeError>;
}
```

A `Record` carries: opaque `payload`, `deleted` flag, `stamp` (HLC), `witness` (node → last-seen full HLC stamp at write time), and retained `conflicts`. The built-ins below are conveniences, never imposed semantics.

`merge` is fallible: a strategy that interprets its payload (OR-Set, PN-Counter)
rejects a malformed document with `MergeError` instead of panicking, so every
binding reports the same explicit error across languages.

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

## Tombstone garbage collection (design, not yet implemented)

A tombstone may be dropped only when **both** conditions hold:

1. **Time**: `now - tombstone.stamp.pt > retention` (default proposal: 30 days), and
2. **Causal dominance**: every known replica's witness for the key dominates the tombstone's stamp — i.e. no live peer can still deliver a write that the tombstone is supposed to kill. Operationally this needs a replica-vector heartbeat, which arrives with the relay (P2); until then GC is exposed as `snapshot` compaction with time-based pruning only, and full dominance-based GC is a pending decision (todo.md).

Dropping a tombstone without condition 2 is exactly the resurrection bug this model exists to prevent.

## Convergence argument

- LWW merge is commutative and idempotent on records (same-stamp short-circuit, dedupe on conflicts).
- OR-Set union of adds/removes is a semilattice; observed-remove gives add-wins for unobserved tags.
- PN-Counter per-node max is a semilattice.
- Op delivery is idempotent (op-id dedup) and order-free for the strategies above, hence out-of-order + duplicate delivery converges (tests: `out_of_order_and_duplicate_delivery_converge`, `example_3_arbitrary_binary_records`).
