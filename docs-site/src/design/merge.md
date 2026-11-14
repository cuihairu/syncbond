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

### `deleted` flag semantics per strategy

The `Record.deleted` flag is honored only by `LwwHlc`, which turns it into a
causal tombstone (`Replicator::delete` writes `deleted: true`). Under
`OrSetStrategy` and `PnCounterStrategy` the `deleted` flag is **ignored**: the
merge result is always `deleted: false`, and a `Replicator::delete` call is
therefore not a tombstone for those strategies. Applications that need removal
under OR-Set must express it through the payload (retire the element's tag),
and PN-Counter has no delete at all — removal is modelled by decrementing (or
by switching the key to an `LwwHlc` tombstone). Do not rely on `deleted: true`
to remove a value under a non-`LwwHlc` strategy.

Note that calling `Replicator::delete` under `OrSetStrategy` or
`PnCounterStrategy` does **not** succeed as a no-op: the delete operation
carries an empty payload, which those strategies' `merge` decodes as JSON and
therefore rejects with `MergeError` (the empty document is not valid OR-Set /
PN-Counter JSON). The call fails and leaves the record untouched — the
application must instead express removal through the payload (retire an
OR-Set element's tag, or decrement a PN-Counter).

### LwwHlc rules (the default)

Merge is a set operation over every version both sides know — the local
primary together with its retained `conflicts`, and the incoming write
together with the conflicts it carries — deduplicated by stamp:

1. **Dominated versions drop out.** A version is dominated when *any*
   version in that pool has demonstrably observed its stamp, per the
   witnesses. The pool matters, not just the two exchange endpoints: a
   retained conflict carries its writer's witness, so `A` dominated by `B`
   stays dominated even after `C` became the primary. An old device
   reconnecting with a stale edit therefore cannot resurrect a deleted
   record — the tombstone's witness dominates (test:
   `old_device_reconnect_cannot_resurrect_a_delete`).
2. **Concurrent survivors are all kept.** The highest-stamp survivor
   becomes primary; the rest are retained in `conflicts` for the
   application to resolve. The conflict set is normalized: deduplicated by
   stamp and sorted, so both directions of the merge produce the same set
   (test: `example_2_note_documents_with_offline_conflict`).
3. **Run-ahead clock.** If the incoming stamp claims a wall time more than
   `max_skew_ms` (default 5 min) ahead, it is treated as concurrent
   regardless of causality — a broken device clock cannot silently overwrite
   local state; the skewed write is retained and flagged. A skewed stamp
   never wins the primary while a normal survivor exists, so a runaway
   clock outranks nothing but loses the value. The empty-record path runs
   the same policy (`MergeOutcome.skew_detected` is set there too), so an
   anomalous first write is flagged rather than silently accepted. The
   local HLC additionally refuses to adopt run-ahead remote stamps
   (`HybridClock::receive`). Tests:
   `large_clock_skew_does_not_silently_overwrite`,
   `empty_record_path_flags_a_future_write`,
   `future_write_outcome_is_order_independent_and_trackable`.
4. **Supersession knowledge is not dropped.** A dominated version's
   witness is merged into the resulting record's witness. Otherwise a
   re-delivery of an already-superseded version could survive as a phantom
   conflict (test: `independent_writes_converge_under_every_delivery_order`).


## Tombstone garbage collection (implemented)

`Replicator::gc_tombstones(now_ms, older_than_ms)` collects a tombstone only
when **both** conditions hold:

1. **Time**: `now_ms - tombstone.stamp.pt >= older_than_ms`, and
2. **Causal dominance**: every known replica's witness dominates the
   tombstone's stamp. The witness map the replicator accumulates from op
   witnesses *is* the replica vector — no separate heartbeat protocol, it
   travels with relay sync. The dominance check covers only replicas we have
   evidence about: a replica that has never been heard from is simply absent
   from the vector and does not block collection. Collection safety does not
   depend on that absence — the compacted barrier rejects a pre-delete write
   redelivered later that loses to the tombstone in the merge. A concurrent
   write with a higher stamp from an unheard replica still follows the normal
   LWW rule and can recreate the key, as it would have before GC
   (`concurrent_higher_stamp_write_resurrects_a_collected_delete`).

A collected tombstone is **not deleted**. It is compacted into a barrier
entry (`gc_barriers`, payload and retained conflicts stripped, stamp and
witness kept) and the key's oplog history collapses to its single tombstone
op. The barrier keeps the guarantee for the writes it decides: a pre-delete
write redelivered after GC that loses to the tombstone in the merge is
rejected by the barrier instead of resurrecting the delete
(`stale_put_cannot_resurrect_a_collected_delete`). A concurrent write with a
higher stamp from an unheard replica still wins under the normal LWW rule and
can recreate the key, as it would have before GC
(`concurrent_higher_stamp_write_resurrects_a_collected_delete`). The retained
tombstone op means a fresh replica still learns about the delete, so the
compacted form costs O(1) per deleted key and never downgrades a peer's view.

Two consequences worth noting:

- Garbage-collected state is safe to restart from: barriers are part of
  `SyncState` (`#[serde(default)]`, so pre-GC snapshots load unchanged) and
  replay reproduces the compacted form (`gc_compacts_the_oplog_and_survives_a_restart`).
- A compacted peer converges with an uncompacted peer; the tombstone travels,
  the payload does not (`compacted_peer_converges_with_an_uncompacted_peer`).

The time-threshold-only degraded mode is deliberately **not** a stable
application option: it waives the evidence requirement and can re-materialize
a collected key from a peer still carrying the pre-delete history. The Rust
method is marked `#[doc(hidden)]` and is reachable only through the
conformance fixture runner's `gc` step (`mode: "time_only"`) or by a Rust
downstream that explicitly opts in; the C ABI and the stable language
bindings expose only the dominance-checked mode. It is off by default and not
documented as an application option.

## Convergence argument

- LWW merge is a canonical function of the delivered version set, not of the
  merge order: dominance and ordering read only stamps and witnesses, the
  conflict set is normalized (deduplicated by stamp, sorted), and
  supersession knowledge survives in the merged record's witness. Every
  delivery permutation of the same writes yields the same primary and the
  same normalized conflict set (tests:
  `independent_writes_converge_under_every_delivery_order` — the A=1000 /
  B=900 having observed A / C=950 matrix over all six delivery orders — and
  `multi_node_permutation_convergence_property`, a deterministic multi-node
  witness DAG explored across all `n!` delivery permutations).
- OR-Set union of adds/removes is a semilattice; observed-remove gives add-wins for unobserved tags.
- PN-Counter per-node max is a semilattice.
- Op delivery is idempotent (op-id dedup) and order-free for the strategies above, hence out-of-order + duplicate delivery converges (tests: `out_of_order_and_duplicate_delivery_converge`, `example_3_arbitrary_binary_records`).
