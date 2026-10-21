[中文](zh/requirements.md)

# Requirements baseline

Status: requirements baseline derived from the 2026-10-21 survey (see [`research/survey-2026-10-21.md`](research/survey-2026-10-21.md)) and the user's project review. Each item maps to code and tests; `todo.md` P1 entries reference these section numbers.

Guiding principle: **the SDK does not understand, interpret, or decide the meaning of business data.** Payloads are opaque bytes; merge semantics are the application's choice.

## 1. Pairing

- Short display code generation from an unambiguous alphabet (no 0/O/1/I/L), fixed length (R1.1).
- PAKE-based pairing: SPAKE2 per RFC 9382 (`SPAKE2-P256-SHA256-HKDF-HMAC`), validated against all RFC Appendix B test vectors (R1.2).
- Code entropy, TTL, single-use, and failed-attempt limits as mandatory policy, bounding online guessing (R1.3).
- Mutual key confirmation: neither side completes without verifying the peer's MAC over the transcript (R1.4).
- Transcript + protocol version + application domain separation: every frame carries a version byte; HKDF info strings bind the application name and version (R1.5).
- Role binding: initiator/responder roles fixed by who starts, mirrored to the SPAKE2 A/B roles and identity signatures (R1.6).
- Long-term device public keys exchanged after pairing, signatures bound to the transcript hash (R1.7).

Implementation: `crates/syncbond-core/src/{pairing,pairing_spake2,codes}.rs`; tests `tests/pairing_tests.rs`, `tests/rfc9382_vectors.rs`. Contract: `docs/design/PROTOCOL.md`.

## 2. Identity

- Long-term Ed25519 key pair per device (R2.1).
- Deterministic device id derived from the public key (R2.2).
- Member invitation = the pairing flow itself; a paired device joins the group (R2.3).
- Revocation propagation via group key epoch rotation; revoked devices cannot open later-epoch envelopes (R2.4).
- Replay protection: per-message ids with a session seen-set; invalidated sessions refuse all traffic (R2.5).

Implementation: `src/identity.rs`, `src/crypto.rs` (KeyRing), `src/pairing.rs` (PairingSession). Tests: `revoked_device_cannot_open_next_key_epoch`, `replayed_message_is_rejected`, `session_invalidation_blocks_further_traffic`.

## 3. Encryption

- Envelope with nine fields; every field except ciphertext is AEAD-associated data (R3.1).
- HKDF domain separation for session keys and confirmation keys (R3.2).
- keyEpoch from v1; rotation is the revocation primitive (R3.3).
- Envelopes of a new epoch cannot be opened with any older-epoch key (R3.4).
- Ciphersuite is fixed for v1; suite negotiation is a versioning decision, not per-message (R3.5).

Implementation: `src/crypto.rs`. Wire schema: `schemas/envelope.schema.json`. Tests: `tests/crypto_envelope_tests.rs`.

## 4. Replication

- Oplog of record operations with monotonic per-node cursors (R4.1).
- Incremental sync by cursor; snapshots for catch-up and persistence (R4.2).
- Deduplication by message/op id (R4.3).
- Out-of-order and duplicate delivery converge to identical state (R4.4).
- Offline catch-up: a device that was offline applies the peer oplog on reconnect (R4.5).

Implementation: `src/replication.rs`. Tests: `out_of_order_and_duplicate_delivery_converge`, example tests.

## 5. Conflict

- Pluggable `MergeStrategy` trait; the core never imposes semantics (R5.1).
- Built-ins: HLC-LWW with causal tombstones, OR-Set, G-/PN-Counter (R5.2).
- Deletions are tombstones with causal witness metadata; a stale device cannot resurrect a delete (R5.3).
- Concurrent versions are retained for application resolution, not silently dropped (R5.4).
- Large clock skew never silently overwrites: run-ahead stamps are treated as concurrent, flagged, and retained (R5.5).
- Tombstone GC design: time threshold + causal dominance (`docs/design/merge.md`); implementation pending relay heartbeat (R5.6).

Implementation: `src/conflict.rs`, `src/hlc.rs`. Tests: `tests/replication_tests.rs`.

## 6. Storage

- Swappable persistence trait (`SyncStorage`) (R6.1).
- Snapshot save is atomic replacement from the caller's view (R6.2).
- Crash-restart consistency: identity, cursor, and oplog all survive reload (release-blocking) (R6.3).
- At-rest encryption is delegated to the storage backend; the SDK exposes the state as bytes (R6.4).

Implementation: `src/storage.rs`. Tests: `crash_restart_restores_identity_cursor_and_oplog`.

## 7. Transport

- Abstract `Transport` interface (send/recv frames) (R7.1).
- In-memory loopback implementation for tests (R7.2).
- WebSocket minimal persistent relay first in P2 (cross-device, reconnect, async online) (R7.3).
- LAN discovery (mDNS) and P2P later; relay sees ciphertext only by construction (E2EE at the envelope layer) (R7.4).

Implementation: `src/transport.rs`.

## 8. Groups and namespaces

- Group authorization: group id derived from member public keys; envelopes carry the group id and are checked on receipt (R8.1).
- Multiple independent datasets per device: namespaces/collections are application-level partitions over the record key space; the core enforces group isolation, not dataset semantics (R8.2).
- Cross-group delivery is rejected at the envelope layer (R8.3).

Implementation: `src/crypto.rs` (group checks), `src/identity.rs` (group id). Tests: `cross_group_delivery_is_rejected`, `two-space isolation` semantics via group checks.

## 9. Version negotiation

- Every frame and envelope carries the protocol version; incompatible versions are rejected with an explicit error (R9.1).
- Extension fields: envelope schema is closed (`additionalProperties: false`) for v1; extensions come as a version bump (R9.2).

Tests: `protocol_version_mismatch_is_rejected`, `unsupported_protocol_version_is_rejected`.

## 10. SDK surface

- Public API: `pair(displayCode)` / `accept(code)` / `sync` over a `Transport` (R10.1).
- Language route: Rust core + TypeScript binding (napi-rs); decision recorded in `docs/design/language.md` (R10.2).
- Universality gate: three unrelated example applications (generic KV, note documents, arbitrary binary records) run on the same core with tests (R10.3).
- Serverless by default; relay optional and ciphertext-only (R10.4).

Implementation: `src/lib.rs`, `packages/ts-bindings` (skeleton). Tests: `tests/examples_tests.rs`.

## 11. Security engineering

- Protocol conformance proven by official RFC test vectors (R11.1).
- Constant-time comparison for MAC verification (`equalBytes`-equivalent; verify every secret comparison) (R11.2).
- Key zeroization on drop where the runtime permits; binding layer must not copy keys into GC-managed memory (R11.3).
- Threat model document: code guessing (online bounded by policy, offline by entropy + single-use), hostile relay (sees ciphertext only), malicious peer (PAKE + confirmation), compromised device (key epoch rotation) (R11.4).

Status: R11.1/R11.2 done (`tests/rfc9382_vectors.rs`, HMAC verification path); R11.3 partial (no zeroize yet — pending); R11.4 covered by `docs/design/PROTOCOL.md` §2–§5, full threat-model page pending.
