# Language decision: Rust core + TypeScript binding vs pure TypeScript

Status: **decision adopted for v1 — Rust core (`crates/syncbond-core`) + TypeScript binding skeleton (`packages/ts-bindings`)**. Recorded for review; the comparison below is the basis.

## Requirements that drive the choice

- Runs inside input-method / desktop apps (Windows, macOS, Linux, mobile), plus a sync relay service.
- Handles secret material (session keys, identity keys, PAKE scalars) — memory hygiene matters.
- Must be embeddable from at least TypeScript (UI layer) and eventually other platform languages.
- Correctness of the CRDT/replication logic is release-blocking; the test suite is the product.

## Comparison

| Dimension | Rust core + TS binding (napi-rs / wasm-bindgen) | Pure TypeScript |
|---|---|---|
| Cross-platform reach | one core, bindings for Node/Electron (napi-rs), browser (wasm-bindgen), and later Swift/Kotlin via FFI | one runtime everywhere, but each host needs the JS engine embedded |
| Secret handling | keys live in native memory; `zeroize`-style wiping possible; no GC copies of key material | key bytes live in the JS heap; GC copying and inspector access widen exposure |
| Performance | curve arithmetic (P-256 PAKE), scrypt and binary replication loops are native; scrypt especially benefits | scrypt/PAKE in JS is workable but 10–50× slower on low-end devices |
| Safety/audit story | RustCrypto + dalek + noble-equivalent crates, type-level ownership; `unsafe` confined to binding glue | audited noble-js stack, but the whole runtime is shared with app code |
| Maintenance | two languages; binding layer must track core API | single language, smallest possible toolchain |
| Iteration speed | slower for protocol experiments (compile, codegen) | fastest for experiments |
| IME/desktop integration | native module load is standard for IME-adjacent components | embedding a JS runtime into IME processes is awkward |
| Relay/server | same crate reused server-side | needs a separate server codebase or Node everywhere |
| Fleet experience | existing Rust practice (meshlet, sandtable) | existing TS practice everywhere |

## Decision

Rust core + TypeScript binding, because the deciding rows are secret handling, native IME embedding, and core reuse in the relay — the rows where pure TS is weakest. Cost accepted: a binding layer and slower iteration. The TS binding starts as a typed skeleton (`packages/ts-bindings/src/index.ts`) mirroring the Rust API; the napi-rs implementation is the first P2 work item.

## Reversal note

If the binding layer turns out to dominate maintenance (tracked in todo.md), the fallback is pure TS on the audited noble-js stack — the protocol documents are runtime-independent by design, and the envelope schema is the stable contract either way.
