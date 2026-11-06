[English](README.md) | [中文](README.zh.md)

<p align="center"><img src="assets/icon.svg" width="64" height="64" alt="SyncBond logo"></p>

<p align="center"><a href="https://cuihairu.github.io/syncbond/"><img src="https://img.shields.io/badge/docs-blue" alt="docs"></a> [![Status](https://img.shields.io/badge/status-in%20development-orange)](https://github.com/cuihairu/syncbond/releases) [![CI](https://github.com/cuihairu/syncbond/actions/workflows/ci.yml/badge.svg)](https://github.com/cuihairu/syncbond/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Rust core](https://img.shields.io/badge/core-Rust-000000?logo=rust&logoColor=white)](crates/syncbond-core) [![TypeScript bindings](https://img.shields.io/badge/bindings-TypeScript-3178C6?logo=typescript&logoColor=white)](packages/ts-bindings) [![Pairing: SPAKE2 RFC9382](https://img.shields.io/badge/pairing-SPAKE2%20RFC9382-2c6e63)](docs/design/PROTOCOL.md)</p>


> **syncbond is the final product name** (confirmed 2026-11-05; crates.io names `syncbond` / `-core` / `-ffi` / `-python` / `-wasm` / `-napi` were all unoccupied as of the last check, but crates.io assigns names first-come-first-served, so that check does not guarantee they remain available).

# syncbond

An accountless, embeddable, end-to-end encrypted device pairing and data synchronization infrastructure SDK, with a Rust core and bindings for C, C++, Python, Go, Java, C#, TypeScript, and browser WASM — all over one C ABI.

The SDK does not understand, interpret, or decide the meaning of business data: payloads are opaque bytes, and merge behavior is a pluggable strategy. There are no dictionaries, notes, passwords, or any other application concepts in the core — an application brings its own data model and its own merge policy.

Cryptography is assembled on maintained, audited components — RustCrypto `p256`, `sha2`/`hkdf`/`hmac`/`scrypt`, `chacha20poly1305`, `ed25519-dalek` — and the pairing protocol follows RFC 9382 exactly, validated against all four of its official test vectors. No cryptographic primitives are implemented in this repository.

## What it provides

- **Pairing** — two devices that both show a short display code derive a shared key via SPAKE2 (RFC 9382, `SPAKE2-P256-SHA256-HKDF-HMAC`), with mutual key confirmation, transcript-bound Ed25519 identity exchange, a version byte on every frame, and a code policy of single-use + TTL + attempt limits.
- **Identity & groups** — long-term per-device Ed25519 keys; deterministic group id; device revocation through group key epochs.
- **Crypto** — XChaCha20-Poly1305 envelopes where every field except the ciphertext is AEAD-associated data; replay, cross-group, wrong-epoch, and tamper attempts are all rejected. `keyEpoch` exists from v1. Schema: [`schemas/envelope.schema.json`](schemas/envelope.schema.json).
- **Replication** — oplog with cursors and deduplication; out-of-order and duplicate delivery converge to the same state.
- **Conflict** — a pluggable `MergeStrategy`; built-ins (HLC-LWW with causal tombstones, OR-Set, PN-Counter) are optional conveniences. See [`docs/design/merge.md`](docs/design/merge.md).
- **Storage** — a swappable persistence trait; identity, cursor, and oplog must survive a crash-restart (release-blocking test).
- **Transport** — an in-memory loopback plus a durable, resumable relay store (file-backed, oplog cursor continuation); transports themselves are application-provided behind the `Transport` trait (no WebSocket in the core). LAN (mDNS) discovery behind the default-off `lan` feature. P2P is assessed; see the research notes.

## Current status

Pre-release development snapshot: nothing is published to any package registry.

- **Rust core** (`crates/syncbond-core`) is implemented and exercised by the workspace test suite (currently 75+ tests), including all four RFC 9382 Appendix B vectors.
- **Runnable demos** (`crates/syncbond-cli`): two CLI examples run the real paths end to end — see [Quickstart](#quickstart-two-runnable-demos). `syncbond-pair` pairs two terminals over TCP (pairing-code entry → SPAKE2 → encrypted messages → oplog sync → snapshot save/reload). `syncbond-relay` syncs a KV document between two device processes through a file relay store and resumes from its persisted cursor after a restart.
- **Transport reality**: the core ships an in-memory loopback and a durable file relay store; the demos add a minimal length-prefixed TCP transport. There is no production network transport (WebSocket/LAN/P2P) in the repository — transports are application-provided behind the `Transport` trait, and LAN (mDNS) discovery sits behind the default-off `lan` feature. The relay channel carries oplog entries as plaintext; envelopes protect pairing sessions, not the relay store.
- **Bindings**: the C ABI plus C++, Go, Java, C#, Python, TypeScript (napi), and browser WASM bindings exist in the repository and run the same cross-language conformance fixture in CI; none are published to any registry.

## Quickstart: two runnable demos

Requires a stable Rust toolchain.

Demo 1 — SPAKE2 pairing with encrypted messages, oplog sync, and a storage round-trip (two terminals):

```sh
# Terminal A: shows the pairing code, then waits
cargo run -p syncbond-cli --example syncbond-pair -- --role a --addr 127.0.0.1:47560

# Terminal B: type the code shown in terminal A, then chat
cargo run -p syncbond-cli --example syncbond-pair -- --role b --addr 127.0.0.1:47560
```

Demo 2 — KV sync through a file relay, resuming across restarts (each command is one device process; run them one at a time — the file relay store is not safe for concurrent writers):

```sh
cargo run -p syncbond-cli --example syncbond-relay -- --role a put theme dark
cargo run -p syncbond-cli --example syncbond-relay -- --role a put font_size 14
cargo run -p syncbond-cli --example syncbond-relay -- --role a sync       # relay cursor 0 → 2
cargo run -p syncbond-cli --example syncbond-relay -- --role b sync       # pulls the two ops
cargo run -p syncbond-cli --example syncbond-relay -- --role b put greeting hello
cargo run -p syncbond-cli --example syncbond-relay -- --role a sync       # resumes from cursor 2, pulls only the new op
cargo run -p syncbond-cli --example syncbond-relay -- --role a show
cargo run -p syncbond-cli --example syncbond-relay -- --role b show
```

The key/value records displayed by the two `show` commands match — both sides converged. State lives in `./syncbond-relay-demo/`; delete the directory to start over.

Progress and open decisions: [`todo.md`](todo.md). Protocol contract: [`docs/design/PROTOCOL.md`](docs/design/PROTOCOL.md). Merge design: [`docs/design/merge.md`](docs/design/merge.md). Language decision: [`docs/design/language.md`](docs/design/language.md). Requirements baseline: [`docs/requirements.md`](docs/requirements.md). Landscape survey: [`docs/research/survey-2026-10-21.md`](docs/research/survey-2026-10-21.md).

## Layout

```
crates/syncbond-core/   the Rust core (pairing, crypto, replication, conflict, storage, transport)
crates/syncbond-cli/    runnable demos (syncbond-pair, syncbond-relay)
crates/syncbond-ffi/    the C ABI (cdylib + headers), plus the C++/Go/Java/C# bindings and conformance fixtures
crates/syncbond-napi/   Node.js TypeScript bindings (napi-rs over the C ABI)
crates/syncbond-wasm/   browser WASM bindings (wasm-bindgen over the core)
crates/syncbond-python/ Python bindings (PyO3 over the C ABI)
packages/ts-bindings/   TypeScript bindings package (napi + WASM wrappers)
schemas/                wire schemas (envelope)
docs/design/            protocol, merge, and language decision documents
```

## Development

Requires a stable Rust toolchain (edition 2021; MSRV not pinned) and Node 24 + pnpm.

```sh
cargo test                 # core test suite
cargo clippy --all-targets # lint
pnpm install && pnpm -r typecheck   # bindings skeleton typecheck
```

## License

[MIT](LICENSE)
