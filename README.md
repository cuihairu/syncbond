[English](README.md) | [中文](README.zh.md)

<p align="center"><img src="assets/icon.svg" width="64" height="64" alt="SyncBond logo"></p>

<div align="center">

<a href="https://github.com/cuihairu/syncbond/releases"><img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange"></a>
<a href="https://github.com/cuihairu/syncbond/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cuihairu/syncbond/actions/workflows/ci.yml/badge.svg"></a>
<a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
<a href="crates/syncbond-core"><img alt="Rust core" src="https://img.shields.io/badge/core-Rust-000000?logo=rust&logoColor=white"></a>
<a href="packages/ts-bindings"><img alt="TypeScript bindings" src="https://img.shields.io/badge/bindings-TypeScript-3178C6?logo=typescript&logoColor=white"></a>
<a href="docs/design/PROTOCOL.md"><img alt="Pairing: SPAKE2 RFC9382" src="https://img.shields.io/badge/pairing-SPAKE2%20RFC9382-2c6e63"></a>

</div>


> **syncbond is a temporary development name; the final brand is to be decided.**

# syncbond

An accountless, embeddable, end-to-end encrypted device pairing and data synchronization infrastructure SDK, with a Rust core and TypeScript bindings.

The SDK does not understand, interpret, or decide the meaning of business data: payloads are opaque bytes, and merge behavior is a pluggable strategy. There are no dictionaries, notes, passwords, or any other application concepts in the core — an application brings its own data model and its own merge policy.

Cryptography is assembled on maintained, audited components — RustCrypto `p256`, `sha2`/`hkdf`/`hmac`/`scrypt`, `chacha20poly1305`, `ed25519-dalek` — and the pairing protocol follows RFC 9382 exactly, validated against all four of its official test vectors. No cryptographic primitives are implemented in this repository.

## What it provides

- **Pairing** — two devices that both show a short display code derive a shared key via SPAKE2 (RFC 9382, `SPAKE2-P256-SHA256-HKDF-HMAC`), with mutual key confirmation, transcript-bound Ed25519 identity exchange, a version byte on every frame, and a code policy of single-use + TTL + attempt limits.
- **Identity & groups** — long-term per-device Ed25519 keys; deterministic group id; device revocation through group key epochs.
- **Crypto** — XChaCha20-Poly1305 envelopes where every field except the ciphertext is AEAD-associated data; replay, cross-group, wrong-epoch, and tamper attempts are all rejected. `keyEpoch` exists from v1. Schema: [`schemas/envelope.schema.json`](schemas/envelope.schema.json).
- **Replication** — oplog with cursors and deduplication; out-of-order and duplicate delivery converge to the same state.
- **Conflict** — a pluggable `MergeStrategy`; built-ins (HLC-LWW with causal tombstones, OR-Set, PN-Counter) are optional conveniences. See [`docs/design/merge.md`](docs/design/merge.md).
- **Storage** — a swappable persistence trait; identity, cursor, and oplog must survive a crash-restart (release-blocking test).
- **Transport** — an in-memory loopback now; WebSocket / LAN / P2P are interface-reserved.

## Current status

The Rust core is implemented with 35 passing tests, including all four RFC 9382 Appendix B vectors and three unrelated example applications (generic KV, note documents, arbitrary binary records) running on the same core. The TypeScript binding is a typed skeleton; the napi-rs implementation has not started.

Progress and open decisions: [`todo.md`](todo.md). Protocol contract: [`docs/design/PROTOCOL.md`](docs/design/PROTOCOL.md). Merge design: [`docs/design/merge.md`](docs/design/merge.md). Language decision: [`docs/design/language.md`](docs/design/language.md). Requirements baseline: [`docs/requirements.md`](docs/requirements.md). Landscape survey: [`docs/research/survey-2026-10-21.md`](docs/research/survey-2026-10-21.md).

## Layout

```
crates/syncbond-core/   the Rust core (pairing, crypto, replication, conflict, storage, transport)
packages/ts-bindings/   TypeScript binding skeleton (typed API, napi-rs implementation pending)
schemas/                wire schemas (envelope)
docs/design/            protocol, merge, and language decision documents
```

## Development

Requires a Rust toolchain (1.85+ / edition 2021) and Node 24 + pnpm.

```sh
cargo test                 # core test suite
cargo clippy --all-targets # lint
pnpm install && pnpm -r typecheck   # bindings skeleton typecheck
```

## License

[MIT](LICENSE)
