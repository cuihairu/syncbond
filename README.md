[English](README.md) | [中文](README.zh.md)

<p align="center"><a href="https://cuihairu.github.io/syncbond/"><img src="https://img.shields.io/badge/docs-blue" alt="docs"></a> [![Status](https://img.shields.io/badge/status-in%20development-orange)](https://github.com/cuihairu/syncbond/releases) [![CI](https://github.com/cuihairu/syncbond/actions/workflows/ci.yml/badge.svg)](https://github.com/cuihairu/syncbond/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Rust core](https://img.shields.io/badge/core-Rust-000000?logo=rust&logoColor=white)](crates/syncbond-core) [![TypeScript bindings](https://img.shields.io/badge/bindings-TypeScript-3178C6?logo=typescript&logoColor=white)](packages/ts-bindings) [![Pairing: SPAKE2 RFC9382](https://img.shields.io/badge/pairing-SPAKE2%20RFC9382-2c6e63)](docs/design/PROTOCOL.md)</p>
</p>

<div align="center">


</div>


> **syncbond is a temporary development name; the final brand is to be decided.**

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

The Rust core is implemented and exercised by the workspace test suite (currently 75+ tests), including all four RFC 9382 Appendix B vectors and three unrelated example applications (generic KV, note documents, arbitrary binary records) running on the same core. Bindings for C, C++, Python, Go, Java, C#, TypeScript (napi), and browser WASM all run the same cross-language conformance fixture byte-for-byte.

Progress and open decisions: [`todo.md`](todo.md). Protocol contract: [`docs/design/PROTOCOL.md`](docs/design/PROTOCOL.md). Merge design: [`docs/design/merge.md`](docs/design/merge.md). Language decision: [`docs/design/language.md`](docs/design/language.md). Requirements baseline: [`docs/requirements.md`](docs/requirements.md). Landscape survey: [`docs/research/survey-2026-10-21.md`](docs/research/survey-2026-10-21.md).

## Layout

```
crates/syncbond-core/   the Rust core (pairing, crypto, replication, conflict, storage, transport)
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
