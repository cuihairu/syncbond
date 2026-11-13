[English](README.md) | [中文](README.zh.md)

<p align="center"><img src="assets/icon.svg" width="64" height="64" alt="SyncBond logo"></p>

<p align="center"><a href="https://cuihairu.github.io/syncbond/"><img src="https://img.shields.io/badge/docs-blue" alt="docs"></a> <a href="https://github.com/cuihairu/syncbond/releases"><img src="https://img.shields.io/badge/status-in%20development-orange" alt="Status"></a> <a href="https://github.com/cuihairu/syncbond/actions/workflows/ci.yml"><img src="https://github.com/cuihairu/syncbond/actions/workflows/ci.yml/badge.svg" alt="CI"></a> <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a> <a href="crates/syncbond-core"><img src="https://img.shields.io/badge/core-Rust-000000?logo=rust&logoColor=white" alt="Rust core"></a> <a href="packages/ts-bindings"><img src="https://img.shields.io/badge/bindings-TypeScript-3178C6?logo=typescript&logoColor=white" alt="TypeScript bindings"></a> <a href="docs/design/PROTOCOL.md"><img src="https://img.shields.io/badge/pairing-SPAKE2%20RFC9382-2c6e63" alt="Pairing: SPAKE2 RFC9382"></a></p>


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

The Rust core is implemented and exercised by the workspace test suite (currently 75+ tests), including all four RFC 9382 Appendix B vectors and three unrelated example applications (generic KV, note documents, arbitrary binary records) running on the same core. Bindings for C, C++, Python, Go, Java, C#, TypeScript (napi), and browser WASM all run the same cross-language conformance fixture byte-for-byte.

Progress and open decisions: [`todo.md`](todo.md). Protocol contract: [`docs/design/PROTOCOL.md`](docs/design/PROTOCOL.md). Merge design: [`docs/design/merge.md`](docs/design/merge.md). Language decision: [`docs/design/language.md`](docs/design/language.md). Requirements baseline: [`docs/requirements.md`](docs/requirements.md). Landscape survey: [`docs/research/survey-2026-10-21.md`](docs/research/survey-2026-10-21.md).

## Nightly builds

A rolling nightly prerelease is built from `main` (on schedule when there is a commit newer than 48 hours, or on manual trigger), and only after fmt + clippy + the full workspace test suite pass. Nightlies are build artifacts, **not stable releases**: versioned releases and npm/crates.io publishing are issued manually by the maintainer only.

Download from the [nightly release](https://github.com/cuihairu/syncbond/releases/tag/nightly), then verify against `SHA256SUMS`:

```sh
sha256sum -c --ignore-missing SHA256SUMS   # after downloading the assets you want
```

- **C / C++** — `syncbond-nightly-<target>.tar.gz` (Linux x86_64 / aarch64, musl static): `include/syncbond.h` + `libsyncbond_ffi.a`; link the archive and include the header.
- **Python** — `syncbond_python-*.whl` (Linux x86_64 / aarch64): `pip install <that .whl file>`.
- **Node.js** — `syncbond-nightly-napi-<arch>.tar.gz` (Linux glibc): unpack, then import the contained `binding.js` (loads the sibling prebuilt `index.<platform>.node`).
- **Browser WASM** — `syncbond-nightly-wasm.tar.gz`: `syncbond_wasm.js` + `syncbond_wasm_bg.wasm` (wasm-pack `web` target).

`BUILD_INFO` inside each archive records the exact source commit.

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
