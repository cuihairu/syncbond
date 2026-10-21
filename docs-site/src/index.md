---
layout: home
sidebar: false

hero:
  name: "SyncBond"
  text: "Accountless, end-to-end encrypted device sync"
  tagline: "An embeddable SDK for device pairing and data synchronization: opaque payloads, pluggable merge strategies, a Rust core with TypeScript bindings. The core never understands your business data."
  actions:
    - theme: brand
      text: Requirements baseline
      link: /requirements
    - theme: alt
      text: Protocol specification (v1)
      link: /design/PROTOCOL
    - theme: alt
      text: GitHub
      link: https://github.com/cuihairu/syncbond

features:
  - title: Pairing without accounts
    details: Two devices that both show a short display code derive a shared key via SPAKE2 (RFC 9382), with mutual key confirmation and transcript-bound identity exchange — validated against all four official RFC test vectors.
  - title: End-to-end encrypted envelopes
    details: XChaCha20-Poly1305 envelopes where every field except the ciphertext is AEAD-associated data. Replay, cross-group, wrong-epoch, and tamper attempts are all rejected.
  - title: Convergence you can reason about
    details: "Oplog replication with cursors and deduplication — out-of-order and duplicate delivery converge to the same state. Pluggable merge strategies: HLC-LWW with causal tombstones, OR-Set, PN-Counter."
  - title: Embeddable by contract
    details: No application concepts in the core — payloads are opaque bytes and merge behavior is a pluggable strategy. Cryptography is assembled from audited RustCrypto components; no primitives are implemented here.
---
