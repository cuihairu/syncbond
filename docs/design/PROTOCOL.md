# Protocol specification (v1)

Status: implemented in `crates/syncbond-core/src/` (pairing, crypto, identity modules). This document is the frozen v1 protocol contract.

## 1. Pairing protocol: SPAKE2 per RFC 9382

### RFC 9382 vs RFC 9383 — what was chosen and why

| | SPAKE2 (RFC 9382) | SPAKE2+ (RFC 9383) |
|---|---|---|
| Model | symmetric PAKE: both sides hold the password | augmented PAKE: one side stores only a verifier |
| Protects against | server/peer compromise of the code at rest — **not** applicable: neither side stores the code | verifier theft in server databases |
| Fit for device pairing | both devices legitimately hold the same display code for the pairing window; there is no "server" | solves a problem syncbond does not have, at the cost of a more complex flow |

Chosen: **SPAKE2, RFC 9382**, ciphersuite `SPAKE2-P256-SHA256-HKDF-HMAC` (RFC 9382 Table 1). Conformance is proven against all four RFC 9382 Appendix B test vectors (`crates/syncbond-core/tests/rfc9382_vectors.rs`, generated from the RFC text).

**No hand-rolled cryptography**: P-256 arithmetic comes from RustCrypto `p256` 0.13 (maintained, part of the RustCrypto stack), SHA-256/HKDF/HMAC from `sha2`/`hkdf`/`hmac`, the password-to-scalar MHF from `scrypt` (RustCrypto), identity keys from `ed25519-dalek`, AEAD from `chacha20poly1305`. The crate only assembles the RFC 9382 steps. (Prior art surveyed Oct 2026: npm `spake2` targets draft-08 and is unaudited — rejected; CrossPaste pairing v3 uses the same RFC 9382 P-256 composition in Kotlin but is application-embedded, not an embeddable core.)

### Password → scalar (w)

`w = OS2IP(scrypt("syncbond/w1/v1" || code, N=2^14, r=8, p=1, 64)) mod n` — 64 output bytes avoid mod bias (NIST SP 800-56Ar3 suggestion); scrypt is the RFC-recommended MHF. Honest limit: a short code has bounded entropy, so the code must be single-use, short-lived and uniformly random (see §3); SPAKE2 protects the exchange, the policy bounds online guessing, and recorded transcripts only permit offline guessing at the code's entropy (≈27 bits for 6 characters — the reason TTL and single-use are mandatory).

### Handshake flow and identity binding

Frames: `[type: u8][protocol_version: u8][payload]`; order per RFC 9382 §3.1:

```
A (initiator, pair())                    B (responder, accept())
  pA = w*M + x*P  ──────── 0x01 ─────────▶
                         ◀──── 0x02 ────  pB = w*N + y*P
  K, TT, Ke||Ka, cA ────  0x03 ─────────▶  check cA
                         ◀──── 0x04 ────  cB            (mutual key confirmation)
  identity_A + sig ─────  0x05 ─────────▶  verify sig
                         ◀──── 0x06 ────  identity_B + sig
```

- **Role binding**: initiator plays A (uses M), responder plays B (uses N); roles are fixed by who starts the exchange, both sides agree without negotiation.
- **Mutual key confirmation**: `cA = HMAC(KcA, TT)`, `cB = HMAC(KcB, TT)`; A MUST NOT complete before verifying cB and B MUST NOT before cA (RFC 9382 §3.1). Mismatched codes fail here; the failing side sends an `abort` frame (0x07) so the peer never blocks.
- **Identity binding**: after confirmation each side sends its long-term Ed25519 public key with a signature over `SHA-256("syncbond/identity/v1" || role || TT)` — the identity is bound to the authenticated transcript, so a man-in-the-middle cannot substitute keys.
- **Group id**: `SHA-256("syncbond/group/v1" || sorted member public keys)[..24]` — order-independent, derives the sync group for both sides.
- **Application domain separation**: the session key is `HKDF-SHA256(Ke, nil, "syncbond/v1/session-key", 32)`; the `syncbond` prefix binds HKDF outputs to this application and version. Confirmation keys are separately derived with the RFC's `"ConfirmationKeys"` info string.
- **Transcript**: `TT` exactly per RFC 9382 §3.3 (8-byte little-endian length prefixes; w big-endian). Every derived key covers TT.

## 2. Pairing code policy (guess limiting)

Alphabet: 30 unambiguous symbols (`23456789ABCDEFGHJKMNPQRSTUVWXYZ`, no 0/O/1/I/L), length 6 → ≈29.5 bits of alphabet entropy (30^6 ≈ 0.87 × 10^9). Defaults (`crates/syncbond-core/src/codes.rs`):

| Rule | Value | Rationale |
|---|---|---|
| Single use | a consumed code can never pair again | replay of a paired code is worthless |
| TTL | 120 s default (application-settable) | bounds the online-guessing window |
| Failed attempts | max 3 per code window, then locked | with 30^6 codes, 3 guesses per 120 s window makes online guessing negligible |
| Format check | pre-exchange, both sides | rejects garbage before any crypto work |

An online attacker gets ≤3 tries per 2 minutes against ≈10^9 codes: expected time to success is centuries. The offline-guessing risk from a recorded transcript is bounded by code entropy, which is why §3's rules are mandatory, not optional.

## 3. Protocol versioning

- The version byte is inside every frame; a mismatch aborts pairing (`protocol version mismatch`). Envelopes carry `protocolVersion` and receivers reject mismatches.
- v1 → v2 changes MUST bump the constant and keep the abort path; cross-version negotiation (accepting older peers) is a planned decision, not implemented (see todo.md).

## 4. Encrypted envelopes

Wire shape: `schemas/envelope.schema.json`. AEAD: XChaCha20-Poly1305 (192-bit nonce, random per message).

```
interface EncryptedEnvelope {
  protocolVersion: u16; groupId: string; senderDeviceId: string;
  keyEpoch: u64; messageId: string; nonce: [u8; 24]; ciphertext: bytes;
}
```

All fields except `ciphertext` are AEAD associated data (stable byte encoding). Receivers reject, in order: protocol-version mismatch → cross-group delivery → wrong key epoch → replayed `messageId` → any AEAD failure. `messageId` is random 16 bytes per message; the session keeps the seen-set, and an invalidated session refuses all further traffic (a replayed frame cannot revive it).

## 5. Key epochs and revocation

The group holds a `KeyRing` with a monotonic `keyEpoch`. Removing a member automatically mints epoch N+1 and updates the member set atomically. The resulting distribution message carries the new key, survivor set, removed device, source identity, an Ed25519 signature over all signed fields, and an HKDF-SHA256 MAC derived from the pre-rotation group key. Receivers install it only after protocol/group/epoch/membership checks and both authentication checks pass. A removed device therefore cannot read any later envelope, forge a source-signed rotation, or replay an applied removal.

## 6. Replication

Records are opaque payloads with an HLC stamp and a causal witness (last-seen full stamp per node). Sync exchanges oplogs over the encrypted session; operations are deduplicated by id, so out-of-order and duplicate delivery converge. Merge behavior is a pluggable `MergeStrategy` (docs/design/merge.md). Full protocol log/cursor semantics live in `crates/syncbond-core/src/replication.rs`.
