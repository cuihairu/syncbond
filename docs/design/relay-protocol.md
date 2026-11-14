[中文](../zh/design/relay-protocol.md)

# Relay protocol v1 (network contract)

Status: **frozen 2026-11-14** (todo.md DSR-07). This is the wire contract between a syncbond client and the default self-hosted relay. Shared DTOs, error codes and size limits are implemented in `crates/syncbond-relay-protocol` (DSR-09); the service that enforces the contract is `apps/syncbond-server` (DSR-11+, planned). Architecture and trust boundaries: [default-server.md](default-server.md). End-to-end protocol: [PROTOCOL.md](PROTOCOL.md).

This contract carries **opaque encrypted envelopes**. The relay never decrypts, merges or interprets them; the envelope's own JSON shape is frozen separately in `schemas/envelope.schema.json` (PROTOCOL.md §4). The relay contract version and the envelope version are independent: either can move to v2 without the other.

## 1. Transport and encoding

- HTTP/1.1 for all request/response routes, WebSocket (RFC 6455) for pairing-room frame forwarding and channel update notifications. Public deployments run behind a TLS reverse proxy; plaintext is local-development only.
- Every HTTP body is UTF-8 JSON with `Content-Type: application/json`.
- Every request body and every success response carries:
  - `protocolVersion` (integer, MUST be `1`) — the **relay contract** version;
  - `requestId` (string, 1–64 chars, client-chosen) — echoed unchanged in the response.
  Failures echo `requestId` when the request was parseable, `null` otherwise.
- Unknown JSON fields are rejected everywhere (HTTP 400, code `bad_request`) — the same closed-shape policy as the envelope schema's `additionalProperties: false`.
- A `protocolVersion` other than `1` fails with 400 `version_unsupported`. There is **no negotiation**, mirroring PROTOCOL.md §3: a future v2 contract hard-rejects v1 clients and vice versa. The end-to-end envelope `protocolVersion` nested inside each envelope is a different, unrelated field with the same hard-reject rule.

## 2. Authentication

- `Authorization: Bearer <token>`. Tokens are opaque base64url of 32 random bytes (43 chars). The server stores only the SHA-256 digest of a token; tokens are never logged and never appear in URLs.
- Three token kinds:
  | Kind | Held by | Grants |
  |---|---|---|
  | admin credential | deployer (bootstrap file, DSR-15) | channel creation, credential issuance/revocation |
  | channel credential | one device, one channel | `append` and/or `pull` scope on that channel |
  | room capability | the ≤ 2 participants of one pairing room | frame forwarding in that room only |
- A valid token with the wrong role, scope or channel is 403 `forbidden`; a missing or unknown token is 401 `unauthorized`. Group ids and device ids are **not** credentials.
- Scope checks: `/append` requires `append` scope; `/pull` and the channel event stream require `pull` scope; admin routes require the admin credential. Cross-channel access with a valid foreign credential is 403, not 404.
- The admin credential is generated at first server initialization (32 random bytes, written `0600` next to the database) and must be moved into protected configuration by the deployer. There is no hardcoded or development default.

## 3. HTTP routes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/channels` | admin | create a channel |
| `POST` | `/v1/channels/{channelId}/credentials` | admin | issue a channel credential |
| `GET` | `/v1/channels/{channelId}/credentials` | admin | list credentials (digests and metadata only, never tokens) |
| `DELETE` | `/v1/channels/{channelId}/credentials/{credentialId}` | admin | revoke a credential |
| `POST` | `/v1/channels/{channelId}/append` | `append` scope | batch-append encrypted envelopes |
| `POST` | `/v1/channels/{channelId}/pull` | `pull` scope | paginated read |
| `GET` | `/v1/health` | none | liveness |
| `POST` | `/v1/pairing/rooms` | none (rate-limited) | create a pairing room |
| `GET` (upgrade) | `/v1/pairing/{roomId}` | room capability | WebSocket pairing-room frame relay |
| `GET` (upgrade) | `/v1/channels/{channelId}/events` | `pull` scope | WebSocket update notifications |

`channelId` is an opaque server-assigned string, 1–128 chars. `POST` is used for pull (the cursor and limits ride in the body, not the URL; pull is side-effect free and idempotent).

### 3.1 Channel management

Create channel — request `{"protocolVersion":1,"requestId":"c7f3a91d2b8e4f06a5c7d9e0b1a2c3d4"}`. Permissions are a property of each credential, not of the channel.

Response `201 Created`:
```json
{"protocolVersion":1,"requestId":"c7f3a91d2b8e4f06a5c7d9e0b1a2c3d4","channelId":"ch_9f8e7d6c5b4a3f2e1d0c"}
```

Issue credential — request:
```json
{"protocolVersion":1,"requestId":"aa11bb22cc33dd44ee55","scopes":["append","pull"],"label":"phone"}
```
Response `201 Created` — the token is shown **exactly once**:
```json
{"protocolVersion":1,"requestId":"aa11bb22cc33dd44ee55","credentialId":"cred_1a2b3c4d5e6f","token":"7JeZ9xK2mQ4vN8sT1wY6uB3cD5fH0gLpR2aVbCxz9kM","scopes":["append","pull"],"label":"phone"}
```

Revoke — `DELETE /v1/channels/{channelId}/credentials/{credentialId}` → `200 {"protocolVersion":1,"requestId":"…","revoked":"cred_1a2b3c4d5e6f"}`. Revocation survives restart and also refuses the credential on already-open connections (its next request or WS frame fails 401).

## 4. Append: commit ACK and idempotency

Request `POST /v1/channels/{channelId}/append`:
```json
{"protocolVersion":1,"requestId":"req_5f6e7d8c9b0a1f2e3d4c","envelopes":[
  {"protocolVersion":1,"groupId":"g_ab12…","senderDeviceId":"dev_phone","keyEpoch":3,"messageId":"m_0192f3e4d5c6b7a8","nonce":"7Je…22chars","ciphertext":"9hK2xQ…"}
]}
```
Each array element is the end-to-end `EncryptedEnvelope` JSON object, shape-frozen by `schemas/envelope.schema.json`. The relay validates the outer shape only: required fields present, sizes within limits. It never inspects or stores `groupId` semantics — routing is by the path's `channelId`.

Constraints (any violation rejects the **whole batch**, nothing commits):
- 1–16 envelopes per request; total serialized envelope bytes ≤ 8 MiB; a single envelope ≤ 4 MiB.
- Envelope JSON must parse into the frozen shape (closed, no unknown fields).

Success `200 OK` — the commit ACK, returned **only after the transaction is durable** (SQLite WAL commit; an acknowledged sequence never disappears on restart):
```json
{"protocolVersion":1,"requestId":"req_5f6e7d8c9b0a1f2e3d4c","channelId":"ch_9f8e7d6c5b4a3f2e1d0c","acks":[
  {"messageId":"m_0192f3e4d5c6b7a8","seq":42,"duplicate":false}
]}
```
`seq` is the per-channel monotonic server sequence (u64, starts at 1, gapless over committed data, assigned inside the append transaction).

Idempotency, keyed by `(channelId, messageId)`:
- Retry with a **field-identical** envelope (parsed-object equality; JSON key order insignificant): the original `seq` is returned with `"duplicate":true`. Safe to retry after a lost ACK.
- Retry with the same `messageId` but any differing field: `409 Conflict` `idempotency_conflict`, whole batch rejected. A batch containing a conflicting envelope commits nothing.

Failure example (`409`):
```json
{"protocolVersion":1,"requestId":"req_5f6e7d8c9b0a1f2e3d4c","error":{"code":"idempotency_conflict","message":"messageId m_0192f3e4d5c6b7a8 already committed with different content","retryable":false}}
```

## 5. Pull: pagination and cursors

Request `POST /v1/channels/{channelId}/pull`:
```json
{"protocolVersion":1,"requestId":"req_aa00bb11cc22dd33ee44","after":41,"limit":16,"maxBytes":4194304}
```
`after` is the client's cursor (last durably delivered `seq`). `limit` defaults to 16, maximum 64. `maxBytes` defaults to 4 MiB, maximum 16 MiB.

Success `200 OK`:
```json
{"protocolVersion":1,"requestId":"req_aa00bb11cc22dd33ee44","channelId":"ch_9f8e7d6c5b4a3f2e1d0c","entries":[
  {"seq":42,"envelope":{"protocolVersion":1,"groupId":"g_ab12…","senderDeviceId":"dev_phone","keyEpoch":3,"messageId":"m_0192f3e4d5c6b7a8","nonce":"7Je…22chars","ciphertext":"9hK2xQ…"}}
],"nextCursor":42,"hasMore":false}
```

Semantics:
- `entries` are ordered by `seq` ascending and **contiguous**: `entries[0].seq == after + 1` and each next seq is previous + 1. A client observing any other arrangement treats it as a protocol violation: stop, keep its durable cursor, and re-pull (gaps mean server-side corruption or a forged response, never "skippable" data).
- `nextCursor` is the last delivered entry's `seq`; the client persists it **only after durably applying the entries locally**.
- Empty page: `entries: []`, `nextCursor == after` (input cursor preserved), `hasMore: false`.
- `hasMore: true` means at least one more committed entry exists beyond `nextCursor`; the client keeps pulling.
- `maxBytes` bounds the serialized response. If the **first** candidate entry alone exceeds it: `400 item_too_large` — fail explicitly, never loop on empty pages.
- `limit > 64`: `400 page_too_large`.
- Cursor validity: `after > head seq` → `400 cursor_invalid` (an ahead-of-log cursor indicates data loss or a forged cursor; the server never silently resets it). Malformed cursor (non-integer, negative) → `400 cursor_invalid`. "Expired cursor" cannot occur in v1 (full retention, no pruning); the code is reserved for a future retention/snapshot bootstrap protocol.

Failure example (`400`):
```json
{"protocolVersion":1,"requestId":"req_aa00bb11cc22dd33ee44","error":{"code":"cursor_invalid","message":"cursor 99999 is ahead of channel head 42","retryable":false}}
```

## 6. Error model

Every failure response is one shape:
```json
{"protocolVersion":1,"requestId":"…|null","error":{"code":"…","message":"…","retryable":true|false}}
```

Stable codes, HTTP status and retryability (frozen; clients switch on `code`, never on `message`):

| Code | HTTP | Retryable | Meaning |
|---|---|---|---|
| `version_unsupported` | 400 | no | `protocolVersion` ≠ 1 (request or envelope level) |
| `bad_request` | 400 | no | malformed JSON, unknown field, missing field |
| `unauthorized` | 401 | no | missing/unknown token |
| `forbidden` | 403 | no | valid token, wrong role/scope/channel |
| `channel_not_found` | 404 | no | path channel does not exist |
| `payload_too_large` | 413 | no | a single envelope exceeds 4 MiB |
| `batch_too_large` | 413 | yes | batch count > 16 or total > 8 MiB |
| `idempotency_conflict` | 409 | no | same `(channel, messageId)`, different content |
| `cursor_invalid` | 400 | no | malformed or ahead-of-log cursor |
| `page_too_large` | 400 | no | `limit` > 64 |
| `item_too_large` | 400 | no | first entry exceeds `maxBytes` |
| `quota_exceeded` | 507 | yes | channel or disk budget exhausted; reads stay available |
| `rate_limited` | 429 | yes | too many requests; response carries `Retry-After` |
| `room_not_found` | 404 | no | pairing room does not exist |
| `room_full` | 409 | yes | room already has 2 participants |
| `room_expired` | 410 | no | pairing room TTL elapsed |
| `internal` | 500 | yes | unexpected server error |

## 7. WebSocket: pairing rooms

Pairing rooms let two devices that hold the same short code exchange pairing handshake frames through the relay. The relay forwards frames opaquely; it never sees the code (that stays device-side, per the code policy in PROTOCOL.md §2).

Create room — `POST /v1/pairing/rooms`, no credential, rate-limited per source IP:
```json
{"protocolVersion":1,"requestId":"req_room_create_0011"}
```
Response `201 Created` — the capability is shown once:
```json
{"protocolVersion":1,"requestId":"req_room_create_0011","roomId":"rm_5a6b7c8d9e0f","capability":"7JezN-xQt0Wm9cLpA2bV_w","expiresAt":"2026-11-14T12:02:00Z"}
```
- `capability` is 128 bits of fresh randomness (base64url), **independent of the short code** — knowing or guessing the code does not reveal the capability, and observing the capability does not reveal the code.
- Room TTL: 120 s (matches the code TTL default). At most 2 participants. At most 16 join attempts per room, then the room dies (`room_expired`). Expired rooms are swept.

Join — `GET /v1/pairing/{roomId}` with `Authorization: Bearer <capability>`, WebSocket upgrade. The capability rides **only** in the header, never the URL. The server sends, as the first message:
```json
{"protocolVersion":1,"type":"room.joined","roomId":"rm_5a6b7c8d9e0f","peerJoined":false}
```
`peerJoined` flips to `true` (a fresh `room.joined` is **not** re-sent) when the second participant connects.

Frame relay — either participant sends:
```json
{"protocolVersion":1,"type":"pairing.frame","data":"<base64url of the raw pairing frame>"}
```
The server forwards it verbatim to the other participant as the same shape. Frames are opaque bytes ≤ 16 MiB (the core's `MAX_FRAME_BYTES`; the relay applies the cap while reading, before allocation). Any other `type`, an unknown field, or an oversized frame closes the socket with 1008.

Close codes (frozen): `4401` capability invalid; `4404` room not found; `4409` room full (third participant); `4410` room expired or attempt limit hit; `1011` internal. Before closing with 44xx the server sends one `error` message (`{"protocolVersion":1,"type":"error","code":"room_expired","message":"…"}`).

Heartbeats: server pings every 30 s; a connection idle > 90 s (no pong, no frame) is closed with 1001. Shutdown closes rooms with 1001 after draining in-flight frames.

## 8. WebSocket: channel update notifications

`GET /v1/channels/{channelId}/events` with a `pull`-scope credential, WebSocket upgrade. First server message: `{"protocolVersion":1,"type":"events.subscribed","channelId":"…"}`. After each committed append on that channel the server pushes a **hint**:
```json
{"protocolVersion":1,"type":"channel.appended","channelId":"ch_9f8e7d6c5b4a3f2e1d0c","seq":43}
```
Notifications are lossy by design: a missed or dropped hint loses nothing — clients treat them as "something may have changed, pull from your cursor". On (re)connect the client always pulls by cursor; the subscription itself carries no state. A revoked credential's stream is closed server-side with 4401 on the next heartbeat or push attempt. Heartbeat/idle rules as §7.

Browser clients MUST present an `Origin` header matching the configured `allowedOrigins`; other origins are rejected at the upgrade with 403. Non-browser clients (no Origin) are unaffected.

## 9. Limits and defaults (frozen for v1)

The server MAY configure lower values; nothing above a maximum is accepted.

| Item | Default | Maximum | Note |
|---|---|---|---|
| single envelope | — | 4 MiB serialized | `payload_too_large` |
| append batch count | — | 16 | `batch_too_large` |
| append batch bytes | — | 8 MiB total | `batch_too_large` |
| pull `limit` | 16 | 64 | `page_too_large` |
| pull `maxBytes` | 4 MiB | 16 MiB | `item_too_large` when the first entry exceeds it |
| request body | — | 16 MiB | server-level cap, read incrementally |
| `requestId` | — | 64 chars | ≥ 1 char |
| `channelId` | — | 128 chars | server-assigned |
| room capability | 128-bit | — | base64url, shown once |
| room TTL | 120 s | — | fixed, matches code TTL default |
| room participants | — | 2 | `room_full` beyond |
| room join attempts | — | 16 per room | then `room_expired` |
| room creation rate | 16/min/IP | — | `rate_limited` |
| pairing frame | — | 16 MiB | core `MAX_FRAME_BYTES`, enforced during read |
| WS heartbeat | 30 s ping | — | idle > 90 s → close |
| append rate | 32 req/s per credential | burst 64 | `rate_limited` + `Retry-After` |
| pull rate | 32 req/s per credential | burst 64 | `rate_limited` + `Retry-After` |
| channel quota | 1 GiB | — | `0` disables; `quota_exceeded` on append only |
| disk quota | 8 GiB | — | `0` disables; reads never blocked by quota |
| retention | keep all | — | no pruning in v1; retention needs a new cursor/bootstrap protocol |
| sequence | u64 per channel | — | starts at 1, gapless, assigned in the append transaction |
| listen address | `127.0.0.1:8080` | — | public exposure requires a TLS reverse proxy |
| database | SQLite WAL, `synchronous=NORMAL` | — | ack ⇒ committed |

## 10. Worked examples

**Append, lose the ACK, retry safely.**
1. Client POSTs a 3-envelope batch → connection drops before the response.
2. Client re-POSTs the byte-identical request (same `requestId` is fine; envelopes identical).
3. Server: every envelope hits the `(channel, messageId)` idempotency record → `200` with the original three seqs, all `duplicate: true`. Nothing is stored twice; no reader sees duplicates (pull returns each envelope once, at its original seq).

**Client falls behind, catches up.**
1. Client's durable cursor is 41; head is 87; pull with `after: 41, limit: 16` → entries 42–57, `nextCursor: 57`, `hasMore: true`.
2. Client applies entries durably, persists cursor 57, pulls again → 58–73, … until a page returns `hasMore: false`.
3. A notification hint arriving mid-catch-up changes nothing: the next pull already covers it.

**Tampered batch is rejected atomically.**
1. Batch of 2 where envelope #2 fails shape validation (unknown field `ttl`).
2. Server rejects the whole request `400 bad_request`; envelope #1 is **not** committed — partial batches never exist.

**Revoked device.**
1. Admin revokes `cred_phone`; the device's open event stream is closed 4401 on the next push attempt.
2. The device's next `/append` → `401 unauthorized` (digest gone). Other devices' credentials are untouched; their streams and appends continue.

## 11. Out of scope for v1

Server-side merges, plaintext visibility, tenant/billing models, federation between relays, P2P transports, retention/pruning, and multi-channel fan-out are outside this contract. Changing any frozen field, code, route or limit requires a relay contract v2 with the same hard-version-reject rule.
