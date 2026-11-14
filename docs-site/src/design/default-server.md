[中文](../zh/design/default-server.md)

# Default relay server: architecture and delivery boundary

Status: **planned on 2026-11-14; not implemented**. This document records layout, responsibilities and acceptance criteria. Atomic tasks live in the repository-root `todo.md`, under the default server plan (DSR). This is not an available API or deployment guide; the exact routes, WebSocket messages, auth, error codes and limits are frozen in the [relay protocol v1 contract](relay-protocol.md) (DSR-07).

## 1. Current state and goal

The repository currently provides MemoryTransport and MemoryRelayStore / FileRelayStore, which store plaintext Operations. There is no server executable, HTTP/WebSocket service or client network adapter. Existing durable relay tests cover a storage prototype, not a deployable default server.

Deliver an optional, self-hosted Rust relay supporting pairing between independent devices and durable synchronization across offline periods, disconnects and restarts. Applications may still inject another transport. A default server implementation does not make the SDK server-dependent or imply an official public hosted service.

## 2. Layout and dependencies

Every path below except `crates/syncbond-relay-protocol/` is planned and does not exist yet:

```text
apps/syncbond-server/
  Cargo.toml
  src/main.rs                 # startup, shutdown, component assembly
  src/config.rs               # configuration and validation
  src/routes.rs               # HTTP / WebSocket endpoints
  src/storage.rs              # ciphertext storage adapter
crates/syncbond-relay-protocol/ # shared versioned relay contract
crates/syncbond-transport-ws/   # Rust network adapter and resume driver
deploy/
  Dockerfile
  compose.yaml
```

Register the server as a separate binary crate in the Cargo workspace. The relay-protocol crate defines outer messages, errors and limits, with no business merge or key management. Both server and transport-ws depend on it; transport-ws also depends on syncbond-core. Core must not depend on the server, network client stack or asynchronous runtime. Use asynchronous server I/O and a bounded bridge to the core's synchronous Transport; do not block the server event loop. Record and lock concrete network library choices during implementation.

## 3. Responsibilities and trust

| Device | Server |
|---|---|
| SPAKE2, code policy, identity private keys, group keys | Temporary pairing rooms and handshake frame forwarding |
| Encryption, operation authentication, merge, tombstones | Ciphertext persistence, sequence numbers, deduplication, pagination |
| Atomic local state and receive progress persistence | Channel access control, rate limits, quotas, health checks |
| Member revocation and secure new-key distribution | Service credential revocation, connections, redacted logs |

The server sees routing metadata, timing, sizes, ciphertext and pairing protocol frames; it must never receive plaintext Operations, pairing codes, identity private keys or group keys. Access patterns are not hidden. Do not use FileRelayStore unchanged as the remote ciphertext backend. Signatures and MACs do not conceal rotation keys: encrypt key distribution separately for surviving devices over their secure channels. Broadcasting a new key under the previous group key cannot exclude a revoked device.

Separate service access from end-to-end group authorization. Initially the deployer holds an administration credential, creates channels and issues random per-device, per-channel credentials with read/write permissions. Credentials can be revoked independently without user accounts. Neither group IDs nor device IDs are credentials. Deliver credentials through protected configuration and TLS requests, never URLs or logs; initial distribution belongs to the application/deployer. Service credential revocation does not replace group key rotation.

## 4. Minimal network contract

The authoritative detail — exact routes, message shapes, error codes and every limit — is the frozen [relay protocol v1 contract](relay-protocol.md). This section records only the invariants behind it.

Use HTTP for control and pull requests, WebSocket for pairing forwarding and update notifications. Notifications are hints; durable logs and pull cursors are authoritative. Disconnects must not lose unacknowledged data.

- Outer messages carry a version, request ID, message type and stable error code. Reject version mismatches. Align envelope JSON with its Schema and unknown-field policy; record compatibility handling before changing existing wire serialization.
- Append encrypted envelopes per channel and return a monotonic server sequence only after commit. Deduplicate by `(channel, messageId)`: identical retries return the original sequence; conflicting content with the same ID fails explicitly. Failed commits must not return success or become readable as committed data.
- `pull(after, limit, maxBytes)` returns ordered pages, the last delivered cursor and `hasMore`. Empty results preserve the input cursor. Reject ahead-of-log, expired or invalid cursors instead of silently resetting them. Sequence gaps must not skip records.
- Apply size bounds while reading/assembling network frames, before unrestricted allocation. Bound envelopes, batches, responses and send queues. Pagination has byte and count limits; a single item that cannot fit must fail explicitly rather than loop on empty pages.
- Pairing rooms use a random routing capability of at least 128 bits, independent of the short code, with a short TTL, at most two participants and expiry cleanup. Devices enforce short-code TTL, single use and failure limits; the server limits room joins and connection attempts without knowing the code.
- Public deployments use a TLS reverse proxy; plaintext is local-development-only. Define trusted proxy settings, browser Origin checks, heartbeat, timeouts, cancellation and shutdown behavior.

P2P, federation, tenant billing and server-side business merges are outside the initial scope.

## 5. Persistence and client recovery

Plan SQLite as the default backend. Transactions persist channels, credential digests, ciphertext and sequence/idempotency indexes. Document file permissions, migrations and backup recovery. Corruption or unsupported database versions must fail startup without clearing data. Initially retain all history and reject writes at disk/channel quotas. Introducing retention requires a separate expired-cursor and snapshot bootstrap protocol.

Devices persist received operations, deduplication state, HLC high-water marks and server receive cursors consistently; advance committed receive progress only after durable storage. Maintain a recoverable outbound queue until the server acknowledges persistence. Retry after disconnects or lost acknowledgements. Keep local operation counters, source-device counters and server sequence numbers distinct.

Known correctness gaps block this delivery: ordinary remote operations are absent from the persisted log, HLC receive/recovery is disconnected, and causal/clock-skew merge outcomes can depend on delivery order. Close these with repository regression tests; existing passing tests are insufficient. Transport handles pairing frames; offline relay replication needs its own paginated driver rather than sending the entire oplog in one sync_over frame.

## 6. SDK rollout

First deliver a Rust example using two independent processes. Then expose external-frame pairing and replication persistence through the C ABI and integrate Node/Python/Go/Java/C#/C++ individually. Bindings must not reimplement SPAKE2, rotation or merges. Browsers need asynchronous single-thread protocol driving; current WASM CRUD and conformance support do not constitute browser network sync.

Dependency order: correctness fixes → shared protocol → server storage/access/network → Rust client → independent-process acceptance → language bindings → deployment and CI. Independent server/client tasks can proceed concurrently once the contract is frozen.

## 7. Release acceptance

- Pair and synchronize two independent processes over real sockets; cover offline writes, reordering, duplicates, server/client restart, lost acknowledgements and pagination boundaries.
- Received remote state survives client restart; explicitly test commit failures, clock rollback and restart within the same millisecond.
- Reject unauthorized/cross-channel requests. A revoked device cannot regain channel access or recover the new group key from observable distribution traffic.
- Search server databases, logs and captured application messages for known plaintext markers; payloads, pairing codes and group keys must be absent. This validates the tested integration, not a cryptographic audit.
- Oversized frames, slow clients, full queues and storage quotas produce bounded errors. Shutdown handles accepted commits; all acknowledged records remain readable after restart.
- Provide reproducible local startup, Docker Compose, TLS proxy guidance, configuration examples, backup/recovery and upgrade instructions. CI starts from an empty data directory and runs Rust network acceptance tests.

Do not mark the default server or real cross-device synchronization implemented until tasks have completion evidence. Preserve existing nightly/manual stable-release boundaries.
