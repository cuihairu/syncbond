[中文](zh/deploy.md)

# Running the relay: operations guide

Status: **the default server ships** (`apps/syncbond-server`, todo.md DSR-11 through DSR-50). This page is the follow-along guide for a deployer: start it, put TLS in front, issue credentials, set quotas, back up, restore, and upgrade. The contract it serves is frozen in the [relay protocol (v1)](design/relay-protocol.md) spec; the trust boundary and responsibilities are recorded in the [default server design](design/default-server.md).

Everything here is deterministic: every command has been run against the shipped image and binary by the acceptance suites (`apps/syncbond-server/tests/`).

## 1. What you are running

A single process that stores **ciphertext envelopes** and forwards pairing frames. It never sees plaintext operations, pairing short codes past their use, identity keys, or group keys — those live on devices. The deployer holds one **admin bootstrap credential**, creates channels, and issues per-device, per-channel credentials. Public deployments terminate TLS in a reverse proxy; the relay itself speaks plaintext HTTP/1.1 + WebSocket on one port.

State is one directory (the `dataDir`): a SQLite database (`relay.db` plus its `-wal`/`-shm`) and the `admin-credential` file. Nothing else persists.

## 2. Quick start (Compose)

From the repository root:

```sh
docker compose -f deploy/compose.yaml up -d
```

That builds the image (`deploy/Dockerfile`), starts the container with a named volume (`relay-data`) for `/data`, and the image's own health check reports readiness. Nothing is required in advance — the container uses the config baked into the image and the server generates its admin credential into the volume on first boot.

Check it:

```sh
docker compose -f deploy/compose.yaml ps          # expect: Up (healthy)
curl http://127.0.0.1:8080/v1/ready               # {"status":"ready"}
```

The published port is bound to `127.0.0.1` only — plaintext is local-development-only. If the host already uses 8080, pick another host port without touching the file:

```sh
SYNCBOND_HTTP_PORT=18080 docker compose -f deploy/compose.yaml up -d
```

Stop (keeps the data volume; `-v` deletes it):

```sh
docker compose -f deploy/compose.yaml down        # add -v to also delete the data
```

## 3. Running the binary directly

```sh
cargo build --release --locked --package syncbond-server
./target/release/syncbond-server /path/to/config.json
```

The single argument is the config file path; without it the process prints usage and exits 2. Invalid configuration exits non-zero before anything is created — an unreadable or newer database is a hard stop, never a wipe. `SIGINT`/`SIGTERM` start a bounded drain; the exit code is 0 once everything acknowledged has been checkpointed.

In a container the same binary runs as a non-root user (`syncbond`, UID 1000) with the config at `/etc/syncbond/config.json`:

```sh
docker build -f deploy/Dockerfile -t syncbond-server .
docker run -d -p 127.0.0.1:8080:8080 -v syncbond-data:/data syncbond-server
```

A host bind (instead of a named volume) must be writable by UID 1000: `chown 1000:1000 /host/data`.

## 4. Configuration

One JSON file, closed shape: unknown fields fail startup, so a typo never silently disables a setting.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen` | address | `127.0.0.1:8080` | Bind address. The shipped container config uses `0.0.0.0:8080` — that is the container-internal face; the public edge is the TLS proxy. |
| `dataDir` | path | `./data` | Database + `admin-credential`. Must be non-empty and not `/`. |
| `channelQuotaBytes` | bytes | 1073741824 | Per-channel budget. `0` disables; otherwise at least 4 MiB (one maximal envelope). |
| `diskQuotaBytes` | bytes | 8589934592 | Whole-database budget, same `0`-or-≥4 MiB rule. |
| `allowedOrigins` | list | `[]` | Browser origins allowed to open WebSocket connections. Empty means no browser origins; non-browser clients are unaffected. |
| `trustedProxies` | list | `[]` | Proxy IPs/CIDRs whose `X-Forwarded-For` may be believed (see §7). |
| `maxWsSessions` | count | 64 | Live WebSocket sessions (pairing + events) admitted at once. `0` disables the limit. |
| `maxConnections` | count | 256 | TCP connections handled at once; above it, connections are dropped at accept. `0` disables. |
| `headerTimeoutSeconds` | seconds | 30 | Time to finish sending request headers (slowloris bound). `0` disables. |
| `shutdownTimeoutSeconds` | seconds | 10 | How long the shutdown drain may last. `0` waits for every connection. |

The full-surface example is [`deploy/config.example.json`](https://github.com/cuihairu/syncbond/blob/main/deploy/config.example.json); the minimal file baked into the image is `deploy/config.json`. To override the config in Compose, bind a file over the baked one:

```yaml
    volumes:
      - ./my-config.json:/etc/syncbond/config.json:ro
```

Frozen contract values (room TTL, frame caps, rate limits, heartbeat) are **not** configurable — see the limits table in §13.

## 5. Health checks

Two unauthenticated GET routes on the listen port:

- `/v1/health` — liveness: the process answers. Never touches storage.
- `/v1/ready` — readiness: flips only after the listener is up **and** the store is open.

The container image's `HEALTHCHECK` probes `/v1/ready` every 30 s (5 s timeout, 15 s start period, 3 retries), so `docker ps` reports the truth. If you bind a non-default port in your config, override the health command to match (`docker run --health-cmd ...`).

## 6. TLS reverse proxy

The relay speaks plaintext; **a public deployment must terminate TLS in front of it** (default-server.md §4). The proxy and the relay talk on the docker network or loopback; clients only ever see `https://`/`wss://`.

nginx, terminating TLS for `relay.example.com` and forwarding to the container's published loopback port:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;
    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;      # WebSocket pairing/events
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;                     # > the 90 s idle timeout
    }
}
```

Caddy does TLS, WebSocket upgrade and the header in one line:

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

In both cases keep the compose port mapping loopback-only (`127.0.0.1:8080:8080`) so the plaintext face is reachable only from the proxy on the same host, and list the proxy's address in `trustedProxies` (§7) so the pairing-room rate limit keys on the real client IP.

## 7. Browser Origins and trusted proxies

**Origins.** Browser WebSocket connections are checked against `allowedOrigins` — list the exact origins your web app is served from (`https://app.example.com`). Non-browser clients (the Rust/TS/Python bindings, curl) are not subject to the Origin check. Empty (the default) allows no browser origins at all.

**Proxy trust.** The pairing-room creation rate limit is keyed by client IP. Directly exposed, the key is the peer socket address. Behind the recommended proxy every peer *is* the proxy, so list the proxy's addresses (IP or CIDR) in `trustedProxies`; for a peer on that list, the client address is taken from `X-Forwarded-For`, scanning from the right, exactly one hop past the trusted proxies. Anything further left was written by the client itself and is never trusted — which is why a header from an untrusted peer is ignored completely: a loopback caller cannot mint new rate-limit budgets by sending `X-Forwarded-For`.

```json
{
  "listen": "0.0.0.0:8080",
  "dataDir": "/data",
  "allowedOrigins": ["https://app.example.com"],
  "trustedProxies": ["172.16.0.0/12", "127.0.0.1"]
}
```

`172.16.0.0/12` covers the default docker bridge networks; narrow it to your compose network's subnet if you know it. Names that are not an IP or CIDR fail startup, not rate limiting.

## 8. Credentials

**The admin bootstrap credential.** On first boot (fresh database) the server generates a 64-hex-char token, writes it to `dataDir/admin-credential` with owner-only permissions, and thereafter verifies it in constant time against admin requests. It is the one secret the deployer must keep — back it up with the database (§10). If the database exists but the file is missing, the server **refuses to start without touching data** (regenerating would hand a fresh key to whoever deleted the file): restore it from your backup instead.

```sh
# In the compose deployment:
docker compose -f deploy/compose.yaml exec relay cat /data/admin-credential
```

**Channels and per-device credentials.** All admin calls carry the token as the bearer credential; the relay-client crate (used by every binding) wraps the exact calls:

```rust
use syncbond_relay_client::{RelayClient, TlsPolicy};
use syncbond_relay_protocol::dto::CredentialScope;

let client = RelayClient::new("https://relay.example.com", TlsPolicy::Validate, timeout)?;
// One channel per replication group:
let channel = client.create_channel(admin_token, "req-1").await?;   // -> channel_id
// One credential per device per channel — the token is shown exactly once:
let issued = client.issue_credential(
    admin_token, &channel.channel_id,
    &[CredentialScope::Append, CredentialScope::Pull],
    Some("phone"), "req-2").await?;                                  // -> token
// Revoke the moment a device is lost (independent of group key rotation):
client.revoke_credential(admin_token, &channel.channel_id, &credential_id).await?;
```

Deliver credentials over a protected side channel to the device that needs them — never in URLs or logs. Revocation is a persisted flag re-read on every authorize, so a revoked token is refused immediately; revoking an already-revoked credential is still 200. An unknown or revoked token is 401; a valid token without the scope or on the wrong channel is 403. Neither group ids nor device ids are credentials — losing one credential compromises one device's access to one channel, nothing more.

## 9. Quotas

Two budgets, both from the config: `channelQuotaBytes` per channel and `diskQuotaBytes` across the whole database. Both accept `0` (disabled) or a value of at least 4 MiB — one maximal envelope — because a smaller non-zero budget could never admit a write.

When a batch would cross a quota the append is refused with **HTTP 507 `quota_exceeded`** and the **whole batch rolls back** — partial batches never exist, so a retry is always safe. Reads and admin calls are never blocked by a quota: a full channel can still be pulled and administered. Quotas count stored bytes; the crypto inside envelopes is the clients' business, and the relay charges only what it stores.

## 10. Backup and restore

The entire state is the data directory: `relay.db`, `relay.db-wal`, `relay.db-shm`, and `admin-credential`. Back it up stopped (this is what the server itself does on shutdown — it folds the WAL before exiting, which is why a clean stop is the natural backup point):

```sh
docker compose -f deploy/compose.yaml stop relay
docker run --rm -v syncbond_relay-data:/data -v "$PWD":/backup alpine \
    tar czf /backup/syncbond-data-$(date +%F).tar.gz -C /data .
docker compose -f deploy/compose.yaml start relay
```

(With a plain binary: `systemctl stop syncbond-server && tar czf backup.tgz -C /var/lib/syncbond .`.)

Restore is the reverse: stop, replace the directory's contents with the backup, start, and confirm `{"status":"ready"}`. Everything the old server ever acknowledged is pullable again — the acceptance suites pin exactly this (`resource_shutdown_suite.rs`: three acknowledged appends survive a stop, and `pull` returns them, seq 1..3, after restart on the same `dataDir`).

Copying a **live** database is not covered by that promise: the `-wal` may hold acknowledged-but-unfolded data. If you cannot stop the server, use SQLite's online backup (`sqlite3 relay.db ".backup '/backup/relay.db'"`) rather than a file copy, and still back up `admin-credential` separately.

## 11. Upgrades

Database migrations are strictly upward via SQLite's `PRAGMA user_version`. Consequences for the deployer:

- **Upgrading** the server (newer binary/image on an older database) migrates forward on boot.
- **Downgrading** (older binary on a newer database) refuses to start — `database schema version N is newer than this server supports (M); refusing to start without touching data`. Your data is never wiped; restore the old binary or restore a backup taken before the upgrade.

The procedure:

```sh
# 1. Back up (§10) — the no-tears rule before every upgrade.
# 2. Replace the image/binary:
docker compose -f deploy/compose.yaml build
# 3. Recreate and verify:
docker compose -f deploy/compose.yaml up -d
curl http://127.0.0.1:8080/v1/ready
```

The data volume survives container recreation (named volumes are not removed by `down` without `-v`), so channels, credentials, and envelopes carry across upgrades unchanged.

## 12. Shutdown behavior

`SIGTERM` (what `docker stop` and every service manager sends) starts a drain bounded by `shutdownTimeoutSeconds`: accepted requests finish, each WebSocket is closed with a declared code (`1001`) after flushing what it already queued, then the WAL is folded and the process exits 0. Everything acknowledged before the signal is pullable after restart — copying the data directory of a cleanly stopped server is a valid backup (§10).

## 13. Frozen limits (reference)

Not configurable; a server MAY be configured below these maxima, never above (relay-protocol.md §9):

| Limit | Value |
|---|---|
| One envelope (serialized) | 4 MiB |
| Envelopes per append batch | 16 |
| Total batch bytes | 8 MiB |
| Whole request body | 16 MiB (transport-level 413 above it) |
| One pairing frame | 16 MiB |
| Per-socket outbound queue | 17 MiB (a peer that cannot drain is closed 1013) |
| Pull page | 64 entries / 16 MiB (defaults: 16 / 4 MiB) |
| Pairing room | 2 participants, 120 s TTL, 128-bit capability |
| Room creation rate | 16 per minute per client IP |
| WebSocket heartbeat / idle close | 30 s / 90 s |

Oversized or malformed input ends the connection with a declared close code (`1008` protocol violation, `1013` outbound budget exhausted, `1001` peer departure/shutdown, `4401` revoked credential, `4410` room expired) — never a hang and never a reset where the contract promises a code. The resource and shutdown acceptance suite (`apps/syncbond-server/tests/resource_shutdown_suite.rs`) pins each of these behaviors over the shipped binary, and the ciphertext-boundary suite pins that no secret rides the server's files, logs, or traffic.
