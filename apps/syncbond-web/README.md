# syncbond web demo

A minimal single-page demo of the browser WASM bindings: one page, three
sections — identity, entries, pairing. Vite + plain TypeScript, no UI
framework. **Demo-grade**: the provisioned tokens live in a gitignored JSON
file and the relay is expected on loopback.

What it shows:

- **Identity** — generate, export (file download), and import (file upload)
  a device identity (Ed25519 keypair) via `WasmIdentity`.
- **Entries** — replicator CRUD. Before pairing, writes land in a standalone
  `WasmReplicator` persisted under the demo's IndexedDB prefix
  (`syncbond-web-demo*`), so a refresh keeps them and they are carried into
  the paired device afterwards. After pairing, writes are sealed envelopes
  staged in an outbox, synced against the relay (`append`/`pull`).
- **Pairing** — two browser contexts (two browsers, or two profiles of one)
  pair through the relay's pairing rooms: one creates an invite (SPAKE2
  display code + room link), the other opens it. Both ends must show the
  same code; the handshake runs over the room WebSocket; the session's
  group facts travel the session's encrypted app channel afterwards.
  "Go offline" pauses sync while writes keep staging; coming back online
  drains them to the peer.

The demo never hardcodes a relay address: the dev proxy targets
`SYNCBOND_RELAY_URL` (default `http://127.0.0.1:8080`).

## Quick start

From the repository root (Node 24 + pnpm, stable Rust):

```sh
# 1. Build the browser WASM bindings (gitignored wasm-gen/ output).
sh scripts/build-wasm.sh

# 2. Run the relay server locally with the demo config.
cargo build -p syncbond-server
./target/debug/syncbond-server apps/syncbond-web/relay.example.json
#   The config listens on 127.0.0.1:8080 and writes to apps/syncbond-web/relay-data/
#   (gitignored). First start bootstraps the admin credential file there.

# 3. Provision one channel + two credentials, then open the demo.
cd apps/syncbond-web
pnpm install
pnpm provision            # writes public/provision.json (gitignored)
pnpm dev                  # http://localhost:5173
```

Then pair:

1. Open <http://localhost:5173> in browser A; click **create invite**.
2. Open the shown invite link in browser B (another browser or another
   profile of the same one). Both pages show the same pairing code.
3. When both report **paired**, write an entry in A — it appears in B
   within a couple of seconds.
4. Tick **go offline** in A, write another entry, untick it — the staged
   write drains and appears in B.

Storage isolation: the demo keeps everything under the IndexedDB names
`syncbond-web-demo` (page metadata) and `syncbond-web-demo-devices` (device
driver records) — a future production frontend shares nothing with it.
Use each browser's "wipe demo" button to start over.

## Notes

- A browser `WebSocket` cannot set an `Authorization` header, which the
  relay requires. The Vite dev server proxies `/relay/*` to the relay and
  injects `Authorization: Bearer <cap>` from the invite link's `cap` query
  parameter, stripping the query before the relay sees the request — the
  capability rides a URL only between the two demo browsers, never on the
  relay side. In production, put a header-capable proxy in front, exactly
  like this demo's dev server does.
- `room.joined`'s `peerJoined` decides the SPAKE2 roles: second arrival is
  the initiator. Whichever end created the invite, arrival order is what
  counts; the page shows the role it got.
- The relay's room-creation rate limit is 16/min/IP and rooms live 120 s;
  if pairing stalls, create a new invite rather than reusing an old link.
- A relay channel is one group's append log, and every pairing derives a
  fresh group id — so start each demo session with `pnpm provision` (it
  creates a new channel; old channels simply go unused). Reusing a channel
  across sessions would poison the pull with the previous group's
  envelopes, which the keyring rejects.
