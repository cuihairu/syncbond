# Research: iroh as a P2P transport — hole-punching rate & relay fallback

> **Research input, not repo facts.** Everything below summarizes iroh as understood on 2026-10-28; every claim must be re-verified against the linked sources before being treated as a property of this repository. Sources located 2026-10-28 via the iroh blog index, docs.iroh.computer, and docs.rs.

Question under assessment (todo.md P2 workline): **can iroh serve as syncbond's P2P transport, and what is the expected hole-punching success rate and relay-fallback path?**

Answer up front: iroh's model is **direct-connection-first** — QUIC (via `noq`) over UDP with hole punching, falling back to a stateless relay that only forwards ciphertext. **iroh publishes no officially measured hole-punching success rate.** The figures that circulate (92–98% "direct") are illustrative marketing examples, not measured telemetry. A syncbond pilot that measures its own direct/relayed split is required before trusting them. The relay path is sound for an E2EE sync SDK: relays are stateless, E2EE-preserving, and swappable (public / managed / self-hosted), so they do not weaken the security model — only the availability model.

---

## 1. What iroh is (the relevant parts)

- **Accountless, key-addressed**: endpoints are dialed by public key, not IP. "IP addresses break, dial keys instead" (Iroh 1.0 launch, `/blog/v1`); the long-standing dial-by-NodeID-no-address work (`/blog/iroh-dns`, `iroh 0.14.0 – Dial the world`).
- **Transport**: QUIC via the `noq` stack; QUIC multipath became a 1.0 pillar (`iroh 0.96.0 – The QUIC Multipaths to 1.0`), and custom transports / `noq` landed in 0.97.
- **Direct first**: "The fastest route is a direct connection, so if necessary, iroh tries to hole-punch" (project README). Direct UDP hole punching is attempted before any relay.
- **Relay fallback**: "iroh establishes direct connections whenever possible, falling back to relay servers if necessary" (docs.iroh.computer landing). Relays are **stateless** — they hole-punch and forward; "no data is stored on the relay servers," and traffic is end-to-end encrypted (`/blog/shared-relays`). Clients try multiple relays and "seamlessly fall back to another" when one is unreachable (`docs/add-a-relay`).
- **Deployment scale**: "in production on hundreds of thousands of devices" (site footer boilerplate — scale claim, not a success-rate metric).

## 2. Hole-punching success rate — what is actually documented

**No published measured rate.** The team describes the result qualitatively and never publishes an aggregate percentage:

- `the-road-to-iroh-1-0`: "in most normal circumstances we punched holes almost immediately, and in the few corporate networks where hole punching was impossible, at least we could still transfer data via relays." Hole punching "was a huge effort," and the resulting rates were "to be proud of" — **no number given**.
- `iroh-0-98-0-getting-back-to-traversing-nats`: fixes regressions where "holepunching wasn't re-triggered on network changes" and "connections that used to punch through would sometimes sit on the relay." No success-rate statistic; the numeric facts are timing knobs (PTO capped at 2 s post-handshake; relay re-ping now immediate, 3× last RTT min 500 ms instead of waiting up to 5 s).

**The circulating figures, each labeled by what it actually is:**

| Figure | Source | What it is | Confidence |
|---|---|---|---|
| ~95% "direct" | iroh.computer homepage cost model | **illustrative** cost-model assumption, explicitly footnoted "Illustrative estimate based on 95% direct traffic. Actual direct rates and costs vary by network conditions, usage, and region." | Illustrative only — not telemetry |
| 98% direct traffic | `/blog/shared-relays` worked example | a cost example (2,000 endpoints × 10 GB/mo ⇒ 20 TB total, "98% of the traffic" direct ⇒ 400 GB relayed) | Example arithmetic, not measurement |
| 93.10% | `/blog/shared-relays` dashboard screenshot | one user's "direct data rate" metric in a screenshot | Single anecdote |
| ~92% direct UDP | search-result snippet, 2025 blog post | **unverified** — the post was not re-located on 2026-10-28; the figure could not be confirmed from a primary source | Unverified — do not cite as fact |

**Conclusion for this assessment**: treat the hole-punching rate as *"illustratively in the low-to-mid 90s %, with no measured value published; the failure mode (relay fallback) is fully supported and E2EE-safe."* Design for the direct path as the happy path and the relay as a budgeted, expected fallback — not as an anomaly.

Independent confirmation of the *mechanism's* feasibility is well established (RFC 5389 / NAT-type literature: hole punching works when neither endpoint is symmetric-NAT; the residual population is where relays earn their keep). iroh's own framing agrees: the only case it names as hole-punch-impossible is "corporate networks" (symmetric NAT / firewall egress restrictions).

## 3. Relay fallback path (the part the assessment must pin down)

- **Relay modes (iroh 1.4.1, `iroh::endpoint::RelayMode`)** — four variants, no `RelayOnly` in this version:
  - `Disabled` — relays off entirely; direct only.
  - `Default` — n0 production relay map; relays available for listening and dialing; fallback on direct failure.
  - `Staging` — n0 staging relays, for test/dev.
  - `Custom(RelayMap)` — user-supplied relay infrastructure (self-hosted, or an Iroh Services preset).
- **Relay provisioning**:
  - **Public** — n0's public relays, free, rate-limited (increasingly enforced as iroh grew; `/blog/shared-relays`).
  - **Managed** — Iroh Services Pro ($19/mo, shared relay, 5 MB/s, 100 GB egress incl.; +$0.09/GB) or Dedicated ($199/region + Pro); Pro/Dedicated relays are **authenticated** — "Protect your relays" (July 2026, `/blog/authenticated-relays`) made managed relays authenticated by default.
  - **Self-hosted** — `iroh-relay` binary on a public-IP host; built-in ACME TLS; free to run, you own availability/latency/ops (`docs/add-a-relay`).
- **Cost shape** (why direct-first matters to an SDK): at 2,000 endpoints / 400 GB relayed egress, the shared-relay example is ≈$46/mo, claimed ~38–39× cheaper than an AWS EC2 WebSocket server for that shape; and "direct connections do not count against relay egress." "Keeping around 100k hole-punched connections that just ping the relay path every ~5s or so is really cheap."
- **Security posture**: relays are E2EE-transparent (ciphertext only) — the exact property syncbond needs; its own session encryption sits above transport regardless. Security history to note: `iroh 1.0.2 – iroh-relay security fix`, `iroh 1.1.0 – security fixes`, `iroh 1.4.0 – security updates and better local networking`, and the authenticated-relay change. This is a maintained, security-reviewed component, but it is a real attack/availability surface — a reason to prefer self-hosted or authenticated managed relays over the open public pool where syncbond's relay carries real traffic.

## 4. Fit for syncbond

syncbond is already accountless, key-addressed, E2EE, and transport-agnostic, with a working **WebSocket minimal persistent relay** (`crates/syncbond-core/src/relay.rs`, P2 首项, commit `27c139d`). iroh would not replace the pairing/sync protocol — it would replace/augment the *transport* under it:

| Aspect | Current WebSocket relay | iroh transport |
|---|---|---|
| Topology | central server relays everything | direct-first (95%+ illustrative), relay only on failure |
| Relay role | the main path | a fallback |
| Addressing | server address | dial by public key |
| E2EE | payload-level (session encryption above transport) | same — relay forwards ciphertext only |
| Accountless | yes | yes |
| Dependency weight | none (WS in core) | heavy (iroh + noq + quinn stack) |
| Browser/WASM | works (WS) | QUIC in browsers needs WebTransport — a separate integration path (alpha since 0.32/0.33); not the same code path as native |
| Ops burden | you run the relay | public/managed/self-hosted relay options |

**Recommendation (assessment deliverable, not a repo change):**

1. **Keep the WebSocket relay as the minimum accountless path.** It is already green, E2EE, and browser-compatible; it is the guaranteed path.
2. **Adopt iroh behind a feature gate as the optional direct-P2P transport.** Its value is the ~20× relay-egress reduction implied by the illustrative direct rates, not the (unpublished) success rate per se. Gate it so the core stays dependency-light and the WASM target is unaffected.
3. **Do not budget capacity on the 92–98% figures.** Measure your own direct/relayed split in a pilot (two real NATs, real devices) before sizing a managed relay or promising latency; treat the published figures as illustrative.
4. **For any relay carrying real syncbond traffic, prefer authenticated managed or self-hosted relays** over the open public pool (rate limits + the relay security history above).
5. **Defer browser/WASM** under iroh (WebTransport path) to a separate validation; the WS relay already covers the browser.

## 5. Evidence limits & follow-ups

- **No empirical hole-punching run was possible from this environment** (sandbox, single network egress, no second NAT). The assessment is documented-findings only; the pilot in recommendation 3 is the required empirical step.
- The "92% direct" snippet from earlier search remains **unverified** — its source post was not re-located; treat as unconfirmed.
- `RelayMode`/relay facts are pinned to **iroh 1.4.1** (docs.rs as of 2026-10-28); the API is evolving (0.95 new relay, 0.91 relay standards, 1.x security releases), so re-check at adoption time.

## Sources (located 2026-10-28)

- https://www.iroh.computer/blog — index (post list)
- https://www.iroh.computer/blog/the-road-to-iroh-1-0 — hole punching qualitative, corporate-NET failure case
- https://www.iroh.computer/blog/iroh-0-98-0-getting-back-to-traversing-nats — NAT-traversal regression fixes, timing knobs
- https://www.iroh.computer/blog/shared-relays — relay cost shape, stateless/E2EE relays, 98% & 93.10% figures, direct-does-not-count-against-egress
- https://www.iroh.computer/blog/authenticated-relays — managed relays authenticated by default (July 2026)
- https://www.iroh.computer/blog/iroh-1-0-3 — steadier connections (no metrics)
- https://www.iroh.computer/ — homepage cost model, "95% direct" illustrative footnote
- https://docs.iroh.computer/ and https://docs.iroh.computer/add-a-relay — relay config, self-hosting, seamless relay fallback
- https://docs.rs/iroh/latest/iroh/endpoint/enum.RelayMode.html — RelayMode variants (Disabled/Default/Staging/Custom), iroh 1.4.1
- https://www.iroh.computer/blog/iroh-1-0-2 — iroh-relay security fix
- https://www.iroh.computer/blog/relay-down-a-post-mortem — relay outage post-mortem
