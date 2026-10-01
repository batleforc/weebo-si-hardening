# endpoint-auth: what the gate costs, and what to do about it

RFC 0009's *Request cost* sets the budget — **p99 under 5 ms** for the gate's round trip — and
this page records what the gate was measured to cost against it, where the time actually goes,
and the improvements that follow from the numbers. Each improvement carries a status; update it
in the change that ships it.

## How it is measured

| Tool | What it times | Run it |
| --- | --- | --- |
| The [`perf`](../.github/workflows/perf.yaml) workflow, nightly and on demand | Both tools below, on a **release** build, with both tables in the job summary. | `gh workflow run perf.yaml` — or `task envtest:perf` locally |
| The conformance suite's cost matrix (`bins/endpoint-gateway/tests/conformance.rs`) | The real gateway binary behind a real Traefik over a real apiserver. Through Traefik, every row next to the same request on a route with no middleware; straight at `/auth` for what Traefik cannot carry from loopback. | `task envtest:conformance` — CI appends the table to the `envtest` job summary |
| The binary's in-process `cost` test (`bins/endpoint-gateway/src/cost.rs`) | Each step of `/auth` in isolation, including the user identities the conformance suite cannot sign in as. | `cargo test --release -p endpoint-gateway --bin endpoint-gateway cost -- --ignored --nocapture` |
| `crates/weebo-si-endpoint-auth/benches/decide.rs` | `decide()` alone. | `cargo bench -p weebo-si-endpoint-auth` |

CI runs the matrix against a **debug** build, about ten times slower than release; its table says
which. Everything here is loopback: the in-cluster hop a real controller pays (0.2–1 ms, RFC 0009)
comes on top.

## What was measured (2026-10-01, release build, loopback)

Through Traefik — the cost the gate *adds*, gated minus ungated:

| Credential | Protocol | Added p50 | Added p99 |
| --- | --- | --- | --- |
| anonymous, open rule | HTTPS h1 / h2 | 0.06 ms | 0.15 ms |
| service-account token, cached | HTTPS h1 / h2 / WebSocket handshake | 0.08–0.09 ms | ≤ 0.23 ms |
| challenge (401), denial (403), plain HTTP (421) | h1 / http | ≈ 0 | ≈ 0 |

Straight at `/auth` — the gateway's own service time:

| Credential | p50 | p99 |
| --- | --- | --- |
| anonymous, open rule | 0.039 ms | 0.096 ms |
| service-account token, cached | 0.048 ms | 0.112 ms |
| a pod's own address | 0.039 ms | 0.061 ms |
| service-account token, **first use** (one `TokenReview`) | **0.47 ms** | 1.24 ms |
| forged service-account token, fresh each request | **0.44 ms** | 0.62 ms |
| forged service-account tokens, one client flooding (past the per-client burst of 10) | 0.069 ms | 1.00 ms |
| opaque bearer, fresh each request | 0.055 ms | 0.076 ms |

In process, per step:

| Step | p50 |
| --- | --- |
| `decide()`, any access type | 0.13 µs (0.25 µs with 16 path rules) |
| session cookie: cache hit / cold open / sliding re-mint | 0.3 / 0.8 / 0.9 µs |
| **OIDC bearer, cold: ES256 verify** | **222 µs** |
| OIDC bearer, cache hit | 0.2 µs |
| decision log line to stdout (`println!`) | 0.6 µs |

## Where the time goes

1. **A first-seen OIDC bearer** — the ES256 verify is about a thousand times everything else.
2. **A first-seen service-account token** — one `TokenReview`, an apiserver round trip.
3. Everything else is under a microsecond. The decision is never the cost; the log line, the
   SHA-256 fingerprints and the network hop are.

The WebSocket gate runs on the handshake only. HTTP/2's higher numbers are on both sides, so they
are Traefik's, not the gate's.

## Improvements

| # | Improvement | Why | Status |
| --- | --- | --- | --- |
| 1 | **OIDC bearer verify.** The parsed `DecodingKey` is built once per `kid` when the key set changes, instead of cloning the whole set and rebuilding the key on every verify; the key-set generation every request reads no longer clones the set either. ES256 and RS256–512 are verified with **`ring`** (`bins/endpoint-gateway/src/adapters/jwt_crypto.rs`, a `jsonwebtoken` `CryptoProvider`) rather than the pure-Rust backend — not `aws-lc-rs`, which would bring a C toolchain into the build. RSA keys under 2048 bits no longer verify. | 222 µs per first-seen bearer, and every unique signed token is a miss: a CPU flood vector as well as a latency one. | **Done** — cold ES256 verify 222 → 45 µs (×4.9). The flood itself is #2. |
| 2 | **Bound the cost of unique credentials**: a per-client limit in front of bearer verification like the one `TokenReview` already has; for service-account tokens, verify the signature offline against the cluster issuer's JWKS (Service Account Issuer Discovery) before any `TokenReview`, and reserve part of the global `TokenReview` budget for clients already seen. | A flood of forged service-account tokens costs one `TokenReview` each until the limits refuse, and the global limit is shared — the flood makes legitimate first-use tokens fail closed. | Proposed. The per-client limit is now asserted by the cost matrix: one client's fresh forged tokens past the burst are refused without a `TokenReview` (counter moves by the overflow; median 0.39 → 0.069 ms in release, the p99 being the ten that were still reviewed). A caller who varies its address — or reaches the gateway with none — still spends the shared global budget. |
| 3 | **Cached service-account token path.** The domain fingerprints a bearer once for both caches and consults the service-account cache before `verify`, which would decode the header and the unverified issuer to reach the same conclusion; the gateway's prewarm consults the reviewer's cache before the shape check that decodes and parses the payload. | ~9 µs per request over an anonymous one, on the path every workspace-to-workspace call takes. | **Done** — `/auth` with a cached service-account token 0.048 → 0.037 ms p50; the gap to an anonymous request 9 → ~3 µs. |
| 4 | **Decision log**: a buffered writer instead of `println!` per denial or challenge, or sampled deny lines; reuse the session fingerprint for the allow-log dedup instead of a second SHA-256. | 0.6 µs and a stdout lock per denial, unbounded under a denial flood. | Proposed |
| 5 | **WebSocket lifetime**: a maximum upstream connection lifetime for WebSocket routes. | Security rather than latency: the gate sees only the handshake, so an open socket outlives a logout or a removed share. | Proposed |
| 6 | **Measure what is not measured yet**: connection reuse between the controller and the gateway (RFC 0009 promises a handful of connections for a 200-request burst), and the in-cluster hop. | Both are named in RFC 0009's *Where the milliseconds actually are* and neither is asserted anywhere. | Proposed |
