---
rfc: 0003
title: preauth-proxy
status: Implemented
authors: [batleforc]
created: 2026-08-23
updated: 2026-08-23
decided: 2026-08-23
brick: bins/preauth-proxy
supersedes: []
superseded-by: []
---

# RFC 0003 — preauth-proxy

## Summary

`preauth-proxy` is a small reverse proxy that keeps a credential obtained from a configured
origin and attaches it to forwarded requests that do not already carry one, renewing it when the
upstream rejects it. It is deliberately domain-agnostic: the binary speaks only of *markers*,
*credentials*, *acquisition exchanges* and *injection*, and every word that would tie it to a
particular application, protocol or product lives in its configuration, not in its code. One
configuration instance makes a session-authenticated upstream reachable through a gateway that has
already authenticated the caller; the binary itself never knows that is what it is doing.

## Motivation

A recurring shape in a self-hosted fleet: an upstream authenticates callers with its own
session — a login form that sets a cookie — and has no way to delegate that decision to an
external identity provider. The identity provider is already in front of it, as a Traefik
forward-auth gateway that decides whether a request reaches the upstream at all. But the gateway
can only *gate*; it cannot *log in*. So an authorised caller is stopped at the gateway, waved
through, and then met by the upstream's own login form. Two logins for one identity, and the
second one issues credentials the gateway has no hand in.

The shape is not tied to one product, which is why this is a brick and not a script. Any upstream
with form/session auth and no OIDC hook — an OSS admin panel, a legacy dashboard, an appliance,
the free tier of a product whose external-identity support sits behind a paid plan — put behind
any forward-auth gateway hits the same wall. A component that treats "log in for the caller and
attach the result" as a configured exchange, rather than code written against one product, solves
all of them and names none of them.

### What exists today

Nothing. The status quo is the second login, per workload. The obvious per-workload alternative is
a bespoke sidecar written against whatever that upstream's login form happens to look like — which
is exactly the thing worth not writing more than once, and the reason the generic form is the one
being designed rather than the first concrete one.

**Outcome we are buying:** a workload placed behind a forward-auth gateway stops presenting its own
second login. A caller the gateway has authorised lands on the application already inside it. The
brick that does this is a generic credential-injecting proxy whose behaviour is fully described by
a config file that names no product and no protocol beyond what that one deployment needs.

## Guide-level explanation

The operator runs the proxy in front of the upstream and points the route at it instead of at the
upstream directly. The proxy is configured with four things: where the upstream is, how to tell a
request already carries its own credential, how to obtain a credential, and how to attach it.

```yaml
# preauth-proxy config, mounted as a file. Secrets come from the environment.
listen: "[::]:8080"
upstream: "http://app:3000"

# A request already carrying this marker is forwarded untouched — the proxy
# never overrides a credential the caller brought.
passthrough:
  header: Cookie
  contains: "session="

# The exchange that mints a credential. Nothing here is interpreted by the
# binary beyond string substitution of ${ENV} values.
credential:
  origin: "http://app-auth:8000"
  request:
    method: POST
    path: "/login"
    headers:
      Content-Type: "application/x-www-form-urlencoded"
      X-Forwarded-Proto: "https"
    body: "email=${CRED_USER}&password=${CRED_SECRET}"
  accept_status: [200, 302, 303]
  extract:
    from_header: "Set-Cookie"
    take: cookie-pair          # first `name=value`, attributes dropped

# How the minted credential rides on forwarded requests.
inject:
  header: Cookie
  mode: append                 # add to any Cookie the caller sent

# What the upstream returns when the credential is stale: re-acquire and replay,
# at most once, before surfacing the failure.
renew:
  on_status: [401]
  max_replays: 1
```

`${CRED_USER}` and `${CRED_SECRET}` are read from the environment, so the credential material comes
from a Secret and never touches the config file or the logs.

When it works, the operator sees nothing — that is the point. A request arrives without the marker,
the proxy attaches the credential it is holding, the upstream serves the page. On first use, and
whenever the held credential is rejected, one line is logged:

```text
INFO  preauth-proxy: acquired credential from origin, 82 bytes, marker=Cookie
INFO  preauth-proxy: upstream returned 401, re-acquiring and replaying once
```

When acquisition fails at startup the process exits non-zero and the rollout stops, rather than
serving an hour of 502s:

```text
ERROR preauth-proxy: startup acquisition failed: origin returned 403
```

A request that already carries the marker is passed straight through, so a caller with its own
session keeps it — the automated jobs that log in for themselves are never re-attributed to the
proxy's identity.

## Design

### Contract

**Invocation**

```text
preauth-proxy --config <PATH>
```

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--config <PATH>` | `PREAUTH_CONFIG` | `/etc/preauth-proxy/config.yaml` | Path to the config file. |
| `--check` | — | off | Parse and validate the config, print the effective form, exit. Touches no network. Substituted values are **not** printed — see below. |

The config file is the whole contract; the flags only locate and verify it. Secrets are supplied
as environment variables and referenced from the config as `${NAME}`; a referenced variable that is
unset is a validation error, not an empty string.

`--check` reports **how many** references resolved, never what they resolved to. Printing the
effective body would print the service password, and a `--check` pasted into a ticket is exactly
how that would escape. The check that matters is that every reference resolves, not that a human
reads the values.

**Config schema**

| Key | Required | Meaning |
| --- | --- | --- |
| `listen` | yes | Address the proxy binds. |
| `upstream` | yes | Origin every non-acquisition request is forwarded to. |
| `passthrough.header` / `.contains` | yes | If this request header contains this substring, forward untouched — do not inject. |
| `credential.origin` | yes | Origin the acquisition request is sent to. |
| `credential.request` | yes | `method`, `path`, `headers`, `body` of the acquisition exchange. `${ENV}` substituted in `headers` values and `body`. |
| `credential.accept_status` | yes | Response statuses that count as a successful acquisition. |
| `credential.extract.from_header` | yes | Response header the credential is read from. |
| `credential.extract.take` | yes | Extraction rule: `cookie-pair`, `whole`, or `after:<prefix>`. |
| `inject.header` | yes | Request header the credential is written to before forwarding. |
| `inject.mode` | yes | `append` (add to existing) or `set` (replace). |
| `renew.on_status` | no | Upstream statuses that mean "credential stale"; triggers one re-acquire+replay. Empty disables renewal. |
| `renew.max_replays` | no (default `1`) | Replays per request after a renewal. |

The vocabulary is deliberately generic. `credential` is any opaque token; `marker` is any header
substring; the *exchange* is any single HTTP request/response. Nothing in the schema names a
cookie type, a session, an auth protocol or an application — those are values an operator writes,
and they are the only place the deployment's actual purpose is legible.

**Request handling**

1. Read the request. If `passthrough.header` contains `passthrough.contains`, forward it to
   `upstream` unmodified and relay the response. Done.
2. Otherwise ensure a credential is held (acquire on demand if not — see *Acquisition*), write it
   to `inject.header` per `inject.mode`, and forward.
3. If the upstream response status is in `renew.on_status` and replays remain, discard the held
   credential, acquire a fresh one, and replay the *same* request once. A second failure is
   surfaced as-is.
4. Relay the response. Bodies are streamed, not buffered: a declared `Content-Length` is passed
   through and the body copied in bounded chunks, so a multi-megabyte upstream response never sits
   whole in memory. Hop-by-hop headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`, …) are
   dropped in both directions per RFC 7230 §6.1.

**Acquisition**

Send `credential.request` to `credential.origin`. On a status in `accept_status`, read
`extract.from_header` and apply `extract.take`; the result is the held credential. Redirects are
**not** followed — the acquisition response itself carries the credential, and a 3xx `Location` on
a login exchange typically points at a public host this process has no business calling. Any other
status, a missing extraction header, or an empty extraction is an acquisition failure.

Acquisition is **single-flight**: concurrent requests that all find the cache empty do not each log
in. The first takes an exclusive lock, acquires, and populates the cache; the rest wait on the lock
and reuse the result. Without this, N simultaneous first-requests — or N simultaneous `401`s after
an expiry — produce N logins against the origin, which is both wasteful and a good way to trip a
rate limiter. This is the same check-then-act-under-a-lock discipline RFC 0001 uses for its file
append, applied to a cache instead of a file.

**Startup**

The proxy acquires once before it begins listening. A failure there exits non-zero, so a bad
credential or an unreachable origin stops the rollout instead of surfacing as request-time 502s
later. `--check` validates the config without this step.

**Exit codes**

| Code | Meaning |
| --- | --- |
| `0` | Clean shutdown, or `--check` on a valid config. |
| `1` | Internal error (bind failure, unreadable config path). |
| `2` | Config error: malformed file, unknown key, or an unset `${ENV}` reference. |
| `3` | Startup acquisition failed. |

**Stability.** The config schema, the extraction/injection rules, the `${ENV}` substitution, and
the exit codes are the contract; changing any of them needs a new RFC. The log line *formats* are
not contract.

### Architecture

**Yes, hexagonal**, and this is the counter-example to RFC 0001. Measured against the three criteria
in [`../architecture/hexagonal.md`](../architecture/hexagonal.md):

1. **A genuine decision with configurable rules and multiple outcomes.** Per request the domain
   chooses between *pass through*, *inject the held credential*, *acquire then inject*, and *renew
   then replay*, driven by the passthrough rule, the cache state, and the renewal config. That is
   policy, not a transformation.
2. **External systems.** Two of them, on opposite sides: the credential origin and the upstream.
3. **Testing the decision without them is desirable** — the whole value of the brick is that the
   lifecycle logic (when to inject, when to renew, single-flight under concurrency) is correct, and
   that is exactly what must be tested against fakes rather than a live login form.

Honesty test: a fake `CredentialSource` returns a canned token in one line; the real one performs
an HTTP exchange and runs the extraction rules. The fake is far smaller than the real. The port
earns its place.

**Ports** (traits the domain owns, named for what the application needs):

- `CredentialSource` — *obtain a credential*. Outbound. Real adapter: the HTTP acquisition
  exchange plus extraction. Fake: returns a fixed value, or a queued sequence to exercise renewal.
- `Upstream` — *forward a request and return its response*. Outbound. Real adapter: an HTTP client
  streaming to `upstream`. Fake: records the injected header and returns a scripted status, which
  is how the renewal-on-401 path is tested without a socket.

**Adapters:**

- **Inbound:** the HTTP listener that turns each connection into a domain call. It owns no policy —
  it extracts the request facts (does the marker header match, the method, path, headers, body
  handle) and hands them in.
- **Outbound:** the two above, plus config loading and `${ENV}` resolution.

```text
bins/preauth-proxy/src/
├── domain/
│   ├── policy.rs      # decide(...) -> Action, and the replay budget     <- the tests live here
│   ├── credential.rs  # the cache + single-flight state machine
│   ├── config.rs      # the validated model and ${ENV} (pure; parsing is an adapter concern)
│   ├── exchange.rs    # the use case: one request through the policy, the cache and the ports
│   └── port.rs        # CredentialSource, Upstream, and the Credential newtype
├── adapters/
│   ├── inbound_http.rs   # listener -> RequestFacts -> exchange
│   ├── http_client.rs    # both outbound ports, over one hyper client
│   └── config_file.rs    # YAML -> the validated model
└── main.rs            # wire config -> adapters -> domain, bind, serve
```

Three departures from the first sketch of that tree, each because writing it said so:

- **`exchange.rs` exists.** The renew-and-replay loop is orchestration over two ports — an
  application concern with nowhere to live in a `domain`/`adapters` pair. Putting it beside the
  policy keeps `policy.rs` a pure decision table and gives the loop somewhere to be tested with
  fakes, which is what the `Upstream` port was for.
- **`port.rs` exists**, matching the `domain/port/` in
  [`hexagonal.md`](../architecture/hexagonal.md) rather than scattering the traits.
- **One `http_client.rs` instead of `source_http.rs` and `upstream_http.rs`.** They are the same
  `hyper` client with two configs; splitting them bought two files and no seam. The *ports* stay
  two, which is where the seam actually is.

The domain depends on nothing in the crate but itself: no HTTP client type, no framework, no
`async` beyond what the ports' signatures require. `policy.rs` is a pure function over facts and
cache state, so every branch — including "marker present ⇒ never inject" and "401 with replays
exhausted ⇒ surface it" — is table-testable.

### Data and state

**In-memory only, and reactive.** The single held credential lives behind a lock; the only other
state is the boolean "is acquisition in flight" that the single-flight rule needs. Nothing is
persisted. On restart the cache is empty and the startup acquisition refills it; a caller mid-flight
during a restart is handled by whichever replica takes the connection.

There is deliberately no TTL clock and no proactive refresh. The upstream is the authority on
whether a credential is still good, and it says so with a status code; the renewal path reacts to
that. Storing an expiry the proxy guessed at would be a second source of truth that could disagree
with the upstream — the same "two things that can desynchronise" trap RFC 0001 avoids by re-reading
the file it is about to write. The credential the upstream just rejected is the credential we
discard; nothing else can be stale.

Because each replica holds its own credential, replicas are independent and need no shared store.
Scaling is horizontal and stateless.

## Security considerations

**Privileges.** None beyond an unprivileged network listener. No RBAC, no Linux capabilities, no
root; runs as a non-root UID with a read-only root filesystem and all capabilities dropped. It
reads a config file and two environment variables and speaks HTTP to two in-cluster origins.

**Trust boundary — the load-bearing one.** The proxy trusts that *something in front of it has
already authenticated and authorised the caller.* It performs no authentication of its own; on the
contrary, it hands every request that reaches it a valid, full-privilege upstream credential. That
is safe **only** while the forward-auth gateway sits ahead of it on the route. If the proxy's
service is reachable without that middleware — a second IngressRoute, a port-forward, a pod in the
same namespace calling the Service directly — then the caller is inside the upstream with the
service identity, no questions asked. **The gateway middleware is not defence in depth; it is the
entire authentication story.** Any deployment of this brick must state, in its own manifests, that
removing the gateway from the route publishes an unauthenticated upstream.

**Shared identity, by design.** The injected credential belongs to one service account, so every
caller behind the proxy acts as that single identity in the upstream. The upstream can therefore
make no per-user distinction — all authorisation must live at the gateway, which is where the real
identity is known. For an upstream whose objects are team-scoped rather than user-scoped this loses
nothing; for one with meaningful per-user permissions it would erase them, and this brick is the
wrong tool.

**Secrets.** It holds the service credential (`${CRED_*}` from a Secret) and the token it mints from
it. Neither is ever logged: acquisition logs the credential's *length* and the marker name, never
its bytes, and the injected header is not echoed. The config file carries no secret — only `${ENV}`
references — so it is safe to keep in a ConfigMap and in git.

**Bypass, and which direction is safe.** Reaching the *upstream* directly, around the proxy, is
harmless: the caller simply meets the upstream's own login and gets no injected session — the
system fails closed to the upstream's native auth. Reaching the *proxy* while skipping the
*gateway* is the dangerous direction, covered above. A caller can also set the passthrough marker
header themselves to suppress injection; that too is safe, because it only means they present no
credential and the upstream challenges them. There is no marker value that causes the proxy to
inject *more* than one credential or a *different* one — it injects exactly the held token or
nothing.

**Blast radius.** A compromise of this process yields the service credential and the ability to mint
upstream sessions for that one upstream. It cannot see the cluster, holds no Kubernetes token, and
fronts a single origin. Rotating the service credential and restarting fully revokes it.

**Acquisition input.** The acquisition request is entirely operator-authored config; no
attacker-controlled request data is interpolated into it. The extraction rules read a named response
header from the origin, which is a trusted in-cluster service. The one thing to guard is that
`extract.take: whole` could copy an unexpectedly large origin header into memory — bounded by a
configured maximum, rejecting an origin response whose extraction header exceeds it.

## Operational considerations

**Failure mode: fail-closed at the edges, fail-fast at startup.** At startup, an acquisition failure
exits non-zero (code `3`) and the rollout halts — a wrong credential should stop the deploy, not
degrade silently. At request time, an acquisition failure returns `502`: the caller gets no injected
session, which for a gated route means the upstream's own challenge, never open access. This is the
deliberate asymmetry — the only failure that opens anything would be losing the gateway, and that is
a routing decision outside this process.

**Rollout.** New Deployment + Service, then repoint the route from the upstream Service to the proxy
Service in one change. Until that change, nothing is affected. The switch is the cutover and its
inverse is the rollback.

**Rollback.** Point the route back at the upstream Service. The upstream's own login returns
immediately; there is no persisted state to unwind and the proxy can be deleted at leisure.

**Observability.** One structured line per acquisition and per renewal, on stderr. A minimal metrics
surface is *Future work*, not required for a first ship: the acquisition/renewal log lines and the
upstream's own request logs already tell an operator whether injection is happening.

**Upgrade.** Rolling. Each replica holds its own credential and acquires independently, so old and
new run side by side with no shared state to coordinate. A replica draining mid-request finishes it;
a new one acquires on startup before it serves.

**Latency.** Steady-state cost is one added in-cluster hop and a header write — negligible. The only
slow path is an acquisition, which happens on first request and on renewal, and single-flight keeps
it to one login per expiry no matter how many requests are waiting.

## Alternatives considered

**The upstream's own unauthenticated mode.** Many session-auth applications ship a "no auth, single
implicit user" switch for local use. Using it, with the gateway as the sole guard, is the obvious
zero-code option. Rejected as a general answer: that mode typically
rebinds every object to a synthetic built-in tenant rather than the real one, which orphans whatever
was already provisioned; it commonly disables the upstream's own API-key/enforcement checks as a
side effect; and it tends to break first-run provisioning that assumes real accounts. It trades a
missing login for a pile of downstream breakage, and it is upstream-specific — there is no such
switch to rely on in the general shape this brick targets.

**`oauth2-proxy` (or `vouch`, `traefik-forward-auth`).** The established forward-auth proxies.
Rejected because they solve the *other half*: they authenticate the *client* (via OIDC) and can pass
identity to the upstream as a header or Basic-Auth. None of them can drive an upstream's own
login *form* and carry the resulting *session cookie* — which is the whole problem when the upstream
has no header/OIDC hook and only a form. They complement the gateway; they do not replace this.

**A gateway plugin doing the login exchange** (a Traefik Yaegi middleware, an Nginx `auth_request`
subrequest). Keeps it inside the gateway with no extra Deployment. Rejected: the exchange has state
(a cached, renewable credential with single-flight) that a per-request subrequest models poorly; the
plugin is interpreted and bound to one gateway; and the interesting logic becomes untestable outside
that gateway. A standalone brick with a hexagonal core is the opposite trade and the one this repo
favours.

**Patch the upstream to trust a gateway-supplied identity header.** If the upstream accepted, say, a
signed `X-Forwarded-Email`, the gateway could authenticate and the upstream would need no session at
all. Rejected where the upstream is third-party OSS with no such hook: it means a fork to maintain
against every release. Where an upstream *does* offer a trusted-header mode, that is strictly better
than this brick and should be used instead — see *Future work* for the pass-through direction.

**Do nothing — two logins.** The status quo. Correct and secure, and rejected only because the
second login defeats the point of putting single sign-on in front of the service at all.

## Drawbacks and risks

- **A shared upstream identity.** No per-user attribution survives inside the upstream; the audit
  trail there names the service account for everyone. Acceptable only because the real identity is
  known and enforced at the gateway.
- **A new hop in the request path** — one more Deployment to run, one more thing that can be down,
  a little latency. Fail-closed behaviour bounds the *security* cost of it failing, not the
  *availability* cost.
- **A long-lived privileged credential held in memory.** Minting sessions is its whole job, so the
  service account is necessarily powerful in the upstream. Rotation is the mitigation and it is
  cheap (restart), but the credential's blast radius is the upstream in full.
- **Coupling to the upstream's login contract, via config.** If the upstream renames its login path
  or its cookie, the config breaks — loudly (acquisition fails at startup), but it breaks. This is
  config, not code, so the fix is a values edit, and the coupling is at least explicit and in one
  place instead of scattered through a codebase.
- **Request bodies are buffered, up to 4 MiB, and rejected with `413` above it.** A replay cannot
  re-read a stream, so replayability and streaming request bodies are mutually exclusive; the RFC
  asks for streaming *responses*, and those are streamed. The cost is that this brick cannot front
  an upstream that takes large uploads without the cap being raised, and the cap is a constant
  rather than a config key because adding one would be a contract change.
- **`http://` only.** An `https://` upstream or origin is refused at startup. Both are in-cluster
  services on the pod network today; a TLS stack and a trust decision are a separate design.
- **The generality cuts both ways.** Because the binary names nothing, a reader must consult the
  config to know what a given instance *does* — which is the stated goal, and also means the config
  is the only place the real behaviour is legible. The security section above is written on the
  assumption that reviewers read the deployed config, not just the brick.

## Unresolved questions

- **Proactive expiry vs reactive-only renewal.** *Non-blocking.* The design renews only on an
  upstream rejection status. An optional TTL that refreshes ahead of expiry would shave the
  occasional renewal round-trip off a user request, at the cost of the second-source-of-truth risk
  argued in *Data and state*. Deferred unless a real upstream is found whose stale-credential
  response is something other than a clean, cheap status code.
- **Extraction expressiveness.** *Non-blocking.* `cookie-pair` / `whole` / `after:<prefix>` covers
  the known cases. A regex or JSON-path extractor is tempting and deliberately omitted for now —
  each is a new, attacker-adjacent parser on a response, and none is needed yet.
- **One upstream per instance.** *Resolved:* one. Fronting several upstreams from a single process
  multiplies the credential-cache and config surface for no gain when a second Deployment with a
  second config is free. Scale by instances, not by config arrays.
- **Marker matching is a substring test.** *Non-blocking.* `contains` is coarse; a caller could in
  principle carry the substring in an unrelated header value and suppress injection. Since
  suppressing injection only costs that caller its own session (fail-closed), a stricter cookie-name
  parse is a refinement, not a correctness fix.

## Future work

- **Metrics** — acquisitions, renewals, failures, in-flight waits — behind a `/metrics` listener,
  once there is a scraper that wants them.
- **Identity pass-through.** If an upstream gains a trusted-header auth mode, a `forward_identity`
  config that relays a gateway-supplied header (e.g. `X-Forwarded-Email`) *instead of* injecting a
  shared credential would restore per-user identity. That is the strictly-better world the fourth
  alternative describes, reachable without changing the brick's shape.
- **First real deployment.** Write the config for one upstream and confirm the schema in
  *Contract* covers it without a code change. This is the check that the vocabulary is actually
  generic and not just generically named — the binary is built and tested against fakes, so
  nothing yet proves the generality claim this RFC is built on. It left the implementation plan
  because it is a deployment, not a code task, but it is the item that would most change this
  design if it went badly.
- **TLS to the upstream and the origin**, for the case where either stops being a plain-HTTP
  in-cluster service. Needs a trust store decision, which is why it is not here.
- **A configurable request-body cap**, or a streaming path for requests that opts out of
  replayability. Both are contract changes; neither is needed until an upstream takes uploads.
- **Response rewriting.** Some upstreams emit absolute redirect `Location`s at their own origin;
  an optional rewrite of the response `Location` header would smooth those. Omitted until one bites.
- **Operator-side injection.** A later brick could add the proxy and reroute to a workload that
  never opted in, the way the operator injects other bricks. Its own RFC.
- **Multi-arch builds** (`arm64`) once anything in the fleet needs them.

## Implementation plan

- [x] `bins/preauth-proxy` scaffold: workspace member, inherited lints, musl target
- [x] `domain/config.rs` — the validated config model and `${ENV}` resolution, with tests for every
      rejection (unknown key, unset env reference, missing required key)
- [x] `domain/policy.rs` — `decide(RequestFacts, CacheState) -> Action`, table-tested across
      passthrough / inject / acquire / renew, including "marker present ⇒ never inject" and
      "replays exhausted ⇒ surface the status"
- [x] `domain/credential.rs` — the cache + single-flight state machine, tested under concurrent
      access (N callers, one acquisition — the test that fails without the lock)
- [x] `adapters/http_client.rs` — the acquisition exchange and the `cookie-pair` / `whole` /
      `after:` extractors, with a bounded max extraction size. Merged with the upstream adapter
      below: both are the same `hyper` client, and splitting them bought two files and no seam
- [x] Streaming forward, `Host` rewrite, hop-by-hop stripping, renewal replay — the replay loop
      lives in `domain/exchange.rs`, the use case the RFC's tree did not name
- [x] `adapters/inbound_http.rs` + `main.rs` — listener, wiring, startup acquisition, exit codes,
      graceful shutdown on `SIGTERM`/`SIGINT`
- [x] Integration test against a fake upstream + fake origin on real sockets: first-request
      acquisition, passthrough of a caller-supplied marker, `append` joining rather than replacing,
      renewal on a scripted 401, fail-closed 502 on an unreachable upstream, startup exits `3` on
      a refusing origin and on one that mints nothing
- [x] Golden test: a fixture config renders the acquisition request byte for byte — method, path,
      header set and `${ENV}`-substituted body — so a change to the substitution or the request
      builder shows up as a diff in review rather than as a failed login at deploy time
- [x] Containerfile with multi-stage musl build; `scratch` final stage, non-root UID 65532
- [x] `task audit` covers the crate
- [x] Docs: [`docs/bricks/preauth-proxy.md`](../bricks/preauth-proxy.md), opening on the
      gateway-is-the-authentication note
- [x] RFC flipped to `Implemented`

## References

- [authentik — Traefik forward auth](https://docs.goauthentik.io/add-secure-apps/providers/proxy/server_traefik/)
  — the gateway shape this brick sits behind, and the source of the "gates but cannot log in"
  constraint in *Motivation*.
- RFC 7230 §6.1 — hop-by-hop headers, the ones stripped in both directions.
- [`../architecture/hexagonal.md`](../architecture/hexagonal.md) — the criteria this RFC is measured
  against when it accepts the layout, as the counterpart to RFC 0001's rejection of it.
- [RFC 0001 — passwd-append](./0001-passwd-append.md) — the single-flight-under-a-lock discipline
  and the "no second source of truth" rule are borrowed from it.

## Changelog

| Date | Change |
| --- | --- |
| 2026-08-23 | Amended after re-reading the code against the contract: the renewal log line this RFC shows under *Guide-level explanation* — and promises under *Observability* as "one structured line per acquisition and per renewal" — **was never emitted**. With no metrics in this RFC, that line is the only signal an operator has that renewal works at all, so its absence was a hole in the one observability story the design has. `relay` now returns what it did (`renewals`, `renewed_on`) and the inbound adapter logs it, which keeps the domain free of I/O rather than reaching for `eprintln!` inside it. |
| 2026-08-23 | **Accepted and implemented in one step**, skipping `Proposed`: the RFC was written, built and merged together, so merging the implementation was the decision. Recorded because the process asks for the intermediate statuses and this did not have them — a reviewer reading the history should know the design was never reviewed separately from the code. |
| 2026-08-23 | Implementation found two rules the design did not state, both now in the code and in *Request handling*. **`invalidate()` is a compare-and-clear, not a clear**: two requests holding the same stale credential would otherwise have the second discard the fresh one the first had just acquired, and the pair would renew forever. **A passed-through request is never renewed on its caller's behalf**: doing so would swap their identity for the service account's, which is exactly what *pass through* promised not to do. Neither is a contract change; both are properties the RFC should have named. |
| 2026-08-23 | Two limits the design implied but did not admit, now in *Drawbacks* with a way out in *Future work*. **Request bodies are buffered to 4 MiB and rejected above it** — a replay cannot re-read a stream, so replayability and streaming *requests* are mutually exclusive; the RFC asks for streaming *responses*, and those stream. **`http://` only**, refused at startup rather than silently downgraded. |
| 2026-08-23 | *Architecture* amended to the tree that was actually built: `exchange.rs` for the renew-and-replay loop, which is orchestration with nowhere to live in a `domain`/`adapters` pair; `port.rs` matching `hexagonal.md`; and one `http_client.rs` instead of two outbound adapters, because they are the same client with two configs. The **ports** stay two, which is where the seam is. Also: `--check` prints how many `${ENV}` references resolved and never their values, because printing the effective body would print the service password. |
