# `endpoint-gateway`

One OIDC relying party and one authorisation decision in front of every workspace endpoint
exposed on its own FQDN. A request reaches the application only if the caller proved a cluster
identity — a browser session, a token this cluster's identity provider minted, or the workspace
pod it is calling from — **and** is the workspace's owner or someone the owner named.

Design and rationale: [RFC 0009](../rfc/0009-endpoint-auth.md). This page is the operator's copy.

> **The gate fails closed.** With the gateway unavailable, every workspace endpoint stops
> serving. That is deliberate — the feature's whole value is that the FQDN path is closed, and a
> control that opens under load is one an attacker can arrange to have open — and the bill is
> itemised in the chart's defaults: three replicas, anti-affinity, a PDB, `maxUnavailable: 0`,
> `system-cluster-critical`, and a break-glass annotation that reopens *one* endpoint rather than
> all of them.

## What runs where

| Piece | Where | Does |
| --- | --- | --- |
| `endpoint-gateway` | its own Deployment, 3 replicas | answers `/auth` per request, and runs the sign-in flow |
| mutating webhook | `weebo-si-operator webhook` | attaches the gate to every routing object in a Che workspace namespace |
| validating webhook | `weebo-si-operator webhook` | host ownership, and the nine-row guard table that pins the gate |
| reconcile sweep | `weebo-si-operator controller` | covers objects that existed before the feature, and owns the shared Traefik `Middleware` |

## Usage

```text
endpoint-gateway [--config <PATH>] [--check [--explain-token]]
```

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--config <PATH>` | `ENDPOINT_GATEWAY_CONFIG` | `/etc/endpoint-gateway/config.yaml` | Config file. |
| `--check` | — | off | Validate the config, fetch the issuer's discovery document, print what it found, exit. |
| `--explain-token` | — | off | With `--check`: read a token on stdin, print which check accepts or refuses it, exit. |
| `-h`, `--help` | — | — | Usage. |

Two secrets arrive as environment variables, never as config values:

| Variable | Contents |
| --- | --- |
| `ENDPOINT_GATEWAY_SESSION_KEYS` | 32 random bytes, base64, newest first, comma-separated — `openssl rand -base64 32`. Standard or url-safe, padded or not. |
| `ENDPOINT_GATEWAY_CLIENT_SECRET` | The OIDC client secret (the name is `client_secret_env`). |

Rotating a session key is "prepend the new one, drop the old one an `sso_ttl` later". Sealing
always uses the first; opening tries each in turn, so a rotation costs nobody a login.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean shutdown, or `--check` on a valid configuration. |
| `2` | The configuration is unusable — refused before serving one request. |
| `3` | The cluster or the identity provider refused something this process cannot start without. |

Refusing to start is the right failure for a bad configuration: a gateway that starts with a
suffix it cannot govern, or a `claims.username` that is not the claim Che derives usernames from,
would deny every request in the cluster while looking healthy.

## HTTP surface

| Path | Method | Public | Meaning |
| --- | --- | --- | --- |
| `/auth` | any | no | The forward-auth decision. `200` allow, `302`/`401` sign-in needed, `403` denied. Called by the ingress controller through the `Service`. |
| `/oidc/start` | GET | yes | Begins the authorization-code + PKCE exchange. `rd`, when present, must be an `https://` URL on a governed endpoint host, like `/host-session`'s — no `#` fragment, and no explicit port other than `:443`. |
| `/oidc/callback` | GET | yes | The only registered redirect URI. Mints the SSO cookie and clears the sign-in state cookie — on every answer, the IdP's `error=access_denied` included. |
| `/host-session` | GET | yes | Exchanges the SSO cookie for a one-time grant on one endpoint host. |
| `/sign_out` | POST | yes | Clears the SSO cookie and any sign-in in flight. `GET` renders the form that posts to it. Same-origin only: `Sec-Fetch-Site: same-origin`/`none`, or (without it) an `Origin` equal to the gateway's own; anything else is `403`. Host cookies already minted live out their `host_ttl_secs` — see below. |
| `/oidc/backchannel-logout` | POST | while `backchannel_logout.enabled` | The IdP's back-channel logout. Revokes a session cluster-wide. On its own rate limit (`rate_limit.backchannel_logout_per_minute`), answered `503` when over it; `503` too when the revocation set is full. Disabled: `404`, and not routed. |
| `/selftest` | GET | while the probe runs | What the gate observed for this request. `404` without a probe token — derived from the shared session keys (HMAC-SHA256, label `weebo selftest`), so any replica answers any replica's probe; compared in constant time. |
| `/healthz`, `/readyz` | GET | no | Liveness, and readiness: informer caches synced, signing keys loaded, not shutting down. |
| `/metrics` | GET | no | Prometheus, on `metrics_listen` (chart: port `9090`) when set, otherwise on the main port. |

**These paths belong to the gateway's own hosts, never to an endpoint's.** The gateway's own host
(`redirect_url`'s) is never governed — it is excluded whether or not `hosts.exclude` names it.
On a forward-auth dialect an endpoint's traffic never reaches these routes at all; on a
`ReverseProxy` deployment, where the gateway carries that traffic, a request whose host the
gateway governs is the application's **whatever its path**, so an application's own `/healthz`,
`/metrics` or `/auth` reaches the application. The table above is served only on hosts the
gateway does not govern: its public host, the pod address the kubelet probes, and the `Service`
name a router calls `/auth` on.

**What the gateway does reserve on an endpoint host** is three names, all prefixed so an
application is unlikely to use them by accident, and none of them a path:

| Name | Kind | What the gate does with it |
| --- | --- | --- |
| `__weebo_grant` | query parameter | Redeems it for a host cookie and redirects without it — **only** when its value is shaped like a grant the gateway sealed (`v1.`, a 12-byte nonce, a ciphertext). Any other value is the application's: the request is decided normally and reaches it unchanged. |
| `__Host-weebo-endpoint` | cookie | The host session. Set by the gate; an application cookie of the same name would be overwritten. |
| `X-Auth-Request-User`, `-Groups`, `-Email` | request headers | Set from the decision and replaced if the caller sent them — the reason the application may trust them. |

"Public" is what the chart's `Ingress` routes on the gateway's own host — exact paths only,
nothing else. The optional `NetworkPolicy` (`networkPolicy.enabled`) narrows who may connect at
all to the ingress controller's namespace (main port) and the monitoring namespace (metrics port).

**Signing out does not revoke.** The only session id the gateway holds is the identity provider's
`sid`; recording it as revoked would refuse the very next sign-in, which silently re-uses the same
provider session and gets the same `sid` back. Host cookies are host-only cookies on other origins,
so `/sign_out` cannot clear them either: they end at their own expiry (at most `host_ttl_secs`,
and never later than the SSO session they were minted from). Ending a session everywhere at once is
back-channel logout's job.

**Shutdown.** On `SIGTERM` the gateway answers `/readyz` with `503`, waits five seconds for the
endpoint to be removed, stops accepting, and gives in-flight requests up to twenty seconds —
inside the chart's `terminationGracePeriodSeconds: 30`.

**An identity provider that is down at boot** costs sign-ins, not the replica: discovery is
retried in the background with backoff (2 s doubling to 5 min) and the JWKS refresh starts once it
succeeds. `/readyz` stays `503` until signing keys are loaded, and while none are, a failed JWKS
fetch is retried with backoff (1 s doubling to 1 min) rather than on the ten-minute schedule.

**Self-origin by pod address** (`self_origin.pod_network`). `On` trusts the client-address
header from the start. `Auto` starts **off** and is turned on only by a conclusive self-origin
probe — `/selftest` answered and the forged `203.0.113.255` did not come back. An inconclusive
probe is retried with backoff (5 s doubling to the interval); a trust not re-confirmed for three
intervals lapses. A forgery seen by any replica is recorded as the
`endpoint-auth.weebo.si/address-forgery-seen` annotation on the revocation `ConfigMap`, which turns
pod-address identity off on every replica until an admin removes it. `Auto` with the probe
disabled is effectively `Off`, and says so at startup.

**Service-account tokens** cost a `TokenReview` only inside limits: the token's unverified `iss`
must be this cluster's service-account issuer (read from the gateway's own mounted token; skipped
if unknown) and a claimed `exp` must be in the future; concurrent requests with one token share a
single call; at most 16 reviews are in flight, 300/min (burst 100) cluster-wide and 30/min
(burst 10) per client key. Over a limit the token is simply not an identity — nothing is asked
and nothing is cached. Counted in `weebo_si_endpoint_auth_token_reviews_throttled_total`.

**Rate-limit keys.** The login surface's limiter keys on the client-address header only when the
connection comes from a peer `trusted_proxy` admits; otherwise on the connection's own address.
At its capacity it examines at most 16 of the oldest buckets per new key rather than scanning all.

**The revocation `ConfigMap`** is written with a merge patch (it used to be a server-side apply
under one field manager, which dropped the previous revocation on every write), prunes expired
entries on every write, and refuses a new entry past 10 000 live ones — loudly: an `ERROR` line,
`503`, and `weebo_si_endpoint_auth_revocations_refused_total{reason="full"}`.

**Identity headers** (`X-Auth-Request-User`, `-Groups`) are written from the credential the
decision was made on — never re-derived — so a revoked session, a grant or a second credential in
the same request can never be what the application is told about.

`/auth` accepts **any** method and never reads the one it was called with: Traefik replays the
original method while nginx's `auth_request` always sends `GET`, so the method under decision is
`X-Forwarded-Method`. The four inputs arrive either as those headers or as query parameters —
never both, because "the header says one path and the query says another" is a path-confusion
bypass.

## How a caller is challenged

Read from the request, not from configuration:

| The request is | The answer |
| --- | --- |
| a top-level navigation | `302` to sign in |
| framed (the IDE's preview panel) | a `200` page with a link — an IdP will refuse to be framed |
| anything else: `fetch`, XHR, a WebSocket upgrade, `curl` | `401` + `WWW-Authenticate` |

The `401` rule is the one that saves the most time: a redirect answered to an XHR becomes an
opaque CORS failure the developer will attribute to their own code.

## Calling an endpoint without a browser

| You are | Present |
| --- | --- |
| a developer's own workspace pod | nothing — the pod's address resolves to its namespace's owner |
| the same, behind a SNAT | the workspace's own service-account token as `Authorization: Bearer` |
| `curl`, CI, a test suite | a token from this cluster's IdP **minted for an audience in `bearer.audiences`**, verified and then authorised like a cookie |
| a task or an extension inside the IDE | nothing, or the workspace SA token — Che forwards no user token into the workspace, so code there is the workspace, not the person |
| an application with its own token auth | ask for `bearer: Passthrough` on the paths where that is true |
| a probe or a third-party webhook | ask for an `open` path rule, scoped to that path and method |

## Configuration

Rendered by the `endpoint-gateway` chart. The catalogue, the grants, the overrides and the
host-ownership patterns are **not** here: the gateway watches `WeeboSiConfig` for those, so a
grant edit takes effect at informer lag rather than at a redeploy.

```yaml
listen: "[::]:4180"
metrics_listen: "[::]:9090" # empty: /metrics on `listen` instead
issuer: "https://sso.weebo.si/realms/weebo"
# PEM bundle trusted on top of the public roots, for every outbound HTTPS call. Empty: public
# roots only. Set by the chart from `extraCa.configMap` / `extraCa.secret`.
extra_ca_file: ""
client_id: "che-client"
client_secret_env: ENDPOINT_GATEWAY_CLIENT_SECRET
redirect_url: "https://auth.weebo.si/oidc/callback"
claims:
  username: preferred_username # must be the claim Che derives its username from
  groups: groups
hosts:
  suffix: ".weebo.si"
  exclude: ["che.weebo.si", "auth.weebo.si"]
session:
  sso_ttl_secs: 43200
  host_ttl_secs: 3600
  host_sliding: true # re-minted past half-life; a working day never expires mid-task
  grant_ttl_secs: 30
  max_groups: 64
bearer:
  verify_own_issuer: true
  audiences: ["endpoint-gateway"] # required: which audience makes a token ours
  authorized_parties: [] # accept on azp/client_id instead — warned, and raises Degraded
  # For opaque access tokens (every Che on OpenShift). `endpoint: ""` means the discovery
  # document's `introspection_endpoint`, and enabled with neither refuses to start.
  introspection: { enabled: false, endpoint: "", negative_ttl_secs: 30, per_address_per_minute: 60 }
  service_account_token: true
  foreign: Reject # Reject | Passthrough
self_origin:
  pod_network: Auto # Auto | On | Off
  client_ip_header: X-Real-Ip
  service_account_token: true
  # Who may state a caller's address: `any`, `off`, or `cidrs:` — real networks
  # ("10.128.0.0/14", "fd00::/8", a bare address, or a legacy whole-octet prefix like "10.128.").
  # Matched as networks, IPv4-mapped peers included; anything else refuses to load.
  trusted_proxy: any
probe: { enabled: true, interval_seconds: 900, url: "" }
revalidation: { mode: WhenNoBackchannel, interval_secs: 3600 }
cache:
  identity_max_entries: 20000 # opened sessions and verified bearers, keyed by hash
  identity_ttl_secs: 300
  token_review_max_entries: 5000
# reject_unnormalised_path is always enforced; `false` refuses to load.
rules: { max_per_endpoint: 16, reject_unnormalised_path: true, on_unknown_key: Default }
enforcement: Enforce # Observe | Enforce
reveal_owner: true
# The login surface, in front of the cryptography. `/auth` is exempt — the controller is its only
# caller. Generous because a missing client-address header makes every caller share one bucket.
rate_limit: { login_per_address_per_minute: 300, backchannel_logout_per_minute: 6000 }
# enabled: false → /oidc/backchannel-logout answers 404 and the chart does not route it.
backchannel_logout: { enabled: true, configmap: endpoint-auth-revocations, namespace: weebo-si-hardening }
```

**An identity provider behind a private CA** needs its root in `extra_ca_file`, or discovery
fails at startup with a certificate error. The bundle is **added** to the built-in public roots,
never substituted for them, and it covers every outbound call: discovery, JWKS, the token and
introspection endpoints, and the self-origin probe. A path that cannot be read or holds no
certificate stops the gateway with exit code 2. It never falls back to the public roots
silently, because that would fail every sign-in while reporting healthy. In the chart:

```yaml
extraCa:
  configMap: corporate-root-ca # or `secret:` — one of the two
  key: ca.crt
```

## Rollout

Four steps, and the third is the interesting one:

1. `mode: DryRun` — counts how many endpoints *would* be gated. It cannot tell you who would be
   denied: with no annotation written, no request ever reaches the gateway.
2. `mode: Enforce` with `gateway.enforcement: Observe` — annotations injected, every decision
   computed, logged and counted, every verdict answered `200`. This is the step that tells you
   which endpoint a probe has been hitting unauthenticated for a year, before the probe breaks.
3. `namespaceSelector` onto a pilot team, `enforcement: Enforce`.
4. Cluster-wide.

Before any of it: two changes on the existing Che OIDC client — one new redirect URI, and an
**audience mapper** adding `endpoint-gateway` to the tokens it mints, without which every token a
developer or a CI job fetches from that client is refused for the audience it names. Then
`endpoint-gateway --check` to confirm the discovery document, the claims and whether the IdP
supports back-channel logout, and `--check --explain-token` on a real token to confirm it is
accepted before anyone depends on it. A cluster whose realm client cannot be edited sets
`bearer.authorized_parties` instead and accepts what that costs — see RFC 0009, *Which tokens are
ours*, which also records what the IDE has instead of a token, which is the workspace's own
identity.

**Rollback** is `mode: Off`: the sweep strips the annotations it owns — never the developer's —
and nothing is persisted. Between the two, `gateway.enforcement: Observe` reopens every endpoint
within a request while keeping the telemetry.

## Break-glass

```console
$ kubectl annotate ingress alice-ws-api -n user-alice \
    hardening.weebo.io/endpoint-auth=bypass --overwrite
```

Only the operator's own identity and an identity in `breakGlassIdentities` may write that value.
It drops the gate for that one endpoint, survives the next DevWorkspace Operator pass, raises a
`Degraded` condition naming the endpoint, and counts in `weebo_si_endpoint_auth_bypassed` — it is
meant to be visible enough that nobody leaves it on.

## Observability

`weebo_si_endpoint_auth_decisions_total{verdict,reason}`,
`weebo_si_endpoint_auth_decision_seconds` (the in-process decision only — the hop is measured at
the controller), `weebo_si_endpoint_auth_identity_cache_total{kind,result}`,
`weebo_si_endpoint_auth_indexed_endpoints`, `weebo_si_endpoint_auth_host_conflicts`,
`weebo_si_endpoint_auth_cache_synced`, `weebo_si_endpoint_auth_logins_total{result}`,
`weebo_si_endpoint_auth_self_origin_total{result}`,
`weebo_si_endpoint_auth_bearer_total{shape,result}`,
`weebo_si_endpoint_auth_client_ip_trusted`, `weebo_si_endpoint_auth_revocations`,
`weebo_si_endpoint_auth_revocations_refused_total{reason}`,
`weebo_si_endpoint_auth_self_origin_probe_total{result}`,
`weebo_si_endpoint_auth_token_reviews_throttled_total`,
`weebo_si_endpoint_auth_insecure_hosts`, `weebo_si_endpoint_auth_bypassed`.

Every label's value set is closed, and **no label carries a namespace, a host or a workspace
id** — which host is in conflict is a `WARN`, not a series.

Alert on `cache_synced == 0`, on `host_conflicts > 0` (always an attack or a bug, never routine),
on `bypassed > 0` outliving the incident that justified it, and on a `deny` rate that jumps —
usually a claim-mapping regression rather than an attack. Alert on any
`revocations_refused_total` (each is a logout not in effect) and on
`self_origin_probe_total{result="forged"}`. `self_origin_total{result="unknown_address"}`
being the whole series is a diagnosis rather than an alert: the cluster SNATs, and workspaces
should use the service-account token path.

## Carrying traffic: the OpenShift shape — deferred

> **Do not enable this yet, and it is now [RFC 0010](../rfc/0010-endpoint-auth-openshift.md)'s.**
> The mode is implemented and **unvalidated**: no OpenShift router has ever served a request
> through it. Its tests are a tier the base suite skips — `task test:openshift` runs them — and
> the gateway logs a warning at startup when the mode is on. It is documented here so the shape is
> reviewable, not because it is ready; RFC 0010 is what carries it to supported.

`config.reverseProxy: true` — for a router with no external-auth hook, which today means
OpenShift. The gateway then serves the application's own traffic: it decides with the same
`decide()`, and on `allow` forwards to the backend the operator recorded in
`hardening.weebo.io/upstream`, streaming both ways and honouring `Upgrade` so an HMR socket still
reconnects.

Three things change with it, and none of them is a detail:

| | `ForwardAuth` (Traefik, Nginx, HAProxy) | `ReverseProxy` (OpenShift) |
| --- | --- | --- |
| On the data path | no | **yes** — WebSockets, uploads, streamed responses |
| A bug here can | answer wrongly | corrupt an application response |
| Capacity is | decisions per second | bandwidth, buffers, connection count |
| `trustedProxy` | `any` is right: only the controller calls `/auth` | must be the router's CIDRs — every caller reaches this process directly |

The gateway **refuses to start** on `reverseProxy: true` with `trustedProxy: any` and pod-network
identity on, because that combination lets any pod that can reach the `Service` claim any
namespace's identity with one header.

The controller reconciles two companion objects per workspace namespace on this dialect — a
selector-less `Service` and an `EndpointSlice` pointing at the gateway's ready pods — because a
`Route`'s `spec.to` is a local reference with no cross-namespace form. Both carry the operator's
ownership label, so `policy-guard`'s original three-row table refuses a developer's edit of them.

## Ground truth

RFC 0009 takes a set of facts about Eclipse Che, DevWorkspace Operator and three ingress
controllers from documentation. These are the same facts read back from a cluster, with the
command that established each one — `scripts/spike-0009.sh`, which `task spike:live` runs. Every
row here is reproducible: `task spike:up` builds the cluster the controller rows need, and the
script runs unchanged against a real Che installation for the rows a laptop cannot answer.

Established 2026-09-24 against Kubernetes v1.35.0 with ingress-nginx v1.15.1, Traefik v3.7.13,
community haproxy-ingress v0.16.2 and DevWorkspace Operator v0.43.0. The Che rows come from a
second rig — `task spike:che:up`, `scripts/kind-che.yaml` — running Eclipse Che against a Keycloak
realm this repo writes. That realm is *shaped* like Che's and is not yours: rows 7 and 8 say the
gateway's assumptions hold against a Keycloak, and the same two commands re-run them against the
real one.

| Row | Fact | Verdict | What the cluster said |
| --- | ---- | ------- | --------------------- |
| 1 | DWO's service-account identity | `settled` | `system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount` — the value `owner.devworkspaceOperatorIdentity` defaults to, exactly |
| 2 | the label Che puts on a user namespace | `settled` | `app.kubernetes.io/part-of: che.eclipse.org`, exactly as assumed, on a namespace Che provisioned itself — alongside `app.kubernetes.io/component: workspaces-namespace` |
| 2a | the value of `che.eclipse.org/username` | **`differs`** | it held **`Alice Example`** — the user's *display name* — where the token's `preferred_username` was `alice`. The owner check compares this annotation to whatever `claims.username` yields, so the RFC's own example config would have failed every owner check, and the startup check cannot catch it because `preferred_username` *is* advertised in `claims_supported` |
| 3 | one routing object per exposed endpoint | `settled` | two endpoints, two `Ingress` objects, one rule and one host each, labelled `controller.devfile.io/devworkspace_id` and annotated `controller.devfile.io/endpoint_name` |
| 3a | how a devfile spells an endpoint annotation | **`differs`** | the field is **`annotation`**, singular. `annotations` is refused by the apiserver outright — `strict decoding error: unknown field` — so a devfile written from RFC 0009's snippet does not start at all |
| 3b | endpoint annotations reaching the object | `settled` | `hardening.weebo.io/endpoint-auth` and `hardening.weebo.io/rules` arrive on the generated `Ingress` verbatim |
| 4 | OpenShift's `Route`, router `Service` and `spec.to` | `open` | `route.openshift.io/v1` is not served on the rig, and no OpenShift cluster has been available |
| 5 | community haproxy-ingress: the annotation names, and the refusal | `settled` | `haproxy-ingress.github.io/auth-url` and `auth-headers-succeed` are honoured; a `401` comes back with its body, its `Set-Cookie` and its `WWW-Authenticate` intact |
| 5a | the four inbound headers on haproxy | **`differs`** on a default install, `settled` with the prerequisite below | absent by default. The auth request is a fixed path plus a *copy of the caller's own headers*: no `X-Forwarded-Host`, `-Uri` or `-Method` unless the caller sent one. With the prerequisite the gate is handed the real host, the real path with its query, and the real method |
| 5b | a caller-stated host on haproxy | **`differs`** on a default install, `settled` with the prerequisite | `X-Forwarded-Host: forged.example.test` from the client reaches `/auth` verbatim; the prerequisite's `set-header` overwrites it with the host that actually routed the request |
| 5c | identity headers on haproxy | **`differs`** on a default install, `settled` with the prerequisite | a caller's own `X-Auth-Request-User` reaches the application whenever the auth response does not itself carry one — the lua overwrites only the headers the response returned. The prerequisite's `del-header` lines strip it before anything else runs |
| 5d | a `302` challenge on haproxy | `settled` | passed through with its `Location` and `Set-Cookie` |
| 6 | nginx variables in `auth-url` | `settled` | `$host`, `$request_uri`, `$request_method` and `$scheme` all interpolate, with `allow-snippet-annotations` off — the dialect's whole reason for carrying the request in the URL holds |
| 6a | a refusal reaching the caller on nginx | **`differs`** | the status and `WWW-Authenticate` survive; the **body and the `Set-Cookie` do not**. `auth_request` discards the subrequest's body and headers |
| 6b | a `302` challenge on nginx | **`differs`** | the caller gets **`500`**. `auth_request` accepts `2xx`, `401` and `403` and treats everything else as a server error |
| 6c | `auth-signin` and the challenge shape | **`differs`** | with the `auth-signin` the dialect writes, a `POST` from `curl` is answered `302` to the sign-in URL. The gateway's three-shape challenge selection collapses to one shape on this dialect |
| 6d | `Set-Cookie` on an allow (sliding re-mint) | `settled`, once the dialect was fixed | reaches the caller when the application answers `2xx`, and is **dropped when it does not** — so a developer working against an endpoint returning 404s was quietly signed out mid-task. `nginx.ingress.kubernetes.io/auth-always-set-cookie: "true"` restores it, proven both ways, and the dialect now writes it |
| 6e | identity headers on nginx | `settled` | a caller's own `X-Auth-Request-User` is stripped, as on Traefik |
| 7 | the Che OIDC client's discovery document | `settled` | `backchannel_logout=true`, `backchannel_logout_session=true`, an `introspection_endpoint`, and `refresh_token` in `grant_types_supported` — so *Revocation*'s primary mechanism is the primary one, and the fallback stays a fallback |
| 7a | `groups` in `claims_supported` | `noted` | absent from the discovery document, present in the token. `claims_supported` is advisory and incomplete on Keycloak; the gateway only checks `claims.username` against it, and warns rather than refusing |
| 8 | the shape of a token a developer can fetch | `settled` | a JWT: `aud=endpoint-gateway`, `azp=endpoint-gateway`, 300s lifetime, no `nonce`, no `at_hash`, and a `sid` — so `bearer.audiences` is satisfiable, `authorized_parties` is not needed, `introspection.enabled` can stay off, and the `sid` revocation check has something to check |
| 9 | Traefik returning a refusal verbatim | `settled` | `401` with its body, its `Set-Cookie` **and** its `WWW-Authenticate` intact — the row the conformance suite could not reach without an identity provider |

### What the differing rows mean

**Row 2a is the one to act on, and it is a lockout rather than a hole.** RFC 0009 says
`owner.namespaceAnnotation` "must match `claims.username` in the gateway's own config" and then
suggests `preferred_username`. On this Che, the annotation held the display name — so an admin
following the document verbatim would have every owner refused on their own endpoint, with the
gate working exactly as designed and the startup check silent. Before setting `claims.username`,
read an actual namespace:

```console
$ kubectl get ns -o json | jq -r '.items[] | select(.metadata.annotations["che.eclipse.org/username"])
    | "\(.metadata.name)\t\(.metadata.annotations["che.eclipse.org/username"])"'
alice-example-che-4f2a1b        Alice Example
```

and pick the claim whose value is that string. Which claim that is depends on the identity
provider and on whether its users have display names at all, which is exactly why this is a thing
to look at rather than a default to copy.

**The devfile spelling is a documentation bug with a hard failure.** Row 3a is the cheapest one to
fix and the most expensive to leave: a developer copying RFC 0009's snippet gets their workspace
refused by the apiserver, with an error that names the field and not the document that told them
to write it.

**The `Nginx` dialect does not satisfy the dialect contract's properties 3 and 4.** RFC 0009 knew
this was the risk and named the remedy — lift the cookie with `auth_request_set`, re-emit it with
`add_header` — which needs a snippet annotation the implementation deliberately does not use. So
today: the gate's explanatory body never reaches a developer (6a), its navigation challenge is a
`500` (6b), and `auth-signin` answers every caller with a redirect including the ones that asked
for JSON (6c).

**6d is fixed**: the dialect now writes `auth-always-set-cookie: "true"`, so a session in
continuous use keeps sliding even while the application is answering 404s. It was the one failure
of the four that cost a single annotation, and the one with the worst shape — not an error a
developer could see and work around, but being signed out partway through a working day by a rule
about somebody else's status codes.

**The `HaproxyIngress` dialect needs a prerequisite this operator cannot write.** On a default
install it fails properties 1 and 2 outright: the gate is handed no host and no path (5a), a caller
can state the host it is judged against (5b), and a caller can hand the application an identity the
gate never issued (5c). That is because the controller builds its auth request by copying the
caller's own headers onto a fixed path — a different contract from Traefik's.

All three close with six lines in the **controller's own ConfigMap**, and the spike proves it both
ways (`scripts/spike-0009-rig.sh prerequisite on|off`, then re-run row 5):

```text
http-request del-header X-Auth-Request-User
http-request del-header X-Auth-Request-Groups
http-request del-header X-Auth-Request-Email
http-request set-header X-Forwarded-Host %[req.hdr(host)]
http-request set-header X-Forwarded-Uri %[pathq]
http-request set-header X-Forwarded-Method %[method]
```

**An annotation cannot do this job, and that is the load-bearing fact.** A per-ingress
`config-backend` snippet is emitted *after* the `lua.auth-intercept` line in the generated
configuration — proven by reading the generated `haproxy.cfg` and by watching a forged host reach
the gate anyway — so it changes what the *application* is handed and never what the *gate* was
asked. The lines above therefore belong to whoever installed the controller, not to anything this
operator writes, owns or can pin with `policy-guard`.

Two further annotations the dialect does write itself, both established here: `auth-method: "*"`
(without it every request reaches the gate as a `GET`, and a rule naming a method decides the wrong
way) and `auth-headers-request` narrowed to an explicit list (with the default `*`, everything the
gate reads is something the caller can state).

**So `HaproxyIngress` is conditionally supportable, and the condition is unverifiable from here** —
which is why enabling it requires `gateway.haproxyPrerequisite: true` in the `WeeboSiConfig`, the
admin's assertion that the lines above are installed. While it is `false` the feature reports
`Degraded` naming the field, and the gate attaches anyway.
Without the prerequisite the gateway cannot tell a header the controller set from one the caller
sent — that is the same header, and there is nothing left to compare it against. The absence is
not fail-closed either: a caller supplying `X-Forwarded-Host` gets a decision made about the host
they chose. This is the `Custom` dialect's situation exactly, and deserves the same treatment —
enabling the dialect *is* the admin's assertion that the prerequisite is installed.

## What is not implemented yet

Honest list, kept here rather than in the RFC's prose:

- **OpenShift**, now tracked by [RFC 0010](../rfc/0010-endpoint-auth-openshift.md). Everything
  above about `reverseProxy` is code without a cluster behind it: the dialect, the `Route` sweep,
  the companion objects and the proxy shell are written and tested in isolation, and none of it
  has met a real router. The dialect this page describes working is
  `Traefik`; `Custom` is whatever the admin asserts it is; `Nginx` and `HaproxyIngress` are the
  next bullet.
- **`HaproxyIngress` requires the controller prerequisite** in *Ground truth* above, and nothing
  in this repo installs it or can detect its absence. What exists is the assertion —
  `gateway.haproxyPrerequisite`, `Degraded` while it is unset — which is a promise recorded, not a
  property verified.
- **`Nginx` loses two of the contract's properties** (rows 6a–6c): the gate's message body, and
  its navigation challenge — which `auth_request` answers `500` rather than reshaping, so
  `auth-signin` redirects every caller including `curl`. Both need the snippet annotation this
  dialect was designed to avoid. The fourth failure the spike found, the sliding re-mint's cookie,
  is fixed.
- **The Che half of the ground-truth spike** — the user-namespace label, the OIDC client's
  discovery document and the shape of a token that realm mints. `scripts/spike-0009.sh` runs those
  rows against the Che cluster unchanged; nobody has run it there yet.
- **Trusted-proxy `Auto`**: the peer check against the ingress controller's own `EndpointSlice`.
  `trustedProxy: {cidrs: [...]}` covers the same ground with a value an admin writes.
- **`--check` does not run the self-origin probe once**; the running gateway probes on its own
  interval instead.
