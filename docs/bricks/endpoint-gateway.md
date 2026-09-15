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
endpoint-gateway [--config <PATH>] [--check]
```

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--config <PATH>` | `ENDPOINT_GATEWAY_CONFIG` | `/etc/endpoint-gateway/config.yaml` | Config file. |
| `--check` | — | off | Validate the config, fetch the issuer's discovery document, print what it found, exit. |
| `-h`, `--help` | — | — | Usage. |

Two secrets arrive as environment variables, never as config values:

| Variable | Contents |
| --- | --- |
| `ENDPOINT_GATEWAY_SESSION_KEYS` | 32 random bytes, base64, newest first, comma-separated. |
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

| Path | Method | Meaning |
| --- | --- | --- |
| `/auth` | any | The forward-auth decision. `200` allow, `302`/`401` sign-in needed, `403` denied. |
| `/oidc/start` | GET | Begins the authorization-code + PKCE exchange. |
| `/oidc/callback` | GET | The only registered redirect URI. Mints the SSO cookie. |
| `/host-session` | GET | Exchanges the SSO cookie for a one-time grant on one endpoint host. |
| `/sign_out` | POST | Clears the SSO cookie. `GET` renders the form that posts to it. |
| `/oidc/backchannel-logout` | POST | The IdP's back-channel logout. Revokes a session cluster-wide. |
| `/selftest` | GET | What the gate observed for this request. Requires the process's own probe token. |
| `/healthz`, `/readyz`, `/metrics` | GET | Liveness, informer-cache readiness, Prometheus. |

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
| `curl`, CI, a test suite | a token from this cluster's IdP, verified and then authorised like a cookie |
| an application with its own token auth | ask for `bearer: Passthrough` on the paths where that is true |
| a probe or a third-party webhook | ask for an `open` path rule, scoped to that path and method |

## Configuration

Rendered by the `endpoint-gateway` chart. The catalogue, the grants, the overrides and the
host-ownership patterns are **not** here: the gateway watches `WeeboSiConfig` for those, so a
grant edit takes effect at informer lag rather than at a redeploy.

```yaml
listen: "[::]:4180"
issuer: "https://sso.weebo.si/realms/weebo"
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
  service_account_token: true
  foreign: Reject # Reject | Passthrough
self_origin:
  pod_network: Auto # Auto | On | Off
  client_ip_header: X-Real-Ip
  service_account_token: true
probe: { enabled: true, interval_seconds: 900, url: "" }
revalidation: { mode: WhenNoBackchannel, interval_secs: 3600 }
cache:
  identity_max_entries: 20000 # opened sessions and verified bearers, keyed by hash
  identity_ttl_secs: 300
  token_review_max_entries: 5000
rules: { max_per_endpoint: 16, reject_unnormalised_path: true, on_unknown_key: Default }
enforcement: Enforce # Observe | Enforce
reveal_owner: true
backchannel_logout: { enabled: true, configmap: endpoint-auth-revocations, namespace: weebo-si-hardening }
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

Before any of it: one new redirect URI on the existing Che OIDC client, and
`endpoint-gateway --check` to confirm the discovery document, the claims and whether the IdP
supports back-channel logout.

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
`weebo_si_endpoint_auth_client_ip_trusted`, `weebo_si_endpoint_auth_revocations`,
`weebo_si_endpoint_auth_insecure_hosts`, `weebo_si_endpoint_auth_bypassed`.

Every label's value set is closed, and **no label carries a namespace, a host or a workspace
id** — which host is in conflict is a `WARN`, not a series.

Alert on `cache_synced == 0`, on `host_conflicts > 0` (always an attack or a bug, never routine),
on `bypassed > 0` outliving the incident that justified it, and on a `deny` rate that jumps —
usually a claim-mapping regression rather than an attack. `self_origin_total{result="unknown_address"}`
being the whole series is a diagnosis rather than an alert: the cluster SNATs, and workspaces
should use the service-account token path.

## Carrying traffic: the OpenShift shape — deferred

> **Do not enable this yet.** The mode is implemented and **unvalidated**: no OpenShift router has
> ever served a request through it. Its tests are a tier the base suite skips — `task
> test:openshift` runs them — and the gateway logs a warning at startup when the mode is on. It is
> documented here so the shape is reviewable, not because it is ready.

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

## What is not implemented yet

Honest list, kept here rather than in the RFC's prose:

- **OpenShift.** Everything above about `reverseProxy` is code without a cluster behind it: the
  dialect, the `Route` sweep, the companion objects and the proxy shell are written and tested in
  isolation, and none of it has met a real router. The supported dialects today are `Traefik`,
  `Nginx`, `HaproxyIngress` and `Custom`.
- **The dialect conformance suite** against a real Traefik: the four inbound headers arriving
  verbatim, a `Set-Cookie` on a `302` reaching the browser, a `401` body arriving unaltered. The
  decision-side equivalents are unit tests; the wire-side ones need a running controller.
- **The ground-truth spike** — the facts about Che, DevWorkspace Operator and three controllers
  that RFC 0009 takes from documentation.
- **Trusted-proxy `Auto`**: the peer check against the ingress controller's own `EndpointSlice`.
  `trustedProxy: {cidrs: [...]}` covers the same ground with a value an admin writes.
- **`--check` does not run the self-origin probe once**; the running gateway probes on its own
  interval instead.
