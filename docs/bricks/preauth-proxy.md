# `preauth-proxy`

A reverse proxy that keeps a credential obtained from a configured origin and attaches it to
forwarded requests that do not already carry one, renewing it when the upstream rejects it.

Design and rationale: [RFC 0003](../rfc/0003-preauth-proxy.md). This page is the operator's copy.

> **The gateway is the authentication.** This process performs none of its own: it hands every
> request that reaches it a valid, full-privilege upstream credential. That is safe **only** while
> a forward-auth gateway sits ahead of it on the route. If the proxy's Service is reachable
> without that middleware — a second IngressRoute, a port-forward, a pod in the same namespace
> calling the Service directly — the caller is inside the upstream with the service identity, no
> questions asked. Removing the gateway from the route publishes an unauthenticated upstream.

## Usage

```text
preauth-proxy [--config <PATH>] [--check]
```

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--config <PATH>` | `PREAUTH_CONFIG` | `/etc/preauth-proxy/config.yaml` | Config file. |
| `--check` | — | off | Parse and validate, print the effective config, exit. Touches no network. |
| `-h`, `--help` | — | — | Usage. |

The config file is the whole contract; the flags only locate and verify it.

## Configuration

```yaml
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

| Key | Required | Meaning |
| --- | --- | --- |
| `listen` | yes | Address the proxy binds. |
| `upstream` | yes | Origin every non-acquisition request is forwarded to. `http://` only. |
| `passthrough.header` / `.contains` | yes | If this request header contains this substring, forward untouched. |
| `credential.origin` | yes | Origin the acquisition request is sent to. `http://` only. |
| `credential.request` | yes | `method`, `path`, `headers`, `body`. `${ENV}` substituted in header values and body. |
| `credential.accept_status` | yes | Statuses that count as a successful acquisition. |
| `credential.extract.from_header` | yes | Response header the credential is read from. |
| `credential.extract.take` | yes | `cookie-pair`, `whole`, or `after:<prefix>`. |
| `inject.header` | yes | Request header the credential is written to. |
| `inject.mode` | yes | `append` (join the existing value) or `set` (replace it). |
| `renew.on_status` | no | Statuses meaning "stale". Omit or leave empty to disable renewal. |
| `renew.max_replays` | no (default `1`) | Replays per request after a renewal. |
| `limits.connect_timeout_secs` | no (default `5`) | Bound on opening a connection to either origin. |
| `limits.response_timeout_secs` | no (default `60`) | Bound on an origin's response **head**, connect included. Response bodies stream, bounded only by the idle timeout below. |
| `limits.response_idle_timeout_secs` | no (default `60`) | Longest silence allowed between two frames of a streamed response body; past it the body is cut (the caller sees a truncated response) and its slot freed. Resets on every frame, so a long live download is not cut. |
| `limits.client_read_timeout_secs` | no (default `30`) | Bound on the caller sending its request head, and separately its body. |
| `limits.drain_timeout_secs` | no (default `20`) | How long `SIGTERM` waits for in-flight requests. `preStopSleepSeconds` + this must stay under `terminationGracePeriodSeconds` (the chart checks). |
| `limits.max_in_flight` | no (default `256`) | Requests handled at once — a request counts until its response body has finished streaming or the caller has gone; the next gets `503`. |
| `limits.max_buffered_mib` | no (default `16`, min `4`) | Request-body MiB buffered across all requests; a request that would exceed it gets `503`. |

`append` joins with a semicolon for `Cookie` and a comma for every other header, because that is
what each one's grammar is.

### Secrets

`${NAME}` references are resolved from the environment, so credential material comes from a Secret
and never touches the config file. **An unset variable is a startup failure, not an empty string** —
`password=` reaching a login form is the failure this rule exists to prevent.

In a `credential.request.body` whose configured `Content-Type` is
`application/x-www-form-urlencoded`, each substituted value is **percent-encoded**, so a password
containing `&`, `=`, `+` or `%` stays one form field. Store the secret raw, not pre-encoded. Header
values, and bodies of any other content type, are substituted verbatim.

`--check` deliberately prints the config *without* substituted values: it reports how many
references resolved, not what they resolved to, so a `--check` pasted into a ticket carries no
password.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean shutdown, or `--check` on a valid config. |
| `1` | Internal error: bind failure, unreadable config path. |
| `2` | Config error: malformed file, unknown key, or an unset `${ENV}` reference. |
| `3` | Startup acquisition failed. |

Exit `3` is the one to wire an alert to: a wrong credential or an unreachable origin **stops the
rollout** rather than surfacing as request-time `502`s an hour later.

## Behaviour

1. A request carrying `passthrough.contains` in `passthrough.header` is forwarded untouched.
   Nothing is injected and no credential is minted for it.
2. Otherwise the held credential is attached per `inject`, and the request is forwarded.
3. If the response status is in `renew.on_status` and replays remain, the held credential is
   discarded, a fresh one acquired, and the **same** request replayed. A second failure is
   surfaced as-is.
4. Hop-by-hop headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`, … and anything
   `Connection` names) are dropped in both directions. `Host` is rewritten to the upstream.
5. On a response to an injected request, a `Set-Cookie` naming the injected cookie or carrying the
   passthrough marker is dropped, so the service session never reaches the caller's browser. If
   the injected credential's cookie names cannot be told (e.g. `take: whole` of a non-cookie
   token injected as `Cookie`), every `Set-Cookie` on that response is dropped. When
   `inject.header` is anything **other than** `Cookie` (`Authorization`, an API-key header),
   every `Set-Cookie` on an injected response is dropped too: an upstream that mints its own
   session off that header does so under a cookie name the proxy cannot know. There is no
   opt-out. With a `Cookie` injection, other cookies (CSRF tokens, preferences) are relayed.

On `SIGTERM` the listener closes, open connections finish the request they are serving, and the
process exits once they have — or after `limits.drain_timeout_secs`, closing what is left. The
chart delays `SIGTERM` by `preStopSleepSeconds` (default 5, a kubelet `sleep` action, Kubernetes
≥ 1.30; `0` disables it) so the Service stops routing here first. The kubelet's
`terminationGracePeriodSeconds` (chart value, default 30) covers the whole sequence —
preStop sleep, then up to `drain_timeout_secs` of draining — so the chart refuses to render
unless `preStopSleepSeconds` < the grace period and `preStopSleepSeconds + drain_timeout_secs` <
the grace period (defaults: 5 + 20 < 30).

A request holds its `max_in_flight` slot until its response **body** has finished streaming, or
the caller has gone — not merely until the head is sent — so the limit bounds streams in
progress. A body that goes silent for `limits.response_idle_timeout_secs` (default 60) is cut
with a `WARN` line, the caller sees a truncated response, and the slot is freed.

Acquisition is **single-flight**: N concurrent first-requests produce one login, not N.

A passed-through request is never renewed on its caller's behalf — doing so would swap their
identity for the service account's, which is exactly what *pass through* promised not to do.

## Reading the logs

One line at startup, and one per renewal. There are no metrics yet, so **these are the only signal
that injection and renewal are working**:

```text
INFO  preauth-proxy: acquired credential from origin, 21 bytes, marker=cookie
INFO  preauth-proxy: listening on [::]:8080
INFO  preauth-proxy: upstream returned 401, re-acquired and replayed 1 time(s)
ERROR preauth-proxy: acquisition failed: origin returned 403
```

The credential's **length** is logged, never its bytes. A steady trickle of the renewal line means
the upstream expires sessions and the proxy is keeping up; a flood of it means something is
rejecting every credential as fast as it is minted.

## Failure modes

| Situation | Result |
| --- | --- |
| Startup acquisition fails | exit `3`, the rollout stops |
| Acquisition fails at request time | `502`; the caller gets no session, so the upstream challenges them |
| Upstream unreachable, or no response head within `response_timeout_secs` | `502` |
| Response body silent for `response_idle_timeout_secs` mid-stream | body cut (truncated response), slot freed, `WARN` line |
| Request body over 4 MiB | `413`. Bodies are buffered because a replay cannot re-read a stream. |
| Request body not received within `client_read_timeout_secs` | `408`; a request head not received in time closes the connection |
| `max_in_flight` or `max_buffered_mib` reached | `503` at once, with a `WARN` line |
| Config invalid | exit `2` before anything binds |

Nothing here fails **open**. The only failure that opens anything is losing the gateway, and that
is a routing decision outside this process.

## Deploying

**Helm**: `charts/preauth-proxy/`. `credentials.existingSecret` is required — the chart renders no
Secret of its own, deliberately, so a credential never has a path through `helm install --set`.
`values.config` is the whole `config.yaml` body, verbatim; the default matches the example just
below.

```console
$ kubectl create secret generic upstream-service-account \
    --from-literal=user="$CRED_USER" --from-literal=secret="$CRED_SECRET"
$ helm install preauth-proxy charts/preauth-proxy \
    --set credentials.existingSecret=upstream-service-account
```

Raw manifest, equivalent to what the chart renders:

```yaml
# Point the route at the proxy Service instead of the upstream Service. Until that change,
# nothing is affected; the switch is the cutover and its inverse is the rollback.
containers:
  - name: preauth-proxy
    image: ghcr.io/batleforc/preauth-proxy@sha256:...
    args: ["--config", "/etc/preauth-proxy/config.yaml"]
    env:
      - name: CRED_USER
        valueFrom: { secretKeyRef: { name: upstream-service-account, key: user } }
      - name: CRED_SECRET
        valueFrom: { secretKeyRef: { name: upstream-service-account, key: secret } }
    volumeMounts:
      - name: config
        mountPath: /etc/preauth-proxy
        readOnly: true
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities: { drop: ["ALL"] }
```

The config is safe in a ConfigMap and in git — it carries `${ENV}` references, never secrets.

**Chart consistency checks.** `values.schema.json` validates the values (a non-empty
`credentials.existingSecret` included), and the render fails when: `config.listen`'s port differs
from `containerPort` (default 8080 — the port the probes, the Service's `targetPort` and the
NetworkPolicy aim at); the shutdown budget above does not fit; or the `startupProbe` budget
(`periodSeconds` × `failureThreshold`, default 5 × 30 = 150 s) does not exceed the startup
acquisition's worst case, `connect_timeout_secs + response_timeout_secs` (default 65 s). The
listener binds only after that acquisition succeeds, so the startupProbe is what keeps liveness
from killing a pod that is still logging in.

**NetworkPolicy.** Set `networkPolicy.enabled=true` with `networkPolicy.gateway.namespaceSelector`
and/or `.podSelector` naming your forward-auth gateway's pods, and only they can reach the proxy
port — closing the "a pod calls the Service directly" bypass at the network layer. Each selector
is a full Kubernetes LabelSelector, rendered as given (the same shape `charts/endpoint-gateway`
takes):

```yaml
networkPolicy:
  enabled: true
  gateway:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: traefik
    podSelector:
      matchExpressions:
        - { key: app.kubernetes.io/name, operator: In, values: [traefik] }
```

It is off by default only because the chart cannot know where the gateway runs; enabling it
without a selector that carries `matchLabels` or `matchExpressions` fails the render rather than
admitting the whole namespace. A bare label map (the pre-2026-09-29 shape) is refused by the
chart's `values.schema.json`. `networkPolicy.metrics.port`/`.from`
admit scrapers on a metrics port only, once one exists.

## Known limitations

- **`http://` only.** An `https://` origin is refused at startup rather than silently downgraded.
  Both origins are in-cluster services on the pod network.
- **One upstream per instance.** Scale by instances, not by config arrays.
- **A shared upstream identity.** Every caller behind the proxy acts as one service account, so
  the upstream's audit trail names it for everyone. The real identity is known and enforced at the
  gateway; an upstream with meaningful per-user permissions is the wrong fit for this brick.
- **No metrics yet.** The acquisition and renewal log lines, plus the upstream's own request logs,
  are what tell an operator injection is happening.
