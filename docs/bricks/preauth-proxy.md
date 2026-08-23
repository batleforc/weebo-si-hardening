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

`append` joins with a semicolon for `Cookie` and a comma for every other header, because that is
what each one's grammar is.

### Secrets

`${NAME}` references are resolved from the environment, so credential material comes from a Secret
and never touches the config file. **An unset variable is a startup failure, not an empty string** —
`password=` reaching a login form is the failure this rule exists to prevent.

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
| Upstream unreachable | `502` |
| Request body over 4 MiB | `413`. Bodies are buffered because a replay cannot re-read a stream. |
| Config invalid | exit `2` before anything binds |

Nothing here fails **open**. The only failure that opens anything is losing the gateway, and that
is a routing decision outside this process.

## Deploying

```yaml
# Point the route at the proxy Service instead of the upstream Service. Until that change,
# nothing is affected; the switch is the cutover and its inverse is the rollback.
containers:
  - name: preauth-proxy
    image: preauth-proxy@sha256:...
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

## Known limitations

- **`http://` only.** An `https://` origin is refused at startup rather than silently downgraded.
  Both origins are in-cluster services on the pod network.
- **One upstream per instance.** Scale by instances, not by config arrays.
- **A shared upstream identity.** Every caller behind the proxy acts as one service account, so
  the upstream's audit trail names it for everyone. The real identity is known and enforced at the
  gateway; an upstream with meaningful per-user permissions is the wrong fit for this brick.
- **No metrics yet.** The acquisition and renewal log lines, plus the upstream's own request logs,
  are what tell an operator injection is happening.
