---
rfc: 0010
title: endpoint-auth on OpenShift
status: Draft
authors: [batleforc]
created: 2026-09-24
updated: 2026-09-24
decided:
brick: bins/endpoint-gateway
supersedes: []
superseded-by: []
---

# RFC 0010 — endpoint-auth on OpenShift

## Summary

RFC 0009 put an authenticating gate in front of every workspace endpoint and attached it through
the ingress controller's own external-auth hook. OpenShift's router has no such hook, so RFC 0009
also specified a second attachment mode — repoint the `Route` at the gateway and let it carry the
traffic — wrote it, and could never run it: no OpenShift cluster has been available to this
project. This RFC takes that mode out of RFC 0009's plan and makes it its own piece of work, so
that "written" and "supported" stop being one unfinished checkbox on an otherwise finished
feature. Nothing here proposes a new design. It carries the existing one to the point where
somebody has watched a real OpenShift router serve a request through it.

## Motivation

**The code exists and the claim does not.** In the tree today: the `OpenShiftRoute` dialect, the
`Route` retarget and its sweep, `hardening.weebo.io/upstream`, the per-namespace companion
`Service` and `EndpointSlice`, `guarded_kinds()` covering the two extra kinds, and the reverse
proxy shell around the same `decide()` — streaming both ways, `Upgrade` honoured on both sides,
hop-by-hop headers dropped, the gate's own cookie kept out of the application. Its admission half
is proven against a real apiserver with a `Route` CRD installed
(`crates/weebo-si-webhook/tests/openshift_envtest.rs`). What has never happened is one request
reaching one workspace through one OpenShift router.

**Leaving it inside RFC 0009 costs that RFC its meaning.** RFC 0009 is otherwise done: its
implementation plan is ticked, its ground-truth spike has been run, and the one thing keeping it
from `Implemented` is a cluster nobody has. An RFC that cannot be closed for a reason unrelated to
its own design stops being a record of a decision and becomes a ticket, and the next reader cannot
tell which parts are finished.

**And the risk here is different in kind.** Every other dialect answers a question and touches no
traffic. This one carries the traffic: a bug corrupts an application response rather than answering
wrongly, capacity is measured in bandwidth and connections rather than decisions per second, and
the trusted-proxy question has a different answer because every caller reaches the process
directly. That deserves its own security section and its own rollout, not a paragraph inside
somebody else's.

Once this exists: an admin on OpenShift sets `dialect: OpenShiftRoute`, the gate attaches to
`Route`s the way it attaches to `Ingress`es elsewhere, and the brick page stops carrying a "do not
enable this" banner.

## Guide-level explanation

Nothing changes for a developer: the annotations, the catalogue keys and the per-path rules are
RFC 0009's, unchanged. What changes is what an admin installs and what they must watch.

```yaml
features:
  endpointAuth:
    gateway:
      dialect: OpenShiftRoute # instead of Traefik
```

and, in the gateway's own configuration, the two settings this mode makes mandatory:

```yaml
reverse_proxy: true
self_origin:
  # `any` is a startup refusal in this mode: every caller reaches the process directly, so a
  # client-address header from an arbitrary pod would otherwise be an identity.
  trusted_proxy: { cidrs: ["10.128.0.0/14"] } # the router's, not the cluster's
```

What they see when it works: a workspace endpoint redirects to the identity provider, comes back,
and the application answers — with the gateway between the two, which `oc get route` shows as a
`spec.to` naming the companion `Service` and a `hardening.weebo.io/upstream` recording the real
backend. What they see when it does not: the gateway's own error page, and
`weebo_si_endpoint_auth_proxy_errors_total` moving.

## Design

### Contract

Unchanged from RFC 0009, which specified all of it. Restated here as the surface this RFC is
responsible for proving:

- **`Dialect::OpenShiftRoute`** — `mode() == ReverseProxy`, `target_kind() == RoutingKind::Route`,
  `guarded_kinds() == ["routes", "services", "endpointslices"]`.
- **The attachment** is `spec.to.name` repointed at the companion `Service`, with the original
  backend recorded in `hardening.weebo.io/upstream` as `{service}:{port}` and pinned by value by
  `policy-guard`, exactly as an annotation is on the other dialects.
- **The companion objects**, per workspace namespace: a selector-less `Service` and an
  `EndpointSlice` the controller reconciles from the gateway's ready pods, because a `Route`'s
  `spec.to` is a local object reference with no cross-namespace form.
- **The proxy shell** decides with the same `decide()` and, on `allow`, forwards to the recorded
  backend: streaming both ways, `Upgrade` honoured, hop-by-hop headers dropped, the gate's own
  cookie removed before the application sees it.

### Architecture

Unchanged, and that is the point: the reverse-proxy shell is a second *inbound adapter* over the
same domain. `decide()` does not know which shell called it, `presented_from` is shared so the two
cannot disagree about which header carries what, and a test asserts both shells build the same
request from the same input. If this RFC finds that OpenShift needs the decision to change, that
is a finding worth stopping for — it would mean the port was drawn in the wrong place.

### Data and state

Unchanged from RFC 0009 — the gateway keeps its identity caches, its revocation set and its host
index, and persists nothing. The one addition this mode already carries is the companion
`EndpointSlice`, which is derived state: delete it and the controller rebuilds it on the next
reconcile, at the cost of the requests in flight.

## Security considerations

- **Privileges.** Beyond RFC 0009's: `services` and `endpointslices` create/update in workspace
  namespaces, and `routes` in place of `ingresses`. The first two are what make this dialect more
  expensive than the others, and `guarded_kinds()` growing to match is what keeps a developer from
  editing their way out through the companion objects.
- **Trust boundary.** Wider than RFC 0009's, and this is the material difference: on a forward-auth
  dialect only the ingress controller ever calls `/auth`, so a client-address header is the
  controller's word. Here every caller reaches the process directly, so the same header is the
  *caller's* word. `trusted_proxy: any` with pod-network identity on is a startup refusal for
  exactly this reason.
- **Bypass.** The gate is `spec.to`, not an annotation — so the guard rule and the mutation have to
  be reasoned about together, which RFC 0009's changelog records getting wrong once already (the
  mutation reapplied `spec.to` unconditionally, so the guard's pin could never fire).
- **Blast radius.** A bug corrupts an application response rather than answering a question
  wrongly. This is the dialect where the gateway is on the data path.
- **Secrets.** Unchanged: the gate's own cookie is stripped before the application sees it, and the
  logging policy cannot carry a cookie, a token or a grant.

## Operational considerations

- **Failure mode.** The gateway being down means the endpoint is down, not open — the opposite
  trade from a forward-auth dialect, where the router answers with its own error page. The chart's
  three replicas, anti-affinity and `system-cluster-critical` exist for this mode more than any
  other.
- **Rollout.** RFC 0009's `Observe` step still applies and is still the useful one, but it no
  longer removes the risk: an `Observe` gateway on this dialect is still carrying the traffic.
- **Rollback.** `dialect: Traefik` does not undo a retarget; the sweep does. The undo is
  `mode: Off`, which strips what the sweep wrote and restores `spec.to` from
  `hardening.weebo.io/upstream` — which is the reason that annotation exists at all.
- **Observability.** The metrics RFC 0009 defines, plus whatever the conformance run shows is
  missing for a proxy: connection counts and bytes in flight are not decisions per second.
- **Upgrade.** A rolling update of the gateway drops in-flight connections on this dialect and
  drops nothing on the others.

## Alternatives considered

- **Leave it in RFC 0009.** What we do today. It keeps one document, and it keeps that document
  permanently open on a line nobody can close — and it lets "written" keep reading as "supported"
  for anyone who skims the plan.
- **Delete the code and re-add it when an OpenShift cluster exists.** Honest, and it throws away
  work that is written, reviewed and admission-tested. It also loses the thing the code is best
  at: being a concrete proposal for the next person to check.
- **Run the OpenShift router as a container instead of a cluster.** The router is HAProxy with
  OpenShift's own configuration; running it outside OpenShift would test HAProxy, not the router,
  and the questions here — does DWO publish `Route`s, does the router serve a selector-less
  `Service`, is `spec.to` local-only — are questions about OpenShift and not about HAProxy.
- **CRC (CodeReady Containers) rather than a real cluster.** Plausible and untried, and the
  cheapest thing this RFC could start with. It answers the three spike rows; whether it answers
  the capacity ones is doubtful.

## Drawbacks and risks

The code ages. Every RFC 0009 change to `decide()`, to the header handling, or to the guard has to
be carried through a shell nobody exercises, and the compiler only catches some of that — the
`task test:openshift` tier catches a little more, and neither catches a behavioural drift between
the two shells on a router nobody has run.

There is also a real chance this RFC's first act is to discover that one of RFC 0009's three
OpenShift assumptions is wrong, and that the companion-object design has to change. That is the
argument for doing it rather than for deferring it further.

## Unresolved questions

### Blocking

None — nothing here needs deciding before the work starts. It needs a cluster.

### Non-blocking

| # | Question | Why it can wait |
| - | -------- | --------------- |
| 1 | CRC or a real cluster? | Both answer the spike rows; only one answers capacity, and which is available decides it |
| 2 | Does the OpenShift router pass a non-`2xx` body verbatim? | It does not matter on this dialect — the gateway writes the response itself — but it decides whether an OpenShift cluster could ever run a *forward-auth* dialect instead |
| 3 | Is `EndpointSlice` reconciliation fast enough that a gateway rollout does not strand a namespace? | Only measurable on a cluster |

## Future work

Whether the gateway should refuse to start on this dialect when the companion objects are absent,
rather than discovering it per request. Left out because the answer depends on what a real rollout
looks like.

## Implementation plan

- [ ] **The three OpenShift ground-truth rows**, which are row 4 of RFC 0009's spike and move here
      with it: that DWO publishes `Route`s on OpenShift, that the router serves a selector-less
      `Service` with an operator-managed `EndpointSlice`, and that `spec.to` is local-only.
      `scripts/spike-0009.sh --row 4` already reads all three and skips itself where
      `route.openshift.io/v1` is not served
- [ ] One request, served end to end through a real OpenShift router: owner allowed, non-owner
      denied, and the application's response arriving unaltered
- [ ] A WebSocket surviving the shell — an HMR socket reconnecting is the case *Developer
      continuity* names, and the one a streaming proxy gets wrong first
- [ ] The `task test:openshift` tier run against that cluster rather than skipped, and promoted
      out of the deferred tier if it passes
- [ ] Capacity: bandwidth, buffers and connection count, measured rather than reasoned about —
      RFC 0009's *Capacity* plans from a decision that costs ~130 ns and says nothing about a
      proxied megabyte
- [ ] The trusted-proxy CIDRs an OpenShift router actually presents, written down where an admin
      can copy them
- [ ] Docs updated: `docs/bricks/endpoint-gateway.md` loses its "do not enable this" banner, or
      keeps it with a reason that is no longer "nobody has tried"
- [ ] RFC flipped to `Implemented`

## References

- [RFC 0009 — endpoint-auth](./0009-endpoint-auth.md), whose *Attaching the gate* specifies this
  dialect and whose changelog records the two bugs its admission half has already found
- `crates/weebo-si-webhook/tests/openshift_envtest.rs` — the admission half, against a real
  apiserver with a `Route` CRD
- `bins/endpoint-gateway/src/proxy.rs` — the reverse-proxy shell
- [OpenShift routes](https://docs.openshift.com/container-platform/latest/networking/routes/route-configuration.html)

## Changelog

| Date | Change |
| --- | --- |
