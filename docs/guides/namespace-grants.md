# Restricted keys and namespace grants

How to keep a workspace from granting itself a catalogue key that widens what it can do, such as
the `internet` network profile or the anonymous `open` endpoint access. Design and threat model:
[RFC 0021](../rfc/0021-namespace-only-grants.md). Fields:
[`features.networkProfiles`](../weebosiconfig.md#featuresnetworkprofiles) and
[`features.endpointAuth`](../weebosiconfig.md#featuresendpointauth). The two features' pages are
[`network-profiles.md`](../bricks/network-profiles.md) and
[`endpoint-gateway.md`](../bricks/endpoint-gateway.md).

## Why

A workspace picks its network profiles with a DevWorkspace attribute and its endpoint access with
the `hardening.weebo.io/access` annotation. Both are written by the developer, and the
workspace's own ServiceAccount token can patch its DevWorkspace. Without this, the team catalogue
is the grant: any process in the workspace (an npm `postinstall`, an AI agent) can patch in
`internet` or `open` and the next reconcile honours it.

A key marked `restricted: true` is honoured only if the workspace's **Namespace** also names it in
an admin grant annotation. Neither the user nor the workspace token can write a Namespace, so the
grant is out of the workspace's reach. Selection does not move: the attribute and the endpoint
annotation still choose; the Namespace annotation only grants, it never selects.

## Mark a key restricted

In the cluster catalogue and in every team that re-declares the entry, **in the same commit**:
entries are compared whole, and a team copy left without `restricted` is a `CatalogKeyConflict`.

```yaml
# WeeboSiConfig cluster
spec:
  features:
    networkProfiles:
      catalog:
        - key: internet
          restricted: true          # default false
          variants: [...]
---
# WeeboSiTeam weebo
spec:
  features:
    networkProfiles:
      catalog:
        - key: internet             # identical to the cluster entry, restricted included
          restricted: true
          variants: [...]
    endpointAuth:
      catalog:
        - { key: open, anonymous: true, restricted: true, delegation: [] }
```

`restricted` defaults to `false` on every entry, anonymous ones included, so an upgrade of the
operator changes nothing a catalogue grants. Nothing changes until an admin writes the line.

## Grant it to a namespace

```yaml
kind: Namespace
metadata:
  name: dev-ws-alice
  annotations:
    hardening.weebo.io/network-grants: internet   # networkProfiles.namespaceGrant.annotation
    hardening.weebo.io/endpoint-access: open      # a constant
```

Each value is a comma-separated set: order, whitespace and duplicates do not matter, an unknown key
is ignored, and an absent or empty annotation grants nothing. A grant never widens past the team
catalogue and never selects a key nobody asked for. On weebo-si the plan is to render them from
`2.helm/user-app` (`dev-ns.yaml`), set per person by an admin in Git as the record of every grant;
**that template does not carry them yet** (RFC 0021, *Integration in weebo-si*). Until it does, a
grant is a `kubectl annotate` Argo CD does not own: write it down.

## What happens

| Case | network-profiles | endpoint-auth |
| --- | --- | --- |
| key not restricted | unchanged: the team catalogue is the grant | unchanged |
| restricted, not in the team catalogue | not granted, as before | `NotGranted` as before: refused at admission under `Enforce`, indexed closed |
| restricted, in the catalogue, the Namespace grants it | **honoured** | **honoured** |
| restricted, in the catalogue, no grant | **refused**: treated as not granted, `onNotGranted` applies (see below) | **refused**: the endpoint resolves to its default (the team's, narrowed by `overrides`); the `Ingress` is admitted |
| restricted key in a team `default` | config violation `RestrictedKeyInDefault`, `Degraded`; filtered at runtime | same; if the endpoint's default itself is filtered, the endpoint is indexed closed (owner only) and, under `Enforce`, its `Ingress` write (DWO's included) is **refused at admission** until the grant exists |
| restricted network `baseline` | refused at `kubectl apply` by a CEL rule (`RestrictedKeyInDefault`, `Degraded` if one is already stored): only `resolve` filters, and the baseline does not go through it | n/a |
| `namespaceGrant.annotation: ""` | every restricted key refused (fail closed) | n/a |

**network-profiles, `onNotGranted: Default`:** the request is dropped and the team default
applied. **`onNotGranted: Deny`:** a DevWorkspace **created** with a refused key is refused
(kubectl prints a bare `Error from server:`, not the RFC mock's `Forbidden`):

```text
Error from server: error when creating "python-web.yaml": admission webhook
"devworkspaces.hardening.weebo.io" denied the request: workspace python-web requests network
profile(s) [internet], which are restricted: namespace dev-ws-batleforc-test does not grant them
(annotation hardening.weebo.io/network-grants)
```

An `UPDATE` is admitted. Every **admitted** write naming a refused key (any `UPDATE`, and a
`CREATE` under `Default`) gets an admission warning; a refused `CREATE` gets the denial alone:

```text
Warning: network profile(s) [internet]: restricted, no namespace grant (hardening.weebo.io/network-grants); not applied
```

The effect is `not applied` under `onNotGranted: Default` and `Deny: baseline only` when the
request is refused under `Deny` (an `UPDATE`). With `namespaceGrant.annotation: ""` the clause
reads `grants disabled (namespaceGrant.annotation empty)` instead. The warning fits in 120
characters: keys that do not fit are counted as `+N more` (`[internet,+2 more]`), so the clause
and the effect are never cut.

Warnings reach `kubectl` only (the Che dashboard drops them); the Event below is for everyone. **Under `Deny`, revoking a grant from a running workspace drops every profile beyond
the baseline**, not only the revoked key: a refused request applies nothing beyond the baseline,
which is the existing `Deny` rule (RFC 0021 does not cover it; the lab runs `Default`). A workspace
whose attribute names `git,internet` loses `git` too, within seconds, until the attribute or the
grant is fixed.

**endpoint-auth:** an unauthenticated browser on an ungranted `open` endpoint is sent to sign in, a
`curl` gets the gate's `401`, and the owner still reaches it.

## Timing

| Change | network-profiles | endpoint-auth |
| --- | --- | --- |
| grant added or removed (enforcement) | at the next pass of the namespace's workspaces, in seconds (a Namespace annotation change re-runs them; bounded at 30 s in the e2e suite) | the gateway reads the Namespace: about 100 ms |
| the same change in the audit (Event, counter, log line) | with the enforcement | at the next `Ingress` event or the **300 s requeue**: endpoint-auth has no Namespace → `Ingress` watch |

So an `open` grant given and revoked within 300 s may never be counted `honoured`. Enforcement
does not lag; only the audit does. A lost Namespace watch event delays a network grant, or lets a
removed one linger, until the 300 s requeue. A revocation does not cut established connections:
restart the workspace for that.

## What is recorded

Every key that **enters** a workspace's (or an `Ingress`'s) honoured or refused set, not every
pass. A key that leaves both sets (the attribute drops it, the workspace is deleted) records
nothing:

```text
INFO feature=network-profiles restricted=internet namespace=dev-ws-batleforc-test workspace=python-web mode=Enforce result=refused reason=no_namespace_grant
INFO feature=endpoint-auth restricted=open namespace=dev-ws-batleforc-test ingress=python-web-api mode=Enforce result=honoured
```

| Signal | Name |
| --- | --- |
| counter | `weebo_si_restricted_grant_total{feature, key, result="honoured"\|"refused"}`, absent from `/metrics` until its first increment; never a namespace or user label |
| Event | `RestrictedGrantHonoured` (Normal), `RestrictedGrantRefused` (Warning) on the DevWorkspace or the `Ingress` |
| admission result | `denied_restricted` (network-profiles, `Deny`, CREATE only), only when every refused key is restricted; a mixed refusal (`internet,foo` with `foo` outside the team) is `denied_not_granted` with a restricted clause appended |

```text
Warning  RestrictedGrantRefused  devworkspace/python-web  network profile internet is restricted and
  namespace dev-ws-batleforc-test does not grant it (annotation hardening.weebo.io/network-grants);
  onNotGranted=Default applied the team default [dev-registries,anthropic]
Warning  RestrictedGrantRefused  ingress/python-web-api   access key open is restricted and
  namespace dev-ws-batleforc-test does not grant it (annotation hardening.weebo.io/endpoint-access);
  served as private
```

Alerts (ClickStack, on the INFO line): any new (namespace, key) pair with `feature=endpoint-auth
result=honoured`, and any new pair with `result=refused` (an attempt, or a grant step 2 below
missed).

## Rollout

The restriction has no mode of its own: it rides each feature's mode. Both features already run
`Enforce` on the lab, so the rollout is by data, test namespace first.

1. **Ship the operator.** `restricted` defaults to `false`: nothing changes.
2. **Inventory and grant current users**, every namespace found except the test one:

   ```bash
   kubectl get devworkspaces -A -o json | jq -r '.items[] |
     select(.spec.template.attributes["hardening.weebo.io/network-profiles"] // "" |
     test("(^|,)\\s*internet\\s*(,|$)")) | .metadata.namespace'
   kubectl get ns -o json | jq -r '.items[] |
     select(.metadata.annotations["hardening.weebo.io/network-profiles"] // "" |
     test("(^|,)\\s*internet\\s*(,|$)")) | .metadata.name'
   kubectl get ingress -A -o json | jq -r '.items[] |
     select(.metadata.annotations["hardening.weebo.io/access"] // "" | test("(^|,)\\s*open\\s*(,|$)")) |
     .metadata.namespace'
   ```

   The last line misses an `open` named only in a `hardening.weebo.io/rules` path rule: check
   those by hand.
3. **Write `restricted: true`** on `internet` (cluster and team entries, one commit) and on `open`.
   Only ungranted namespaces are affected; run RFC 0021's cluster checks (T-07, T-12, T-27) on the
   test namespace.
4. **Watch `result="refused"` for at least seven days.** Each one is an attempt, or a namespace
   step 2 missed.

## Rollback

Remove `restricted: true` from the entry (or revert the values commit). The next configuration
load restores the team-wide grant. The grant annotations can stay: they select nothing.

## Not implemented

RFC 0021 asks for a warning at every configuration load when an `anonymous: true` entry lacks
`restricted: true`. This build does not log it: check the catalogue by hand at step 3.
