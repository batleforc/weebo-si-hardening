---
rfc: 0005
title: image-policy
status: Implemented
authors: [batleforc]
created: 2026-08-24
updated: 2026-08-24
decided: 2026-08-24
brick: crates/weebo-si-image-policy
supersedes: []
superseded-by: []
---

# RFC 0005 — image-policy

## Summary

`image-policy` decides which container images a workspace is permitted to run, per team, on the
[RFC 0002](./0002-weebo-si-operator.md) chassis. An admin writes a catalogue of image patterns,
grants each team a subset, and a workspace picks inside what its team was granted — the same
catalogue-and-grants shape [`dwoc-pin`](./0002-weebo-si-operator.md#feature-dwoc-pin) and
[`network-profiles`](./0004-network-profiles.md) already use, so an admin learns the routing once.
A pattern may interpolate `{TEAM_NAME}`, so a registry laid out one path per team is one catalogue
entry rather than one entry per team.

Enforcement happens at two admission points with deliberately different precision: a validating
webhook on `DevWorkspace` gives the developer a readable error at `kubectl apply` time and
enforces the exact selection, and a validating webhook on `Pod` is the floor that catches the
images DevWorkspace Operator injects, the plugin sidecars a devfile pulls in by URI, and any pod
created without a workspace at all. This is the RFC [RFC 0002](./0002-weebo-si-operator.md)
reserved in its *Future work* under "Image restriction".

## Motivation

A workspace runs whatever image its devfile names. `docker.io/library/anything`, a personal
account on a public registry, a URL in a repository the developer cloned this morning. Nothing
in Eclipse Che, in DevWorkspace Operator, or in [RFC 0002](./0002-weebo-si-operator.md) narrows
that: `dwoc-pin` decides which `DevWorkspaceOperatorConfig` a workspace runs with, which settles
the *pull policy* and the *default* image, and settles nothing about the image a devfile asks
for by name.

The exposure is the same one [RFC 0004](./0004-network-profiles.md) describes and it arrives one
layer earlier. A devfile is a file in a repository; the person who wrote it is not necessarily
the person who runs it, and an image reference in it is an instruction to download and execute
arbitrary code inside the cluster, under the workspace's service account, with the workspace's
network position. [RFC 0004](./0004-network-profiles.md) bounds where that code can reach.
Nothing yet bounds what the code *is*.

Three concrete failures, in increasing order of how often they actually happen:

- **A typo'd or squatted reference.** `quay.io/devfile/universal-developer-image` and a
  lookalike differ by characters nobody reads. Pull succeeds, workspace starts, nothing looks
  wrong.
- **An image that is simply not supportable.** Someone bases a project on an image the platform
  team has never seen, it works, and it becomes load-bearing. There is no moment at which
  anybody decided that.
- **Egress the network baseline cannot see.** A workspace permitted to reach the internal
  registry is permitted to reach whatever the internal registry proxies. Image naming is a
  distinct control from image reachability, and neither substitutes for the other.

**The granularity is per team, not per cluster.** OpenShift already ships a cluster-wide answer
— `image.config.openshift.io/cluster`'s `registrySources` — and it is the wrong shape for the
same reason a cluster-wide network policy is: a data team needing one vendor image and a web
team needing none are one decision under it. Granting the cluster what the data team needs
grants it to everyone, which is the whole problem restated one level up.

**And the catalogue must not become a second copy of `spec.teams`.** The layout an internal
registry actually has is a path per team — `registry.internal/teams/team-1/...` — and writing that
as one catalogue entry per team means the catalogue restates a list the chassis already holds.
[RFC 0002](./0002-weebo-si-operator.md) hoisted teams to the chassis precisely to stop that: two
places holding the same names, both individually valid, with nothing reporting the day they
diverge. A pattern that can say `{TEAM_NAME}` refers to the declaration instead of copying it,
which is why variables are part of this design rather than a later convenience.

### What exists today

- **Nothing, in a stock Che install.** Any image any registry serves.
- **`registrySources` on OpenShift**, cluster-wide, and it blocks the *pull* rather than the
  *admission*, so the failure arrives as `ImagePullBackOff` with no explanation of the policy.
- **A policy engine** — Kyverno and Gatekeeper both do registry restriction well, and Kyverno
  ships a tested reference parser. Discussed at length under *Alternatives considered*, because
  this is the closest thing to a reason not to write this RFC.
- **Only handing workspaces credentials for the internal registry.** Real, complementary, and
  not a control: unauthenticated public registries need no credentials.

**Outcome we are buying:** every image that starts in a workspace namespace matches a pattern an
admin wrote down or a platform image the operator ships; a team reaches exactly the entries its
grant names; a developer naming something else learns it in the API error on their own
`kubectl apply` rather than as a pod that will not start; and an admin can answer "what is
running in this cluster and what would this configuration do to it" before switching anything on.

## Guide-level explanation

The feature starts `Off`, per the chassis. It needs a catalogue, a default for namespaces with
no team, and grants against the teams `spec.teams` already declares.

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  teams:                                  # chassis-level, shared with dwoc-pin and network-profiles
    - name: team-1
      namespaceSelector:
        matchLabels: {weebo.io/team: team-1}
  features:
    imagePolicy:
      mode: DryRun
      variables:
        PROJECT:                          # bound to an annotation users cannot write
          fromNamespaceAnnotation: weebo.io/project
      catalog:
        - key: internal
          patterns:
            - "registry.internal/shared/**"
        - key: team-registry              # one entry, every team, no copy per team
          patterns:
            - "registry.internal/teams/{TEAM_NAME}/**"
        - key: project-registry
          patterns:
            - "registry.internal/projects/{PROJECT}/**"
        - key: devfile-udi
          patterns:
            - "quay.io/devfile/universal-developer-image:ubi9-*"
        - key: dockerhub-library
          patterns:
            - "docker.io/library/**"
      default: [internal]                 # a namespace belonging to no team
      grants:
        team-1:
          allowed: [internal, team-registry, devfile-udi]
          default: [internal, team-registry]
      platform:
        builtin: true                     # the images Che and DWO inject — always allowed
```

Nobody writes the platform images down. They are compiled in, they are allowed for every team,
and no grant can withhold them — the same non-negotiable position
[RFC 0004](./0004-network-profiles.md)'s `baseline` holds, for the same reason: a control that
can be configured into breaking the platform it protects is a control nobody will leave on.
What is in that set is printed by the binary rather than described in prose:

```console
$ weebo-si-operator images platform
quay.io/devfile/project-clone:*
quay.io/che-incubator/che-code:*
quay.io/che-incubator/configbump:*
quay.io/eclipse/che--traefik:*
```

Before switching anything on, the question an admin actually has is "what would this do to my
cluster", and it is answerable without touching the cluster's behaviour:

```console
$ weebo-si-operator images audit --all-namespaces
IMAGE                                                    PODS  VERDICT
quay.io/devfile/universal-developer-image:ubi9-latest      41  allowed  devfile-udi
registry.internal/teams/team-1/dev-java:21                 18  allowed  team-registry
registry.internal/shared/base:2026.3                       11  allowed  internal
quay.io/devfile/project-clone:v0.30.0                      59  allowed  platform
registry.internal/teams/team-3/dev-go:1.24                  4  DENIED   in user-carol: {TEAM_NAME}=team-1
docker.io/library/postgres:16                               6  DENIED   team-2 grants [internal]
ghcr.io/someone/scratch-image:main                          1  DENIED   no matching pattern
```

That command reads pods with the admin's own kubeconfig, not the operator's service account, and
writes nothing. The three denied rows are the entire content of the rollout conversation, and the
middle one is the case a per-team path exists to catch: a workspace in a team-1 namespace running
an image out of team-3's registry path. Because a pattern may interpolate, a verdict is a property
of the namespace rather than of the image alone — `audit` aggregates the images whose verdict is
the same everywhere and names the namespace for the rest.

In `DryRun` the same verdicts are computed on real admission traffic and thrown away:

```text
INFO  feature=image-policy mode=DryRun resource=devworkspace ns=user-alice team=team-1
      workspace=data-pipeline entries=[internal,devfile-udi] result=allowed images=3
WARN  feature=image-policy mode=DryRun resource=devworkspace ns=user-bob team=team-2
      workspace=scratch entries=[internal] result=denied component=tools
      image="docker.io/library/postgres:16"
```

A developer asks for a wider entry in the devfile, so the request travels with the project
rather than with the person, exactly as it does for network profiles:

```yaml
schemaVersion: 2.2.0
metadata:
  name: data-pipeline
attributes:
  hardening.weebo.io/image-policy: "internal,devfile-udi"
```

Switching to `Enforce`, narrowed to a pilot namespace first, a bad reference is refused where the
developer is standing:

```console
$ kubectl apply -f devworkspace.yaml
Error from server: admission webhook "images.hardening.weebo.io" denied the request:
  component "tools": image "docker.io/library/postgres:16" is not permitted
  (team team-2, entries [internal]); permitted patterns are in WeeboSiConfig/cluster
  .spec.features.imagePolicy.catalog
```

And the floor underneath it catches what the devfile never mentioned — a plugin the devfile
imported by URI, resolved to an image by DevWorkspace Operator long after admission:

```console
$ kubectl get events -n user-bob
Warning  FailedCreate  replicaset/scratch-abc123  Error creating: admission webhook
  "images.hardening.weebo.io" denied the request: container "sidecar": image
  "ghcr.io/someone/tool:main" is not permitted (team team-2)
```

That message is worse than the first one, and it is supposed to be. It is the one that fires for
images the developer did not write down, which is exactly the case where the good error message
was never available.

## Design

### Contract

Terminology is the chassis's, plus one word. An **entry** is a named, admin-authored set of image
patterns, one catalogue entry. The **platform set** is the pattern set allowed in every namespace
regardless of team, and it is the only one no grant can withhold.

#### `imagePolicy`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | enum | — | required, per the chassis |
| `namespaceSelector` | LabelSelector | none | per the chassis — the rollout knob |
| `catalog` | list of entries | — | required, non-empty. Each is `{key, patterns}`. |
| `variables` | map, name → `{fromNamespaceAnnotation}` | empty | Additional pattern variables, beyond the two built in. Declaring one is the opt-in to an annotation-sourced value; see *Variables in a pattern*. |
| `default` | list of entry keys | — | required. Applied to a namespace belonging to no team. May be empty, which means the platform set and nothing else. |
| `grants` | map, team name → `{allowed, default}` | empty | `allowed` is the set of keys a team may reach; `default` is the subset applied when a workspace asks for nothing. Both may be empty. |
| `namespaceSelection.annotation` | string | `hardening.weebo.io/image-policy` | Namespace annotation carrying a comma-separated key list, overriding the team default for that namespace. Empty string disables it. |
| `workspaceSelection.attribute` | string | `hardening.weebo.io/image-policy` | DevWorkspace attribute carrying the same, overriding the namespace. Empty string disables it. |
| `onNotGranted` | `Default` \| `Deny` | `Default` | What to do when a workspace names a key its team lacks. |
| `platform.builtin` | bool | `true` | Whether the compiled-in platform patterns apply. |
| `platform.extra` | list of patterns | empty | Additional always-allowed patterns, for an admin who mirrors the platform images into their own registry. |

An **entry** is `{key, patterns}`; `patterns` is a non-empty list. Nothing else. An entry carries
no scope, no exception and no negation — see *A pattern set is a union* below for why the shape
has no room for a deny rule.

#### Image references, and why they are parsed rather than matched

**This is the security-critical part of this RFC, and everything else in it is bookkeeping.** A
pattern matched against the reference string a user typed is a bypass generator, because the
string a user types and the image a kubelet pulls are related by a normalization nobody has in
their head:

| Written | Pulled |
| --- | --- |
| `nginx` | `docker.io/library/nginx:latest` |
| `weebo/dev` | `docker.io/weebo/dev:latest` |
| `REGISTRY.INTERNAL/weebo/dev` | `registry.internal/weebo/dev:latest` — hosts are case-insensitive |
| `registry.internal./weebo/dev` | `registry.internal/weebo/dev:latest` — the trailing dot is a valid FQDN |
| `localhost:5000/dev` | `localhost:5000/dev:latest` — a host, because of the port |
| `internal/weebo/dev` | `docker.io/internal/weebo/dev:latest` — *not* a host, no dot and no port |
| `dev:v1@sha256:abc…` | `sha256:abc…` — the tag is decoration, the digest is what runs |

So: a reference is **parsed into `{host, path, tag, digest}` and normalized before anything
looks at it**, and a pattern is parsed by the same code into the same shape. Matching is per
field. Two consequences worth stating as rules:

- **A reference that does not parse is denied**, never allowed and never passed through. This is
  the one place in this RFC with no configurable knob, because the alternative is a control whose
  bypass is "send something malformed".
- **A pattern that does not parse is a `Degraded` condition** at reconcile, and the entry
  carrying it grants nothing. A misconfigured entry must fail toward denying, not toward
  matching more than the admin meant.

`weebo-si-operator images check` exposes the parser so an admin can see the normalization rather
than infer it:

```console
$ weebo-si-operator images check nginx --team team-1
reference  nginx
normalized docker.io/library/nginx:latest
           host=docker.io path=library/nginx tag=latest digest=<none>
verdict    DENIED — team team-1, entries [internal, team-registry], no matching pattern

$ weebo-si-operator images check registry.internal/teams/team-1/dev-java:21 --team team-1
reference  registry.internal/teams/team-1/dev-java:21
normalized registry.internal/teams/team-1/dev-java:21
           host=registry.internal path=teams/team-1/dev-java tag=21 digest=<none>
patterns   registry.internal/teams/{TEAM_NAME}/**  ->  registry.internal/teams/team-1/**
verdict    permitted by entry team-registry
```

The `patterns` line is not decoration. A pattern that interpolates is one an admin cannot check by
reading, so the command prints what it became.

#### Pattern grammar

A pattern is parsed as a reference is, and each field is matched independently.

| Field | Grammar | Notes |
| --- | --- | --- |
| host | a literal host, `*.suffix`, or a host whose whole label is a variable | Lowercased, trailing dot stripped, port significant. A bare `*` is rejected at validation — "any registry" is not an allow-list, and an admin who genuinely means it writes `**` for the path under each registry they name. |
| path | `/`-separated segments; `*` matches within one segment, `**` matches one or more whole segments; a whole segment may be a variable | `library/*` matches `library/nginx`, not `library/a/b`. `**` matches both. |
| tag | glob, `*` within the tag; may contain a variable | Absent from the pattern means "any tag, or none". |
| digest | not writable in a pattern | See below. |

Variables — `{TEAM_NAME}` and `{NAMESPACE}` — have their own section immediately below, because
substituting a value into a matcher is the second-most dangerous thing in this RFC.

The separator ambiguity that makes flat-string globbing unsafe — is the `:` in
`registry:5000/foo` a port or a tag, does `**` cross it — does not exist here, because the split
happened in the parser and the pattern never sees a `:` it has to guess about.

**Tags, digests, and what a pattern with a tag constraint means.** A reference carrying a digest
runs that digest whatever its tag says, so the tag is not evidence. The rule:

- A pattern with no tag constraint matches any reference in its host and path, tagged, digested,
  or both.
- A pattern with a tag constraint matches a reference whose tag matches the glob. A digest-only
  reference has no tag and therefore matches only tag-agnostic patterns.

An admin who wants "only `ubi9-*`, and pinned" gets the first half from this RFC and the second
half from *Future work* — a `requireDigest` switch per entry is named there, deliberately not
shipped, because it is a fleet-wide devfile rewrite and it should be its own decision.

#### Variables in a pattern

A pattern may carry a variable, written `{NAME}`, substituted from facts the operator has already
resolved for the subject. Two are built in, and an admin may declare more:

| Variable | Value | Written by | In host | In path | In tag |
| --- | --- | --- | :-: | :-: | :-: |
| `{TEAM_NAME}` | the resolved chassis team's name | the admin, in `spec.teams` | yes | yes | yes |
| `{NAMESPACE}` | the subject's namespace | the platform — Che creates workspace namespaces | no | yes | yes |
| declared | a namespace annotation's value | whoever may annotate the namespace — see below | no | yes | yes |

A declared variable binds a name to an annotation key:

```yaml
      variables:
        PROJECT:
          fromNamespaceAnnotation: weebo.io/project
      catalog:
        - key: project-registry
          patterns:
            - "registry.internal/projects/{PROJECT}/**"
```

A variable name is `[A-Z][A-Z0-9_]*`; `TEAM_NAME` and `NAMESPACE` are reserved and rebinding one
is a `Degraded` condition. An **undeclared** name used in a pattern is a `Degraded` condition too,
never a literal — `{TEMA_NAME}` has to be a reported typo rather than a path segment that silently
never matches, because "never matches" is indistinguishable from "correctly restrictive" from the
outside.

**A declared variable rests on the workspace user being unable to annotate their own namespace,
and that is a property of the cluster rather than of this feature.** In the Che installation this
repo targets, they cannot — which is what makes the annotation an admin-controlled input and the
pattern a real allow-list. In a cluster where the user namespace carries something closer to the
built-in `edit` role, the same configuration is an allow-list whose value the constrained party
writes: it still reports `allowed`, and it means nothing. This is the same shape
[RFC 0004](./0004-network-profiles.md) gives `policy-guard` — same code, two very different
importances — and it gets the same treatment. Declaring `variables` at all is the opt-in, "can a
workspace user annotate their namespace" is a line on the install checklist with a command next to
it, and *Operational considerations* carries the detection for the day the answer changes.

The two built-ins are not affected by any of that: `{TEAM_NAME}` comes from `spec.teams` and
`{NAMESPACE}` from the apiserver's own naming, and neither is reachable by a workspace user under
any RBAC.

**Substitution happens after parsing, into one slot, never into the string.** The pattern is
parsed into `{host, path, tag, digest}` first; a variable occupies exactly one whole path segment,
one whole host label, or a run inside the tag, and its value is validated as a single legal
component before it is placed there. A value is never concatenated into the text and re-parsed.
This is the same decision as parsing references rather than globbing them, for the same reason: a
team named `a/**` would otherwise turn one segment into a wildcard, and the pattern an admin read
in the CRD would not be the pattern that ran.

Three rules follow, each fail-closed:

- **A value must be a single legal path component** — `[a-z0-9]` groups separated by `.`, `_`,
  `__` or `-`, with no `/`, no `*`, and no brace. `{NAMESPACE}` satisfies this by construction,
  since a DNS-1123 label is a strict subset and the apiserver already enforced it. The other two
  do not, and **they fail differently on purpose**:
  - `spec.teams[].name` is free text, so a team name that is not a legal path component is a
    `Degraded` condition naming that team, raised as soon as any pattern uses `{TEAM_NAME}`. It
    is statically checkable, it is the admin's own file, and a team name is not going to become
    legal at admission time — so the controller catches it at reconcile.
  - A declared variable's value is per namespace and only known at request time, so an illegal
    value makes the variable **undefined for that namespace** and raises no condition. That
    asymmetry is deliberate: a value a namespace carries must never be able to drive the status of
    a cluster-scoped singleton. Otherwise, on the day the RBAC assumption above stops holding,
    anyone able to annotate a namespace could flip `WeeboSiConfig` to `Degraded` at will, and the
    condition that reports a broken catalogue would be full of noise anyone can generate. It is
    counted instead, in `weebo_si_image_policy_variable_total{result="illegal"}`.
- **An undefined variable matches nothing.** A namespace belonging to no team has no
  `{TEAM_NAME}`; a namespace without the bound annotation has no `{PROJECT}`. A pattern carrying
  one is skipped for that namespace. It is *not* treated as an empty segment, which would collapse
  `registry.internal/teams/{TEAM_NAME}/**` into `registry.internal/teams/**` and hand every
  namespace with no team every team's images — the single most damaging way this could be
  implemented, and the reason the rule is written down rather than left to whoever writes the
  substitution. It follows that an entry named in the top-level `default` that carries
  `{TEAM_NAME}` is a `Degraded` condition too: it can only ever grant nothing, so it is a mistake
  with no correct reading.
- **Only `{TEAM_NAME}` is permitted in the host.** The host is the trust anchor of the whole
  allow-list, and a variable there means the set of registries depends on data resolved per
  request. `{TEAM_NAME}` is permitted — `{TEAM_NAME}.registry.internal` is a real registry layout
  — because its value comes from `spec.teams`, which is the admin's own file and is validated
  once. There is no comparable statement about a namespace name, and emphatically none about an
  annotation.

**Braces need no escaping and there is no ambiguity**, because `{` and `}` are not legal in a
registry host, a repository path component, or a tag under the
[distribution grammar](https://github.com/opencontainers/distribution-spec). A brace in a pattern
is always a variable delimiter; a brace in a reference is always a parse failure, which is already
a denial. That is a property of the grammar rather than a convention we chose, so it cannot be
eroded by a later change to ours.

**What is deliberately not a variable:** the workspace name, the workspace id, and anything else
carried on the DevWorkspace. Those are chosen by the developer under any RBAC — a devfile is a
file in a repository — so a pattern interpolating one is an allow-list whose contents the person
it constrains gets to write, with no cluster configuration that fixes it. A namespace annotation
is different in exactly the way that matters: whether the developer can write it is a question
with an answer, and in this cluster the answer is no.

#### A pattern set is a union

The effective permission for one pod is the union of the patterns of every selected entry, plus
the platform set. An image is permitted if it matches any pattern in that union.

This is the same semantics [RFC 0004](./0004-network-profiles.md) argues for NetworkPolicy and it
has the same consequence: **there is no deny rule, and there cannot be one.** Selecting more
entries can only permit more. That is what makes the grant intersection the security boundary
rather than one input among several, and it is why an entry has no `except` field: an exception
inside a union is a rule whose meaning depends on which other entries happen to be selected,
which is a configuration nobody can review.

#### Resolution

For one subject, in this order — the same three scopes, same order, as `dwoc-pin` and
`network-profiles`:

1. **The team, and its grant.** Per the chassis: the first `spec.teams` entry whose selector
   matches the namespace. No team means `allowed` and `default` both come from the top-level
   `default`. A team with no grant here is the same case.
2. **The workspace attribute**, if set — the complete list, not an addition. A project may ask
   for fewer entries than its default, including none, which is how it drops a permission it does
   not need.
3. **The namespace annotation**, if set and the attribute is not.
4. **The grant's `default`.**

Whatever wins is intersected with `allowed`. Keys outside it follow `onNotGranted`: `Default`
drops them and applies the team default, `Deny` refuses with a message naming the ungranted key.
The platform set is added unconditionally at the end, and it is not a member of any `allowed`
set — asking for it is asking for something already permitted.

#### Two enforcement points, and the difference between them is deliberate

| | `DevWorkspace` webhook | `Pod` webhook |
| --- | --- | --- |
| Path | `/validate/v1alpha1/devworkspaces` | `/validate/v1/pods` |
| Images read | `spec.template.components[*].container.image` | `spec.containers[*]`, `spec.initContainers[*]`, `spec.ephemeralContainers[*]` |
| Entries enforced | the **resolved selection** — steps 1 to 4 above | the team's **whole `allowed` set**, plus platform |
| Error reaches | the developer, on their own `kubectl apply` | a ReplicaSet event |
| Sees plugin and injected images | no | yes |

**The second row of "entries enforced" is the one decision in this table.** The Pod half
enforces the team boundary rather than the per-workspace selection, and it does that so it needs
no DevWorkspace lookup at all: a pod carries `controller.devfile.io/devworkspace_id`, not the
selection attribute, and resolving the attribute from the id would mean a DevWorkspace watch in
the webhook role, new RBAC, a cache that scales with the fleet, and a startup race in which a
cold replica denies pods belonging to workspaces it has not observed yet.

**Variables resolve identically at both layers**, which is not a coincidence worth relying on
silently: every variable — the two built in and every declared one — derives from the subject's
namespace, and a `Pod` carries its namespace exactly as a `DevWorkspace` does. That is the reason
the variable set is namespace-sourced rather than workspace-sourced: a per-team or per-project
registry path is then enforced by the floor as well as by the readable error, and the row above is
the only thing the two layers disagree about.

What that costs is exactly one thing: a workspace running an image its team is granted but its
own selection excluded is not caught at the Pod layer. That is a policy nicety, not a security
boundary — the team boundary is intact, and the selection is enforced where it was authored, at
the `DevWorkspace`. What it buys is that this feature adds **zero** new RBAC and no new cache,
which is the property *Security considerations* leans on.

`spec.template.components[].plugin` and `spec.contributions[]` are **not** read. They name a
plugin by URI or id, DevWorkspace Operator resolves them to images long after admission, and a
resolver we wrote would be a second implementation of somebody else's resolution that is wrong
the day theirs changes. The Pod half sees the result, which is the honest place to check it.

#### Webhook configuration

Two `ValidatingWebhookConfiguration` objects, because their blast radii are not comparable and
one object carries one `namespaceSelector`.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: weebo-si-hardening-devworkspaces-validate
webhooks:
  - name: images.hardening.weebo.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    matchPolicy: Equivalent
    failurePolicy: Fail
    timeoutSeconds: 5
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: ["controller.devfile.io"]
        apiVersions: ["v1alpha1"]
        resources: ["devworkspaces"]
        scope: Namespaced
    namespaceSelector:                    # opt-OUT, per RFC 0002's dwoc-pin
      matchExpressions:
        - key: hardening.weebo.io/exclude
          operator: DoesNotExist
    clientConfig:
      service: {name: weebo-si-operator-webhook, namespace: weebo-si-hardening,
                path: /validate/v1alpha1/devworkspaces, port: 443}
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: weebo-si-hardening-pods
webhooks:
  - name: images.hardening.weebo.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    matchPolicy: Equivalent
    failurePolicy: Fail
    timeoutSeconds: 5
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods", "pods/ephemeralcontainers"]
        scope: Namespaced
    namespaceSelector:                    # opt-IN, per RFC 0004's policy-guard
      matchExpressions:
        - key: hardening.weebo.io/exclude
          operator: DoesNotExist
        - key: hardening.weebo.io/workspace-namespace
          operator: Exists
    clientConfig:
      service: {name: weebo-si-operator-webhook, namespace: weebo-si-hardening,
                path: /validate/v1/pods, port: 443}
```

Four values are decisions:

- **The two `namespaceSelector`s have opposite polarity, on purpose, and the split is the same
  one [RFC 0004](./0004-network-profiles.md) made.** Every `DevWorkspace` is a workspace by
  definition, so a namespace reached by accident is a namespace that got hardened — opt-out fails
  toward protected, exactly as `dwoc-pin` argues. A `Pod` is not: pods exist in every namespace
  in the cluster, and a mis-scoped deny-pods webhook is a cluster outage rather than an
  over-hardened namespace. The Pod half therefore requires a positive label, and which namespaces
  carry it is Che's to say. It goes on the install checklist, where `policy-guard` already put it.
- **`resources` includes `pods/ephemeralcontainers`.** `kubectl debug` adds a container through
  that subresource and never through `pods` `UPDATE`, so a rule listing only `pods` leaves a
  one-command bypass that is also the most convenient one available to anybody who already has
  workspace access.
- **`operations` includes `UPDATE` on `pods`.** `spec.containers[].image` is one of the few
  mutable fields on a running pod. `CREATE` alone would mean "start a permitted image, then patch
  it".
- **`failurePolicy: Fail` on both**, argued under *Operational considerations*, where the Pod
  half is the harder half of the argument.

**No `objectSelector` on the Pod rule.** Selecting only pods labelled as workspace pods would
mean a pod that omits the label is unchecked, and the label is user-writable. The namespace is
the boundary; the label is not.

#### CLI

Three additions to [RFC 0002](./0002-weebo-si-operator.md)'s table.

```text
weebo-si-operator images platform          # the compiled-in platform patterns
weebo-si-operator images check REF         # parse, normalize and judge one reference
                                           # [--team NAME] [--namespace NS]
weebo-si-operator images audit             # every image running now, and its verdict
                                           # [--namespace NS | --all-namespaces]
```

`audit` is to this feature what `canary` is to
[RFC 0004](./0004-network-profiles.md): the command that answers "is this safe to switch on"
before it is switched on. It uses the invoking kubeconfig rather than the operator's service
account, so listing pods cluster-wide is the admin's permission and never the operator's.

#### Observability contract

| Metric | Type | Labels |
| --- | --- | --- |
| `weebo_si_image_policy_total` | counter | `result` ∈ `allowed`/`denied`/`not_granted`/`unparseable`, `resource` ∈ `devworkspace`/`pod`, `team` |
| `weebo_si_image_policy_platform_total` | counter | `resource` — permitted only by the platform set |
| `weebo_si_image_policy_catalog_entries` | gauge | `state` ∈ `valid`/`invalid` |
| `weebo_si_image_policy_variable_total` | counter | `variable`, `result` ∈ `resolved`/`undefined`/`illegal` |
| `weebo_si_image_policy_variable_changed_total` | counter | `variable` |

**No metric carries an image reference as a label**, for the reason
[RFC 0004](./0004-network-profiles.md) gives for namespaces and workspace ids: the value is
unbounded and attacker-chosen, so a per-image time series is a metrics backend taken down by a
hardening component on purpose. The denied reference lives in the log line and in the API error,
which are the two places it is actually useful.

The `variable` label is the variable's *name*, never its value: names are written by an admin in
one file and are bounded by the same thing bounding that file's length, while a value is a
namespace annotation and is therefore unbounded — the same rule as the image reference, applied to
the other user-influenced string in this feature.

**`weebo_si_image_policy_variable_changed_total` is a detection control, not a diagnostic**, and it
is the answer to "how would we notice the RBAC assumption stopping being true". The controller
already watches namespaces; counting the times a bound annotation's value changes costs one
counter. If workspace users cannot annotate their namespaces, that counter moves only when an
admin edits one, which is rare and deliberate. A rate that is not rare is either a controller
nobody accounted for or a user doing exactly the thing the design assumes they cannot, and it
should page someone in the second case. *Operational considerations* carries the alert.

The reference also reaches a log line, and it is attacker-controlled text, so it is emitted as a
quoted, escaped, length-bounded field. A control that can be made to write arbitrary bytes into
an operator's log stream has traded one problem for another.

`image-policy` reuses the chassis's `weebo_si_admission_requests_total` with
`feature="image-policy"`, so its denial rate reads next to `dwoc-pin`'s and `policy-guard`'s on
one dashboard.

**Stability.** The feature identifier, its CRD fields, the pattern grammar, the variable names and
their substitution rules, the reference normalization rules, the attribute and annotation keys and their comma-separated grammar, the two
webhook paths, and the metric names are the contract. Changing one needs a new RFC, per
[the RFC process](./readme.md#when-is-an-rfc-required). The compiled-in platform pattern list is
explicitly **not** contract — it tracks Che and DevWorkspace Operator, and pinning it in a
document would guarantee it goes stale.

### Architecture

**Hexagonal, and it needs no new chassis trait.** Against the three criteria in
[`../architecture/hexagonal.md`](../architecture/hexagonal.md):

1. *A real decision.* A reference parser with a normalization table, a pattern matcher over four
   fields, a three-scope resolution chain, a grant intersection, a non-negotiable platform set,
   and two enforcement points that deliberately compute different answers.
2. *Touches an external system.* Two admission paths, two resource types.
3. *We want the decision tested without it.* This is the strongest case in the repo. The parser
   and the matcher are pure functions over strings whose failure mode is a silent bypass, and
   they should be tested by the hundred, in milliseconds, with no cluster anywhere near them.

**`Feature<S>` already covers this, and that is worth stating.**
[RFC 0004](./0004-network-profiles.md) needed a second trait because a reconcile feature returns
objects that belong somewhere else. A validating feature does not: it returns a `Decision<S>`
with `denial: Some(..)` and no mutations, which is what `policy-guard` already does. So this RFC
adds no trait, and it gets the mode invariant for free — **`DryRun` on a validating feature is
"who would I have denied", computed by the identical code path that will deny them.** That is the
entire rollout story, and it exists because a feature cannot tell `DryRun` from `Enforce`.

What it does add is the first entry in a registry [RFC 0002](./0002-weebo-si-operator.md)
scaffolded and left empty: `Registry<PodImages>`, the first `Feature` over a subject that is not
a `DevWorkspace` or one of our own objects, and the first webhook route on a core resource.

**Lands as its own crate, beside `weebo-si-dwoc-pin` and `weebo-si-network-profiles`**, depending
on `weebo-si-crd` + `weebo-si-chassis` only — the same "fewest dependencies, tested exhaustively
without a cluster" rule both of them state for themselves.

```text
crates/weebo-si-image-policy/src/
├── lib.rs                    # crate root — mirrors weebo-si-network-profiles/src/lib.rs
├── reference.rs              # parse + normalize. Pure, and the whole security surface.
├── pattern.rs                # Pattern parse + variable substitution + per-field match. Pure.
├── variable.rs               # the closed variable set, and the value validator
├── platform.rs               # the compiled-in platform pattern set, and nothing else
├── resolve.rs                # the three-scope chain, the grant intersection, the union
├── verdict.rs                # Verdict: Permitted{by} | Denied{reason} | Unparseable
├── subject.rs                # WorkspaceImages, PodImages — the two bounded projections
└── feature/
    ├── workspace_images.rs   # Feature<WorkspaceImages> — the selection-precise half
    └── pod_images.rs         # Feature<PodImages> — the team-boundary floor

crates/weebo-si-crd/src/
└── image_policy.rs           # ImagePolicyConfig, Entry, PlatformConfig, validate()

crates/weebo-si-runtime/src/
└── image_metrics.rs          # the three weebo_si_image_policy_* metrics

crates/weebo-si-webhook/src/
└── image_policy.rs           # the two routes, AdmissionReview -> subject -> allow/deny
```

`Entry` and its `patterns` live in `weebo-si-crd` rather than in a `model/` module, per the
amendment [RFC 0004](./0004-network-profiles.md) recorded for `Profile`: where the CRD struct
tree *is* the domain model, there is no second copy of it.

The two subjects are this feature's own bounded projections, following the pattern
`weebo-si-dwoc-pin`'s `Workspace` and `weebo-si-network-profiles`' `WorkspaceAdmission`
established — a `Subject` is what one feature is entitled to see, not a shared type every feature
widens:

```rust
// crates/weebo-si-image-policy/src/subject.rs
pub struct WorkspaceImages {
    pub name: String,
    pub namespace: NamespaceName,
    /// (component name, raw reference) — the reference is not parsed here; the adapter must
    /// hand the domain exactly what the user wrote, or normalization happens twice.
    pub images: Vec<(String, String)>,
    /// The workspace's own selection attribute, if it carries one.
    pub attribute: Option<String>,
    /// The namespace annotation, read through `NamespaceView::annotation`.
    pub namespace_annotation: Option<String>,
}

pub struct PodImages {
    pub name: String,
    pub namespace: NamespaceName,
    /// (container name, raw reference), across all three container lists. Which list a
    /// container came from is not carried: the verdict does not depend on it, and the name
    /// is what the error message needs.
    pub images: Vec<(String, String)>,
    /// Already-resolved variable values for this namespace, keyed by variable name. Not a raw
    /// annotation bag: the adapter reads only the keys `spec.variables` declared, and validates
    /// each value before it lands here — so an illegal one is absent rather than present and
    /// dangerous.
    pub variables: BTreeMap<VariableName, PathComponent>,
}
```

**`PodImages` carries no selection attribute and no selection annotation**, which is the
type-level statement of the "team boundary, not selection" decision above. It gained `variables`
when declared variables did, and the distinction is worth being precise about rather than letting
the earlier claim quietly become false: `variables` is a resolved, validated, admin-declared map,
and there is still no field a later change could start reading a *workspace's selection* from.
Both subjects carry the same map, populated by the same adapter code, which is what makes
"variables resolve identically at both layers" a consequence of the types rather than a promise.

**Substitution is typed, which is how the "after parsing, into one slot" rule is enforced rather
than remembered.** A parsed pattern holds `Vec<Segment>` where `Segment` is
`Literal(String) | Glob(..) | Var(Variable)`, and `Variable` resolves to a `PathComponent` — a
newtype whose only constructor validates the charset and returns `Err` otherwise. There is no
function anywhere in the crate taking a pattern and a `&str` and returning a pattern, so the
string-substitution version of this feature cannot be written by accident. The compile-time
statement is worth more than the paragraph in *Contract*, because the paragraph is what a later
change forgets.

**The parser is the thing to review, and it owns no `k8s-openapi` type.** A reference is a
string in the domain and a string in the adapter; the domain never sees a `Container`, a `Pod`,
or a `DevWorkspace`. That keeps the crate's dependency list at two, and it means the test suite
for the part that can be catastrophically wrong is a table of `(input, normalized, verdict)`
triples with no fixtures.

`NamespaceView::annotation(ns, key)` — the general form the chassis already grew when
`network-profiles` needed a second annotation key — is what the namespace scope reads. No chassis
change is needed for a third key, which is what that method was added for.

### Data and state

**Stateless, and more so than any feature in the repo so far.**

Nothing is cached that is not already cached. The subject arrives in the admission request — the
`DevWorkspace` and the `Pod` both — and the only lookup is the namespace, through
[RFC 0002](./0002-weebo-si-operator.md)'s existing `NamespaceFacts` cache. There is no image
cache, no registry client, no manifest fetch, and no network call of any kind in the admission
path: **this feature never contacts a registry.** It judges names, and names are in the request.

That is a deliberate boundary rather than a simplification. Contacting a registry from admission
would make the decision depend on a third party's availability, put an attacker-supplied
hostname into an outbound connection from the operator's pod, and turn a five-millisecond
verdict into a network round trip in front of every pod creation in a workspace namespace. What
that costs is that the control is over names, not over content — stated plainly under *Drawbacks*.

`WeeboSiConfig.status` gains one more feature entry, derived from `spec` as the others are, and
the parsed catalogue lives behind the same `Arc<RwLock<Option<..>>>` hot-reload `dwoc-pin` uses.
Patterns are parsed once at config load, not per request; a pattern that fails to parse is what
raises `Degraded` and drops its entry.

There is nothing to migrate, nothing to back up, and no object this feature writes. The undo is
`mode: Off`.

## Security considerations

**Privileges. This feature adds none.** No new verb, no new resource, no new `Role`, no new
`ClusterRole` rule, in either role. [RFC 0004](./0004-network-profiles.md) is where the operator
gained write verbs and a `Role` for the canary; this one gains nothing at all, because both
subjects arrive in the admission body and the only cache it reads already exists. The `audit`
CLI's `list pods` is the admin's own permission, exercised from their kubeconfig.

That is worth stating as a property rather than an absence: **the role an untrusted
`AdmissionReview` body reaches is unchanged by this RFC.**

**Trust boundary.** The webhook body is attacker-controlled and this RFC parses more of it than
any previous feature does. Concretely: an image reference is an arbitrary user-supplied string
that our own parser tokenizes. Three rules follow, and they are the reason the parser is the
review target:

- **Parse failure denies.** Never allow, never pass through, never fall back to string
  comparison. There is no knob.
- **No unbounded work.** A reference is length-capped before parsing, the parser is
  non-backtracking, and pattern matching is linear in the pattern and the input. A glob engine
  with backtracking in an admission path at `failurePolicy: Fail` is a denial of service against
  the whole cluster's pod creation, delivered as a long image name.
- **No reflection without escaping.** The reference reaches an API error message and a log line.
  Both escape and length-bound it.

**Interpolation is a second input to the matcher, and it is the one that is easy to get wrong.**
The reference is obviously attacker-controlled and gets treated as such; a variable's *value* is
not, and that is exactly why it deserves saying. `{TEAM_NAME}` comes from `spec.teams`, so its
trust level is the admin's file — but "admin-written" is not "safe to substitute", because an
admin who names a team `a/**` has widened every pattern using it without doing anything that looks
like a security change. `{NAMESPACE}` comes from the apiserver's own DNS-1123 validation, which is
the strongest guarantee available to any value in this RFC. Both are validated at the same gate
anyway, both fail closed, and the typed constructor in *Architecture* is what makes "validated"
mean "unconstructible otherwise".

**A declared variable is the one place this feature's strength depends on the cluster's RBAC, and
it is worth reading rather than skimming.** Its value is a namespace annotation. In the Che
installation this repo targets a workspace user cannot annotate their own namespace, so the value
is admin-controlled and `registry.internal/projects/{PROJECT}/**` is a real allow-list. Where that
is not true, the same configuration is an allow-list the constrained party fills in — and, unlike
most degradations in this repo, it degrades *silently*: every verdict still reads `allowed`, no
condition is raised, and nothing about the CRD looks different. Four things carry that risk rather
than one:

- **Declaring `variables` is the opt-in.** A cluster that never writes the field never has the
  dependency, and neither built-in carries it.
- **The RBAC question is on the install checklist with a command next to it**, not an assumption
  buried in a paragraph — the same treatment [RFC 0004](./0004-network-profiles.md) gives
  `policy-guard`, where "which cluster am I in" is the first line rather than a footnote.
- **The value is validated identically to the admin-written ones**, so even where a user *can*
  write the annotation, they can write one path component and not a wildcard. The failure is
  "reaches another project's path", not "reaches every registry".
- **A change to a bound annotation is counted**, per *Observability contract*, so the day the
  assumption stops holding is a metric moving rather than a silence.

The values a workspace user controls under *any* RBAC — the workspace name, the workspace id,
anything carried on the DevWorkspace — are not in the variable set at all, and *Contract* records
why a namespace annotation is a different question rather than the same one.

**Bypass.** The list, honestly:

| Route | Covered |
| --- | --- |
| patch the image onto an existing `DevWorkspace` | yes — `UPDATE` is in the rule |
| patch the image onto a running pod | yes — `UPDATE` on `pods` |
| `kubectl debug` an ephemeral container in | yes — `pods/ephemeralcontainers` is in the rule |
| a `Deployment`/`Job`/`CronJob` in a workspace namespace | yes at the pod, with a poor error |
| a plugin resolved to an image by DWO after admission | yes at the pod, never at the `DevWorkspace` |
| a team named `a/**`, widening every pattern that interpolates it | yes — validated as one path component, `Degraded` otherwise |
| a namespace with no team reaching a `{TEAM_NAME}` pattern | yes — an undefined variable matches nothing |
| an annotation value carrying `/` or `*`, widening a declared variable | yes — same validator; the variable goes undefined |
| a user annotating their own namespace to reach another project's path | **only if they can annotate it** — the RBAC dependency above |
| a mutable tag repointed after the reference was permitted | **no** — see *Drawbacks* |
| a permitted registry that proxies an unpermitted one | **no** — see *Drawbacks* |
| a namespace missing `hardening.weebo.io/workspace-namespace` | **no** — the pod half never sees it |
| a workspace running before the webhook was installed | **no** — admission is not retroactive |
| an image its team allows but its own selection excluded | **no**, by design — see *Contract* |

The last three are the same class [RFC 0002](./0002-weebo-si-operator.md) and
[RFC 0004](./0004-network-profiles.md) already carry, and the same answer applies: the labelling
is on the install checklist, and drift reconciliation for objects that predate installation is
named in *Future work* in all three RFCs and belongs to a controller rather than to admission.

**The platform set is a standing exemption, and it is scoped as narrowly as an exemption can be.**
It is a list of patterns, compiled in, over registries and repositories the platform team already
trusts to run in every workspace pod today. It is not an identity exemption and it is not a
namespace exemption. `platform.builtin: false` turns it off for an admin who has mirrored
everything, and `platform.extra` is how they name the mirror.

**Why identity-based exemption was rejected outright**, since it is the obvious alternative and it
is worth closing here rather than only under *Alternatives*: DevWorkspace Operator creates a
`Deployment`, so the workspace pod is created by `system:serviceaccount:kube-system:replicaset-controller`,
not by DWO. An exemption keyed on the creating identity would therefore either not fire at all,
or — if written to cover the replicaset controller — exempt every pod in the cluster created
through any controller, which is nearly all of them. The exemption has to be over image names
because the identity carries no signal.

**Blast radius, if this brick misbehaves.** At `Enforce` with `failurePolicy: Fail`, a bug that
denies too much stops pod creation in every namespace carrying the workspace label. That is the
largest blast radius of any brick in this repo, larger than
[RFC 0004](./0004-network-profiles.md)'s, and it is the reason the Pod half requires a positive
namespace label rather than inheriting `dwoc-pin`'s opt-out. Running pods are untouched — this is
an admission control, not a runtime one — so the failure is "nothing new starts", not "everything
stops".

**Secrets.** None are read. `imagePullSecrets` are not inspected, registry credentials are never
held, and no outbound connection is made. The only attacker-influenced value that reaches a log
is the image reference, escaped and bounded per the rule above.

## Operational considerations

**Failure mode: `failurePolicy: Fail` on both, fail-closed.** The `DevWorkspace` half is the easy
case and [RFC 0002](./0002-weebo-si-operator.md) already argued it: the blast radius is workspace
creation and start, a control whose bypass is "cause an error" is not a control, and the cost is
paid down with two replicas, a `PodDisruptionBudget` and an admission path that makes no API call.

**The `Pod` half is the harder argument and deserves its own paragraph.**

*For `Ignore`.* At `Fail`, an unavailable operator means no pod is created in any workspace
namespace. Not just no new workspace — no *rescheduling*. A node drains and its workspace pods do
not come back until the operator does. That is a strictly worse outage than the `DevWorkspace`
half's, because it fires on cluster events nobody initiated.

*For `Fail`.* At `Ignore`, the bypass is two steps: make the webhook unavailable, create the pod.
Worse, the `Pod` half exists *specifically* to catch what the `DevWorkspace` half cannot see —
plugin-resolved and injected images. A floor that can be removed by causing an error is not a
floor, and running it at `Ignore` while telling an admin their images are constrained would be
the most misleading thing in this repo.

*The decision.* `Fail`, with the cost paid down in three ways the `DevWorkspace` half does not
need. The webhook role is scaled for pod-creation volume rather than workspace-creation volume,
which is a different number and is measured at step 1 of the rollout below. `timeoutSeconds: 5`
with no API call and no registry call in the path, so the verdict cannot be slowed by anything
outside our own process. And the positive `namespaceSelector`, so the set of namespaces that
stop creating pods is the set someone deliberately labelled.

**Rollout.** Six steps, each independently reversible. Step 0 is the one that does not exist for
any other feature in this repo and it is the most valuable one.

0. **`weebo-si-operator images audit --all-namespaces`, before installing anything.** Every image
   running in the fleet, with the verdict the draft configuration would give it. This is where a
   catalogue is written — from what is actually running — rather than guessed and then discovered
   one denial at a time.
1. Install the webhook configurations with `spec.features: {}`. Nothing changes beyond a no-op
   round trip; watch `weebo_si_admission_duration_seconds` for `resource="pod"` specifically,
   because pod volume is not workspace volume and this is the step that proves `Fail` is
   survivable on the busier of the two resources.
2. `mode: DryRun`, catalogue and `default` written, **no teams**. The number that matters is
   `weebo_si_image_policy_total{result="denied"}` — every one is a workspace that will stop
   starting. `platform_total` is the second number: if it is large, the platform list is doing
   more work than expected and deserves a look before it is depended on.
3. **Add `spec.teams` and the grants, still in `DryRun`.** `result` broken down by `team` is how
   an admin confirms the routing, exactly as in [RFC 0002](./0002-weebo-si-operator.md)'s step 3.
   A namespace routed to the wrong team is invisible in aggregate and obvious per team.
4. `mode: Enforce` with a `namespaceSelector` on a pilot label. One namespace, real denials.
5. Remove the selector.

Steps 2 through 5 are writes to one resource, effective on the next admission, with no rollout.

**Rollback.** Four levels:

- `mode: Off` — seconds, no restart. Both webhooks still answer, and answer `allowed`.
- **Widen the grant or add a catalogue entry** — the surgical undo, and the one that fits the
  most likely incident, which is not "the feature is broken" but "one team needs one more image".
- **Delete the `ValidatingWebhookConfiguration`s** — the break-glass, and at `failurePolicy: Fail`
  the only lever that works when the operator itself is the broken thing. It belongs in the
  runbook, and for the Pod half it is the difference between a bad afternoon and a cluster whose
  workspaces cannot be rescheduled.
- Uninstall.

Unlike [RFC 0002](./0002-weebo-si-operator.md), **rollback here restores the state as well as the
policy**, because this feature writes nothing. There is no fleet of pinned workspaces to unpick;
the pods that were denied were never created, and the pods that exist were never modified.

**Observability.** `weebo_si_image_policy_total{result="denied"}` is the first alert, and at
`Enforce` a nonzero rate is user-visible failure — either a real policy hit or a catalogue that is
missing something. Broken down by `resource`, it says which: `devworkspace` denials are developers
naming images, `pod` denials are the platform, and a spike in `resource="pod"` with no
corresponding `devworkspace` movement is the signature of a Che upgrade that changed an injected
image. `result="unparseable"` is the second, and it should be flat at zero forever; a nonzero rate
is either a client we have never seen or someone probing the parser.
`weebo_si_image_policy_variable_changed_total` is the third, and it is the only alert in this repo
that watches an *assumption* rather than a behaviour: where `variables` is declared, a bound
annotation changing is either an admin doing something deliberate or a workspace user doing
something the design assumes they cannot. Alert on the rate, expect it to be zero between admin
edits, and treat a sustained one as an RBAC regression to go and verify with the checklist command
rather than as a metrics problem. `variable_total{result="illegal"}` sits next to it: a value that
failed the path-component validator is someone writing something that is not a project name. `catalog_entries{state="invalid"}`
is the third, and it is the configuration-side view: it fires on a pattern that stopped parsing
after an edit, even in a team whose workspaces nobody has restarted. A `Degraded` condition on the
CRD carries the reason. From the apiserver side,
`apiserver_admission_webhook_rejection_count` for `images.hardening.weebo.io` is the ground truth,
and it belongs on the dashboard next to ours because ours cannot report a request that never
arrived.

**Upgrade.** Two replicas behind a `PodDisruptionBudget`, rolling, `maxUnavailable: 0` — at `Fail`
on `pods`, a moment with no ready endpoint is a moment when nothing schedules in a workspace
namespace. Old and new pods compute independently from their own watches and the verdict is a
pure function of the request plus the config, so a mixed fleet is safe by construction rather
than by idempotence. Within `v1alpha1` the CRD only grows fields.

**The upgrade that actually breaks this is Che's, not ours.** The compiled-in platform set tracks
DevWorkspace Operator and che-code. A Che upgrade that changes an injected image is, at `Enforce`,
a fleet that stops starting — and it is the single most likely operational failure of this
feature. Three mitigations, in order: `images audit` is run before a Che upgrade as well as before
installation, and it names the new image before anything is applied; `platform.extra` is the
one-line fix that needs no operator release; and the denial is loud in a metric that is otherwise
flat. That sequence belongs in the runbook.

**Self-deadlock.** The operator is not a workspace and its namespace carries neither the
`workspace-namespace` label the Pod rule requires nor a `DevWorkspace`. It cannot deny its own
pods. This is stronger than [RFC 0002](./0002-weebo-si-operator.md)'s equivalent — there the
exclusion label is redundant belt-and-braces, here the Pod rule's positive selector means the
operator's namespace is out of scope structurally.

## Alternatives considered

**Do nothing.** The status quo is "any image, any registry, any workspace". Rejected because
[RFC 0002](./0002-weebo-si-operator.md) already committed to closing it and named this RFC as
where. It is worth recording what "do nothing" actually costs, though: nothing else in this repo
constrains what code runs in a workspace, only where it can reach once it does.

**Kyverno or Gatekeeper.** The strongest alternative, and it would be dishonest to dismiss it
quickly. Kyverno ships tested registry-restriction policies, a reference parser far more
exercised than one we write this month, and `imageVerify` for signature checking we do not have.
For a cluster that already runs Kyverno, "add a policy" is a smaller change than "add a feature to
an operator".

Three things decide against it here, in order of weight. **The routing.** This feature's value is
per-team entitlement resolved through `spec.teams`, which the other two features already use; in
Kyverno that becomes one policy per team, each carrying its own copy of a namespace selector, with
nothing reporting the day they diverge from `spec.teams` — the exact failure
[RFC 0002](./0002-weebo-si-operator.md) rejected per-feature team lists to avoid. **The
workspace scope.** The per-workspace attribute has no Kyverno equivalent that does not amount to
writing our resolution chain in JMESPath. **The second engine.** A cluster that does not already
run Kyverno would install one, with its own admission webhooks at their own `failurePolicy`, to
express one rule.

The condition under which this reverses is worth writing down: if a future feature needs image
*content* verification — signatures, attestations, SBOM policy — that is Kyverno's or Sigstore's
job and not ours, and at that point the registry allow-list should move there with it rather than
being maintained in two places.

**OpenShift's `image.config.openshift.io/cluster`.** Already in the cluster, needs no code, and
blocks at the pull. Rejected on granularity: it is cluster-wide, so the union of every team's
needs becomes every team's permission, which is the "per project, not per user" argument
[RFC 0004](./0004-network-profiles.md) makes about network reachability, restated for images. It
also fails as `ImagePullBackOff` with no policy explanation, and it does not exist off OpenShift.
It remains a good *second* layer and the two do not conflict.

**Mutate instead of validate — rewrite the registry to an internal mirror.** Tempting, because it
turns a denial into a success. Rejected: it runs different bytes than the devfile asked for,
silently, and the failure mode when the mirror is stale or incomplete is a workspace running
something nobody chose. [RFC 0002](./0002-weebo-si-operator.md) chose mutation for `dwoc-pin`
because a config reference has one correct value the admin owns; an image reference does not.

**Identity-based exemption for platform images.** Rejected on a fact rather than a preference:
the workspace pod's creator is the replicaset controller, so the identity carries no signal about
whether the image is platform or user. Argued in full under *Security considerations*.

**A closed set of built-in variables, with no admin-declared ones.** The conservative version:
`{TEAM_NAME}` and `{NAMESPACE}` and nothing else, on the grounds that both are unreachable by a
workspace user under any RBAC while an annotation's writability is a cluster property this RFC
does not control.

It was the first draft of this section and it is rejected, because the boundary it draws is not
where the risk is. The two built-ins cover "a registry laid out per team", and they do not cover
"per project" — and a namespace-per-user Che topology means a project is exactly the thing a team
name cannot express. Declining the general form would not make that requirement go away; it would
push it into one catalogue entry per project, which is the duplication *Motivation* argues against,
with a list that drifts from whatever actually defines a project.

The decision instead: ship it, and make the dependency explicit rather than implicit. Declaring
`variables` is the opt-in, the RBAC question goes on the install checklist with a verification
command, the value passes the same typed validator as an admin-written one, and a change to a
bound annotation is counted so the assumption is monitored rather than trusted. That is the shape
[RFC 0004](./0004-network-profiles.md) uses for `policy-guard` — same code, two very different
importances, and the install decides which cluster it is in — and it is a better answer than
withholding the feature from the clusters where it is safe.

**Interpolating by string, before parsing.** The one-line implementation, and the reason
*Contract* and *Architecture* both pin the alternative. `format!` the value into the pattern text
and parse the result, and a team named `a/**` silently widens every pattern using it while the CRD
still reads `registry.internal/teams/{TEAM_NAME}/**`. Rejected for the same reason flat-string
globbing is: the pattern an admin reviews stops being the pattern that runs.

**One flat glob over the whole reference string.** The obvious implementation, and the reason
*Contract* spends a table on normalization. `registry.internal/**` against a raw string does not
match `REGISTRY.INTERNAL/x`, matches `registry.internal.evil.com/x` under some glob dialects, and
gives no defensible answer for the `:` in `host:5000/repo:tag`. Rejected for the same reason
[RFC 0004](./0004-network-profiles.md) refuses to parse network rules: a matcher that is subtly
wrong is a security bug that looks like a working control.

**Registry allow-list only, with no repository or tag patterns.** Nothing to get wrong in the
matcher, which is a real argument. Rejected because "quay.io, but only devfile's images" is the
most common request an admin actually has, and a control that cannot express it gets configured
as "quay.io" and stops meaning anything.

**Enforce through credentials — give workspaces pull secrets only for the internal registry.**
Complementary, and it belongs in the install checklist. Not a control: public registries need no
credentials, so it constrains only the registries that were already authenticated.

## Drawbacks and risks

**It is a control over names, not over content, and that gap is not small.** A permitted
`quay.io/devfile/udi:ubi9-latest` says nothing about what those bytes are today. Anyone who can
push that tag has pushed into every workspace that uses it, and this feature will report
`allowed`. The honest framing: this closes "run something nobody catalogued", not "run something
that changed under you". `requireDigest` in *Future work* is the first half of an answer and
signature verification is the second, and the second is Kyverno's or Sigstore's job.

**A pull-through cache makes the allow-list a superset of what it appears to be.** If
`registry.internal` proxies Docker Hub, `registry.internal/**` permits Docker Hub through a name
that looks internal. Nothing in this feature can detect that, and an admin whose registry does
this needs a narrower path pattern rather than a host pattern. It belongs in the install
checklist, and it is the most likely way for this control to be believed while doing nothing.

**A pattern that interpolates is not reviewable by reading the CRD.** `registry.internal/teams/{TEAM_NAME}/**`
means something different in every namespace, so "what may this team run" stops being a property
of the configuration and becomes a question with a namespace-shaped argument. That is the cost of
not restating `spec.teams` in the catalogue, and it is paid in tooling rather than absorbed:
`images check` prints the interpolated pattern, `images audit` reports per namespace whenever
verdicts differ, and the *Future work* item on rendering effective permission exists mostly
because of this. An admin who does not want the trade writes literal entries and nothing forces
them not to.

**A declared variable makes one line of this control depend on a cluster property we do not
enforce.** Everything else in this RFC holds whatever the cluster's RBAC says; a pattern
interpolating a namespace annotation holds only while workspace users cannot write that
annotation. It is opt-in, validated, checklisted and monitored — but it is the one place where an
RBAC change elsewhere quietly reduces this feature's strength without anything in this feature
looking different, and that is worth a reviewer's attention rather than a footnote.

**A parser we now own.** Reference normalization is a small parser with a long tail of cases, and
a bug in it is a bypass rather than a crash. Mitigated by denying on parse failure, by testing it
as a table rather than through fixtures, and by exposing it through `images check` so its answers
are inspectable rather than inferred — but it is real, and it is the part of this RFC to review
hardest.

**Admission on `pods` is new latency on the busiest resource in the cluster.** The positive
namespace selector bounds it to workspace namespaces, the verdict makes no API call, and the
parse is linear — but this is the first time this repo puts itself in front of pod creation, and
the honest statement is that step 1 of the rollout exists to measure it rather than to assume it.

**Coupling to Che's release cadence.** The platform list tracks somebody else's images. This is
the maintenance cost the feature carries forever, it is paid on every Che upgrade, and
`platform.extra` exists so that paying it does not require an operator release.

**A poor error message at the Pod layer**, for exactly the images the developer did not choose.
Mitigated in the only way available: the good message fires first for everything the developer
did write, so a Pod-layer denial is a signal that an admin needs to look, not a developer.

## Unresolved questions

**Resolved before implementation**, and left here rather than deleted, because both answers are
now load-bearing in the chart and neither is obvious from reading it:

- ~~**Is `failurePolicy: Fail` on the `pods` webhook acceptable to whoever operates this
  cluster?**~~ **Settled the way [RFC 0004](./0004-network-profiles.md) settles `policyGuard`'s:
  one manifest, one `values.yaml` switch (`imagePolicy.podWebhook.failurePolicy`), `Fail` by
  default.** The argument in *Operational considerations* lands on `Fail` — the Pod half exists
  specifically to catch what the `DevWorkspace` half cannot see, and a floor removable by causing
  an error is not a floor — and the switch is what keeps `Ignore` a deliberate install decision
  rather than a fork of the chart. The `DevWorkspace` webhook has no such switch and is hard-coded
  to `Fail`: RFC 0002 already settled that argument, and there is no cluster for which the answer
  differs. The cost of `Fail` on `pods` is the first line of the install checklist rather than a
  paragraph someone has to find.
- ~~**Which label marks a workspace namespace**~~ — **`hardening.weebo.io/workspace-namespace`,
  the same label [RFC 0004](./0004-network-profiles.md)'s `policy-guard` already requires.** This
  RFC always said the answer was shared with that one; making it the *same string* rather than a
  parallel decision means one checklist line covers both webhooks, and a cluster that labelled its
  namespaces for `policy-guard` has already labelled them for this. Whether Che applies it
  automatically is still that installation's question, and it is on the checklist with the
  consequence spelled out: a namespace missing it is a namespace the floor never sees.

**Non-blocking:**

- Whether the per-workspace `attribute` scope is worth having at all here. It is kept for symmetry
  with the other two features, and the argument for it is weaker: a project needing a different
  *image* is a more visible act than a project needing a different network profile, so the
  namespace scope may be sufficient in practice. Deciding to drop it later is a contract change
  and therefore an RFC; deciding now saves that.
- Whether the platform set should be **discovered** at install — `images audit` already sees every
  injected image — rather than compiled in. Discovery would end the Che-coupling drawback and
  would introduce a worse one: a set derived from what happens to be running, including whatever
  is running that should not be.
- Whether `default` for a namespace with no team should be required, as written here, or default
  to empty. Required is chosen so the no-team case is an admin's decision rather than a policy
  hiding in the chassis, per [RFC 0002](./0002-weebo-si-operator.md)'s rule.

## Future work

- **`requireDigest` per catalogue entry**, so a mutable tag cannot be repointed under a permitted
  reference. The largest single improvement available to this feature and a fleet-wide devfile
  rewrite, which is why it is a decision of its own rather than a field added here.
- **Variable values from a source that is not a namespace annotation** — a label, or a field on a
  Che `CheCluster`/user object — for a cluster that wants the per-project split without depending
  on annotation RBAC at all. `fromNamespaceAnnotation` is deliberately the only binding shipped,
  so the surface stays one thing rather than a small language.
- **`{WORKSPACE_NAME}` and `{WORKSPACE_ID}`**, explicitly declined rather than merely absent, and
  kept here so the idea is not rediscovered as new. Both are chosen by the developer, so a pattern
  interpolating one is an allow-list the constrained party fills in. `{WORKSPACE_ID}` is
  additionally unavailable at `DevWorkspace` admission, since DevWorkspace Operator assigns it
  afterwards — the two enforcement points would disagree, which is worse than not having it.
- **Signature and attestation verification.** Explicitly not ours — see *Alternatives*, where the
  condition for handing this whole feature to Kyverno is written down.
- **Resolving the per-workspace selection at the Pod layer**, via a DevWorkspace watch in the
  webhook role, closing the one deliberate gap in the two-enforcement-point table. It costs new
  RBAC, a fleet-scaled cache and a startup race, and it buys a policy nicety, so it waits until
  somebody wants it.
- **Drift reconciliation** for workspaces running since before installation, closing the
  "created before the webhook existed" gap with a controller rather than with admission. The same
  item is open in [RFC 0002](./0002-weebo-si-operator.md) and
  [RFC 0004](./0004-network-profiles.md); it should be built once, for all three.
- **Validating the plugin registry** rather than the images it resolves to, so a devfile importing
  a plugin by URI can be refused at the `DevWorkspace` layer with a readable error instead of at
  the pod.
- **A validating webhook on our own CRD**, so a catalogue with an unparseable pattern is rejected
  at write time rather than reported as `Degraded` afterwards. Shared with
  [RFC 0002](./0002-weebo-si-operator.md)'s *Future work*.
- **Reporting effective permission** — "which images may this team run" as a rendered answer
  rather than a catalogue an admin intersects by hand.

## Implementation plan

- [x] `crates/weebo-si-image-policy` scaffolded (`Cargo.toml` depending on `weebo-si-crd` +
      `weebo-si-chassis` only, picked up by the workspace's `crates/*` glob), mirroring
      `crates/weebo-si-network-profiles`
- [x] `reference.rs`: parse and normalize, with the *Contract* table as its test table
      (`the_rfcs_normalization_table_is_executable`). Length cap, single forward pass, denies on
      failure. Three decisions the RFC left implicit and the code had to make explicit: a
      reference carrying a digest reports `tag() == None` **whatever tag it was written with**
      (so `dev:v1@sha256:…` and `dev@sha256:…` behave identically, which is the fail-closed
      reading of "the tag is decoration"); an uppercase repository path is a *parse failure*
      rather than something to case-fold (folding would make two distinct references compare
      equal to one pattern); and the fields are private with accessors rather than `pub`, so the
      only way to obtain an `ImageReference` is through the normalizer. A `parsing_is_idempotent_
      over_its_own_output` test pins the fixed point, since a normalization that is not one is
      exactly the gap a bypass lives in
- [x] `pattern.rs`: parse and per-field match, including the `*.suffix` host form and the
      rejection of a bare `*` host. The property test the plan asked for is
      `a_pattern_never_matches_a_reference_whose_normalized_host_differs`, run over the cross
      product of the catalogue-shaped patterns and references the suite already uses.
      **Writing the tests found two real bugs before any of this ran anywhere**, both of the
      "looks like a working control" class this RFC is shaped against: `*/**` parsed, because a
      bare `*` in the first position has no dot and no port and so fell through the host/path
      split into `docker.io/*/**` — an admin writing "any registry" got a very large Docker Hub
      allow-list instead of the refusal *Contract* promises; and `registry.internal/-dev` parsed
      while being unable to match anything, because a wholly-literal segment was only checked at
      *match* time, so a pattern that could never work was invisible rather than `Degraded`.
      Both are now parse-time refusals with their own tests
- [x] `variable.rs`: the built-ins, the declared-variable binding, the reserved names, the
      `PathComponent` newtype whose only constructor validates, and `Segment::Var`. The
      compile-time half of *Architecture*'s claim is structural rather than a textual test —
      there is no function in the crate taking a pattern and a `&str`, because substitution
      resolves `Var` to a `PathComponent` inside the matcher and `PathComponent` has no
      `From<String>`, no `Deref<Target = str>` and no public field
- [x] `pattern.rs`: substitution into a parsed `Segment`, `{TEAM_NAME}` permitted in the host and
      nothing else, and an undefined variable matching nothing —
      `an_undefined_variable_matches_nothing_rather_than_collapsing_the_segment` is the test for
      the single most damaging way this could have been implemented. Table tested with a team
      named `a/**`, a team named `Team One`, a namespace with no team, a missing annotation, and
      an annotation valued `../other-project`
- [x] The declared-variable adapter — **in `weebo-si-image-policy`, not `weebo-si-runtime` as the
      plan sketched.** It needs only `NamespaceView` (a chassis port) and this crate's own
      observer port, both of which the domain already knows, and putting it in an adapter would
      have meant the `DevWorkspace` route and the `Pod` route each calling their own copy — two
      implementations that can drift, of the one thing this RFC calls a property rather than a
      promise ("variables resolve identically at both layers"). `variable::resolve_declared`
      reads only the declared keys, validates each value, and yields an absent entry for an
      illegal one while raising no CRD condition, tested by
      `an_illegal_value_yields_an_absent_entry_and_raises_no_condition`
- [x] `weebo-si-crd/src/image_policy.rs`: `ImagePolicyConfig`, `Entry`, `PlatformConfig`, and
      `validate()`. **Split across two crates, because the dependency direction forces it**:
      `weebo-si-crd` cannot call `Pattern::parse` (it is `weebo-si-image-policy`'s dependency,
      not the reverse), so `ImagePolicyConfig::validate` proves everything *structural* and
      `weebo_si_image_policy::validate` calls it and appends the parse-dependent half. Both
      produce the same `ImagePolicyConfigViolation`, which lives in the CRD crate so neither half
      owns a private vocabulary, and callers want the second function. Every violation the plan
      listed is covered, plus `EmptyVariableBinding`. `onNotGranted` reuses `dwoc-pin`'s
      `OnUnknownKey` rather than a third copy of the same `Default`/`Deny` pair; the *field* name
      is this RFC's own. CRD regenerated by `task recu`
- [x] `platform.rs`: the compiled-in set, plus `platform.builtin`/`platform.extra` handling. An
      unparseable `platform.extra` entry is an error rather than a silent skip — the same
      fail-toward-denying rule the catalogue gets, applied to the one set no grant can withhold
- [x] `resolve.rs`: the three-scope chain, the grant intersection, `onNotGranted`, the union with
      the platform set. Exhaustive table test, no cluster. Two shapes worth recording: a
      no-team namespace (and a team with no grant) falls back to the **top-level `default`**
      rather than to an empty grant, which is where this deliberately diverges from
      `network-profiles` — that feature's floor is the baseline, applied unconditionally, while
      here the floor is the platform set, and a namespace reaching *nothing* is one where no
      workspace can start; and `effective_patterns` drops an entry entirely if **any** of its
      patterns fails to parse, because a half-applied entry is an allow-list whose contents
      differ from what an admin reads
- [x] `subject.rs` + `feature/workspace_images.rs`: `Feature<WorkspaceImages>`, the
      selection-precise half
- [x] `feature/pod_images.rs`: `Feature<PodImages>`, the team-boundary floor.
      `the_pod_subject_exposes_no_path_to_a_workspace_selection` is the test the plan asked for —
      textual, because "this struct has no field of that shape" is not something the type system
      can be asked, and it fires on exactly the change this RFC argues costs new RBAC, a
      fleet-scaled cache and a startup race. The judging core both halves share is
      `feature/core.rs`: the two differ only in which `resolve` function the caller invoked, so
      "variables resolve identically at both layers" is a consequence of there being one
      implementation
- [x] `weebo-si-webhook/src/image_policy.rs`: both routes, extraction from `AdmissionReview` for
      `DevWorkspace` and for `Pod` including all three container lists and the
      `pods/ephemeralcontainers` subresource shape. A container with no `image` is skipped rather
      than denied — the apiserver rejects that on its own, and denying would be this webhook
      answering for a validation that is not ours
- [x] `weebo-si-runtime/src/image_metrics.rs`: the metrics, with the no-reference-in-a-label test.
      **One departure worth naming: this feature has an outbound port of its own**
      (`ImagePolicyObserver`), which `dwoc-pin` and `policy-guard` do not. The chassis' `Observer`
      records one `FeatureOutcome` per `evaluate()`, and this contract needs `resource` (the two
      halves are the same `FeatureId`), a per-*image* platform counter and a per-*variable*
      counter — several observations per decision, which `Decision` does not model and should not
      grow to, per its own doc comment. Same place `network-profiles` puts `ReconcileObserver`,
      same reason. The mode invariant is untouched: the port has no method answering "what mode
      am I in". `variable_value_seen` passes the raw annotation value across the port and it
      **stops there** — compared against the last one seen, counted as a change, never labelled
- [x] `weebo-si-operator`: registry lines in the composition root (one `ImageMetrics`, one config
      handle, two registries — sharing the handle is what makes "the two enforcement points
      cannot disagree" structural), `images_cmd.rs` for `platform`, `check` and `audit` —
      including the interpolated-pattern line in `check` and per-namespace `VARIES` reporting in
      `audit` when verdicts differ — and `features` output updated. Both cluster-reading
      subcommands use the invoking kubeconfig and a plain list rather than a reflector
- [x] Helm chart: both `ValidatingWebhookConfiguration`s with their opposite selector polarities,
      the pods one's `failurePolicy` driven by `values.yaml`'s
      `imagePolicy.podWebhook.failurePolicy` (`Fail` by default) rather than two separate
      manifests — the same shape RFC 0004 uses for `policyGuard`. Verified rendering at both
      values, and that the switch moves *only* the pods webhook. The RBAC template gained a
      comment recording that this feature adds nothing to it, so a future edit that adds a grant
      "for image-policy" has to argue with a note rather than an absence
- [x] envtest: 10 tests in `crates/weebo-si-webhook/tests/envtest.rs`, against a real apiserver
      calling back into a real running webhook over TLS through both real
      `ValidatingWebhookConfiguration`s. Denial at both layers, `DryRun` admitting what `Enforce`
      denies (at both layers), `pods/ephemeralcontainers` denied through its own subresource,
      `UPDATE` on a running pod denied, an unparseable reference denied, a platform image
      admitted for a team granted nothing, a namespace without the positive label out of the Pod
      rule's scope, and **one namespace per team proving `{TEAM_NAME}` resolves per namespace at
      both layers and denies across teams** — the one thing no single-namespace test can show.
      envtest has no kubelet, which is irrelevant: admission runs before scheduling, and
      admission is the whole of what this feature does
- [x] `docs/bricks/weebo-si-operator.md` updated with the feature, the three CLI commands, the
      Che-upgrade runbook entry, and *Known limitations* naming everything above that this does
      not do
- [x] Install checklist gains: which label marks a workspace namespace, whether the registry is a
      pull-through cache, the `failurePolicy` choice for the pods webhook, and — only where
      `variables` is declared — whether a workspace user can annotate their own namespace, with
      the command that answers it:
      `kubectl auth can-i patch namespace/<user-ns> --as=<workspace-user>`
- [x] Docs updated
- [x] RFC flipped to `Implemented`. Both *blocking* unresolved questions are answered above and
      moved to *Resolved*; what remains open is listed as a limitation rather than a gap, in the
      runbook's own *Known limitations*: this control is over names rather than content, workspaces
      predating installation are untouched, plugin components are read at the pod rather than at
      the `DevWorkspace`, an interpolating pattern is not reviewable by reading the CRD, and
      catalogue validation is reconcile-time rather than write-time. None of those is this RFC
      claiming something it does not do

## References

- [RFC 0002 — weebo-si-operator](./0002-weebo-si-operator.md) — the chassis, `spec.teams`, the
  catalogue-and-grants shape, and the *Future work* item this RFC answers.
- [RFC 0004 — network-profiles](./0004-network-profiles.md) — the non-negotiable baseline, the
  union semantics, the positive-label `namespaceSelector`, and the `audit`-before-enforce pattern.
- [Hexagonal layering](../architecture/hexagonal.md) — the three criteria.
- [Open Container Initiative Distribution Specification](https://github.com/opencontainers/distribution-spec)
  — repository and tag grammar.
- [`distribution/reference`](https://pkg.go.dev/github.com/distribution/reference) — the
  normalization behaviour the parser is written against, and the source of the *Contract* table.
- [DevWorkspace Operator `pkg/constants`](https://pkg.go.dev/github.com/devfile/devworkspace-operator/pkg/constants)
  — the workspace labels on a pod.
- [Kubernetes admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
  — subresource rules and the mutable fields of a running pod.
- [OpenShift image controller configuration](https://docs.openshift.com/container-platform/latest/openshift_images/image-configuration.html)
  — `registrySources`, the cluster-wide alternative.

## Changelog

| Date | Change |
| --- | --- |
| 2026-08-24 | Implemented in one pass, and flipped from `Draft` to `Implemented`. Both *blocking* unresolved questions were answered before any code was written, and both took RFC 0004's shape rather than inventing one: the `pods` webhook's `failurePolicy` is a `values.yaml` switch defaulting to `Fail` (the `DevWorkspace` one is hard-coded, since RFC 0002 already settled that argument), and the workspace-namespace label is `hardening.weebo.io/workspace-namespace` — the same string `policy-guard` already requires, so one checklist line covers both. **Four things surfaced that the design could not have known, and each is recorded in the *Implementation plan* rather than silently absorbed.** (1) `validate()` had to split across two crates: `weebo-si-crd` cannot call `Pattern::parse`, because it is the *domain crate's dependency* and not the reverse, so the CRD proves everything structural and `weebo_si_image_policy::validate` appends the parse-dependent half, both producing the one violation enum. (2) The declared-variable resolver moved from `weebo-si-runtime` (where the plan sketched it) into the domain crate: it needs only ports the domain already knows, and an adapter-side copy per route would have made "variables resolve identically at both layers" a promise about two implementations rather than a property of one. (3) This feature needed an outbound port of its own, which neither `dwoc-pin` nor `policy-guard` does — the chassis' `Observer` records one outcome per `evaluate()`, and this contract needs `resource`, a per-image counter and a per-variable counter; `ImagePolicyObserver` sits where `network-profiles` puts `ReconcileObserver`, and carries no method that could tell a feature its own mode. (4) **Writing `pattern.rs`'s tests found two real bugs before any of this ran anywhere**, both of the "looks like a working control" class this RFC is shaped against: `*/**` parsed into `docker.io/*/**` rather than being refused, so an admin writing "any registry" got a very large Docker Hub allow-list instead of the error *Contract* promises; and `registry.internal/-dev` parsed while being structurally unable to match anything, so a pattern that could never work was invisible rather than `Degraded` — and "never matches" is indistinguishable from "correctly restrictive" from the outside, which is the same argument this RFC already makes for undeclared variables. Both are now parse-time refusals. Verified with 141 pure tests in the domain crate, the full workspace suite green, and 10 new envtests against a real apiserver calling back into a real running webhook through both real `ValidatingWebhookConfiguration`s — including the per-team `{TEAM_NAME}` case at both layers, which is the one thing no single-namespace test can show. |
