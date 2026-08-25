---
rfc: 0008
title: policy-guard-coverage
status: Draft
authors: [batleforc]
created: 2026-08-25
updated: 2026-08-25
decided:
brick: crates/weebo-si-policy-guard
supersedes: []
superseded-by: []
---

# RFC 0008 — policy-guard-coverage

## Summary

`policy-guard` refuses writes to the objects this operator owns. It covers two kinds —
`networkpolicies` and `ciliumnetworkpolicies` — out of the four this project now writes into
workspace namespaces. This RFC extends it to `kubearmorpolicies`
([RFC 0006](./0006-kubearmor-policy.md)), promotes the guard out of
`weebo-si-network-profiles` into its own crate, and settles how the *next* guarded resource
joins so that the third and fourth extensions are not three more RFCs' worth of the same
argument.

It is not a new control. It is the control RFC 0004 already accepted, applied to the objects
that have shipped since without it.

## Motivation

RFC 0004 built `policy-guard` on a specific claim: an operator that writes policy objects into
namespaces their users can edit has not enforced anything unless something refuses those users'
edits. That claim is not resource-specific, but the implementation is — the webhook rule names
`networkpolicies` and `ciliumnetworkpolicies`, and the domain type is called
`NetworkPolicyWrite`.

Since then RFC 0006 shipped `kubearmor-policy`, which writes `KubeArmorPolicy` objects into the
same namespaces, and RFC 0007 proposes writing `ConfigMap`s and `Secret`s there too. Neither is
guarded. So today:

- **A user with `edit` on `kubearmorpolicies` in their own namespace can rewrite the policy that
  constrains their own workspace's process, file and capability access.** The controller puts it
  back on its next pass, so the window is bounded by the reconcile interval rather than
  unbounded — but "the control is off for up to five minutes, on request, for anyone who wants
  it off" is not a sentence this project should be able to write about one of its own bricks.
- **It already cost us a design compromise, in code, today.** RFC 0006's `PolicyStore` uses
  server-side apply with `force`, where `network-profiles`' identical store does not. The reason
  is exactly this gap: a `kubectl edit` makes the editor a field manager, and every subsequent
  apply from the controller fails with a 409 conflict — the drift the brick exists to correct
  becoming the drift it can no longer correct. `network-profiles` can afford not to force because
  the guard refuses that edit before a field manager is ever created. One brick forcing and its
  twin not, for reasons neither brick's code can state locally, is the kind of asymmetry that
  gets "cleaned up" by someone six months from now who does not know why.
- **The gap widens on its own.** Every brick that writes an object into a workspace namespace
  inherits it. RFC 0007 adds two kinds; the pattern this project is built on guarantees more.

### What exists today

`policy-guard`, at `mode: Enforce`, denying `CREATE`/`UPDATE`/`DELETE` on
`networkpolicies` and `ciliumnetworkpolicies` in workspace namespaces, per a three-row table:
the operator's own identity is exempt; anyone else touching an object carrying
`hardening.weebo.io/managed-by: weebo-si-operator` is denied; anyone outside `allowedIdentities`
creating an *unmanaged* policy is also denied, because authorship of policy in a workspace
namespace belongs to the platform.

That table is already resource-agnostic. What is not is the type it reads
(`NetworkPolicyWrite`), the crate it lives in (`weebo-si-network-profiles`), and the one webhook
rule that routes to it.

**Outcome we are buying:** every object this operator writes into a namespace it does not own is
refused to everyone else, by the same rule, whichever brick wrote it — and adding the next
resource is a rule in a chart plus a row in a table, not an RFC.

## Guide-level explanation

Nothing changes for an admin who has `policy-guard` on today, except that it now also protects
the `KubeArmorPolicy` objects `kubearmor-policy` writes. The feature keeps one `mode`, one
`namespaceSelector` and one `allowedIdentities` list:

```yaml
features:
  policyGuard:
    mode: Enforce
    allowedIdentities:
      - system:serviceaccount:platform:network-admin
```

The chart grows one rule, gated on the same value that gates `kubearmor-policy`'s RBAC — a
cluster without KubeArmor should not register a webhook for a resource its apiserver does not
serve:

```yaml
# values.yaml
kubearmorPolicy:
  rbac:
    enabled: true      # already governs the controller's write permission
policyGuard:
  failurePolicy: Fail  # unchanged, and now covers three resources
```

What a developer sees when they try:

```console
$ kubectl edit kubearmorpolicy weebo-base -n user-alice
error: kubearmorpolicies "weebo-base" could not be patched: admission webhook
  "policies.hardening.weebo.io" denied the request: user-alice/Update is managed by
  weebo-si-operator and may not be touched by system:serviceaccount:user-alice:default
```

The same sentence `network-profiles`' objects already produce, from the same code path, with the
resource name being the only difference.

## Design

### Contract

#### One feature, one mode, three resources

`policy-guard` keeps its single `FeatureId`, its single `spec.features.policyGuard` block and its
single `mode`. **No per-resource mode**, and that is a decision rather than a shortcut: the
guard's whole claim is "objects this operator owns are not yours to edit", and a cluster where
that is true of a `NetworkPolicy` and false of a `KubeArmorPolicy` is a cluster where the claim
is not true. An admin who needs the distinction has `namespaceSelector`, which narrows by
namespace rather than by how the object happens to be enforced.

#### The domain type becomes resource-agnostic

`NetworkPolicyWrite` → **`GuardedWrite`**, and `NetworkPolicyOperation` → **`WriteOperation`**,
with one field added:

```rust
pub struct GuardedWrite {
    pub namespace: NamespaceName,
    pub actor: String,
    pub operation: WriteOperation,
    pub target_is_managed: bool,
    /// Which resource this write is against — a metric label and a log field, never a branch.
    pub resource: GuardedResource,
}

pub enum GuardedResource { NetworkPolicy, CiliumNetworkPolicy, KubeArmorPolicy }
```

**`resource` is never read by the verdict logic**, and that is the point: the three-row table is
the same table for every resource, and a `match` on `resource` inside `evaluate` would be the
first step toward a guard that protects some objects more than others. It exists so a metric can
be broken down and a log line can name what was refused. The enum is closed for the same reason
`Ecosystem` is in RFC 0007: it becomes a metric label.

#### A second webhook path, not a second rule on the first

- **New path**: `/validate/v1/kubearmorpolicies`, handled by the same resource-agnostic handler
  as `/validate/v1/networkpolicies`.
- **Not** a third rule on the existing path, even though the handler would serve it correctly.
  Two reasons: a path named `networkpolicies` that also decides KubeArmor writes is a lie a
  future reader has to discover, and — more concretely — a separate rule can be gated on
  `kubearmorPolicy.rbac.enabled` and carry its own `failurePolicy` without touching the rule that
  protects the network baseline.

#### No `objectSelector`, deliberately

RFC 0007 proposes an `objectSelector` on `hardening.weebo.io/managed-by` for its own guard rule,
because `ConfigMap` writes are among the highest-volume writes in a cluster and a webhook in
front of all of them is a cluster-wide risk. **This rule takes the opposite decision**, for two
reasons that are worth writing down because they are the general rule:

1. **The third row needs to see unmanaged writes.** "Authorship of policy in a workspace
   namespace belongs to the platform" is a denial of a `CREATE` for an object that carries no
   management label. An `objectSelector` matching the label would make that row unreachable.
2. **`kubearmorpolicies` are low-volume.** They are written by this operator and, in the state
   this RFC brings about, by nobody else. A webhook in front of all of them costs nothing a
   cluster notices.

So the selector question has an answer that is not a preference: **a guard rule that must refuse
unmanaged creates cannot use an ownership `objectSelector`; one that only protects existing
objects should, if the resource is high-volume.** RFC 0007's rule is the second kind, which is
why it differs.

#### The third row, and why it matters more here

For `NetworkPolicy`, denying user-authored policies is about keeping one team's hand-written
policy from contradicting the baseline. For `KubeArmorPolicy` it is stronger: KubeArmor evaluates
a pod against *every* policy selecting it, and the presence of an `Allow` rule in a domain
changes how unmatched operations in that domain are treated. A user-authored policy is therefore
not merely additive — it can change how the operator's own baseline is evaluated. The third row
extends unchanged, and this is the argument for it.

#### Webhook configuration

| | |
| --- | --- |
| Path | `/validate/v1/kubearmorpolicies` |
| Rules | `CREATE`, `UPDATE`, `DELETE` on `security.kubearmor.com/v1` `kubearmorpolicies`, `scope: Namespaced` |
| `failurePolicy` | `.Values.policyGuard.failurePolicy` — `Fail` by default, the same value and the same argument as the network rule |
| `namespaceSelector` | the same exclusion label the existing rule uses |
| `objectSelector` | none — see above |
| Gate | rendered only when `kubearmorPolicy.rbac.enabled` |

`DELETE` is included for the reason RFC 0004 gives: deleting the baseline is the cheapest bypass,
and a rule that does not cover `DELETE` does not cover it. On a `DELETE` the object arrives in
`oldObject`, which is where the adapter reads the ownership label from.

#### Observability

No new metric. `weebo_si_admission_requests_total{feature="policy-guard"}` gains
`resource="KubeArmorPolicy"` alongside the two it already carries — which is the whole reason
`GuardedWrite::resource` exists.

### Architecture

**Hexagonal, yes** — it already is; this RFC moves it rather than reshaping it.

**`policy-guard` moves to `crates/weebo-si-policy-guard`.** It lives in
`weebo-si-network-profiles` today for a historical reason (RFC 0004 introduced both), and that
placement is now actively wrong: `weebo-si-kubearmor-policy` would have to depend on
`weebo-si-network-profiles` to be guarded by it, which is a dependency between two sibling
features with nothing to say to each other. After the move, the guard depends on
`weebo-si-chassis` and `weebo-si-crd` only, and every feature crate stays unaware of it — the
webhook's composition root is the one place that knows both.

The move is mechanical (`PolicyGuard`, `GuardedWrite`, `WriteOperation`, `GuardedResource`, their
tests) and is the largest part of this RFC's diff while being the smallest part of its risk.

### Data and state

Stateless, unchanged. The guard reads its verdict from the request plus two configured identity
lists; it holds no cache and makes no port call. That is why it can sit on the admission path of
three resources without a readiness question.

## Security considerations

- **Privileges.** None added. The guard is a validating webhook: it reads `AdmissionReview`
  bodies and answers allow/deny. The webhook role's RBAC is unchanged by this RFC — it already
  reads `kubearmorpolicies` (RFC 0006 granted that for the `BaselineView` read), and a guard
  needs no permission on the objects it refuses.
- **Trust boundary.** The `AdmissionReview` body is attacker-controlled, and this RFC puts one
  more resource's bodies in front of the same handler. The handler reads four fields
  (namespace, username, operation, the old object's labels) and never the object's spec — the
  rule content of a `KubeArmorPolicy` is never parsed, which is the same promise
  `kubearmor-policy` itself makes about templates.
- **What this closes.** The edit window named in *Motivation*: a workspace owner rewriting or
  deleting the runtime policy that constrains their own workspace.
- **What it does not close.**
  - **Anyone who can bypass admission.** A cluster admin with `--force` against etcd, a
    controller running as an exempt identity, or someone who can edit the
    `ValidatingWebhookConfiguration` itself. The guard is a control over ordinary API writes.
  - **The namespace posture annotations.** `kubearmor-policy` writes three
    `kubearmor-*-posture` annotations onto workspace namespaces (RFC 0006). A namespace carries
    no ownership label, so the guard — which is object-scoped — does not protect them. A user who
    can annotate their own namespace can move their posture from `Block` back to `Audit`. This is
    a real remaining gap, named in *Unresolved questions* rather than quietly left out.
  - **Objects that predate the guard.** Admission is not retroactive. An object edited before this
    rule was installed stays edited until the controller's next pass puts it back.
- **Blast radius, and the honest version.** A validating webhook in front of a resource is a
  denial-of-service surface for that resource by construction: at `failurePolicy: Fail`, a
  webhook outage means nobody writes `kubearmorpolicies` cluster-wide, including KubeArmor's own
  operator if a future version writes them. That is the same trade RFC 0004 already made for
  `networkpolicies` and is argued again below.
- **Secrets.** Reads none. Log lines carry the namespace, the actor identity and the resource —
  never the object.

## Operational considerations

- **Failure mode.** `Fail`, matching the existing rule, from the same argument: the alternative
  is a window in which the object the control depends on can be removed, and an operator who
  cannot write a `KubeArmorPolicy` for a few minutes is a much smaller problem than a workspace
  whose runtime policy silently went away. The counter-argument — that this makes a webhook
  outage block a resource KubeArmor's own tooling may need to write — is real, which is why
  `.Values.policyGuard.failurePolicy` remains a single install-time switch an admin can set to
  `Ignore` for every guarded resource at once.
- **Rollout.** `policy-guard` already has `mode`. On a cluster already running it at `Enforce`,
  installing this rule extends an active control to one more resource — so the rollout step is
  the chart upgrade, and the dry run is `mode: DryRun` if the admin wants one, which records
  denials without issuing them for **all three** resources (the mode is shared, per *Contract*).
- **Ordering with the controller.** Install the rule after `kubearmor-policy` has reached a
  steady state, not before: a guard that starts refusing writes while the controller is still
  converging turns a converging namespace into a stuck one, since the controller's own identity
  is exempt but a half-applied object may still need a write the operator has not attempted yet.
- **Rollback.** Remove the rule (chart value), or `mode: Off`. Both are effective on the next
  admission with no restart.
- **Upgrade.** The move to `crates/weebo-si-policy-guard` is a source-level refactor with no
  behavioural change and no wire-format change; the webhook path for the existing rule is
  unchanged, so a rolling update never has one replica serving a path another does not.
- **The force-apply question.** RFC 0006's store force-applies *because* this gap existed. Once
  this RFC ships, should it stop? **No** — see *Unresolved questions*; the short version is that
  the guard prevents new conflicts while force is what recovers from ones that already exist.

## Alternatives considered

- **Do nothing; rely on the controller putting objects back.** The status quo, and the reason
  this RFC exists. It bounds the window rather than closing it, and it is why one store forces
  and its twin does not.
- **RBAC instead of a webhook.** Kubernetes RBAC cannot express "everything in this namespace
  except the objects carrying this label" — it has no field or label selector on write verbs at
  all. If it could, this whole brick would be a `Role`.
- **A third rule on the existing `networkpolicies` path.** Works today and costs nothing to
  build. Rejected for the naming lie and, more practically, because the two rules could then not be
  gated, nor given different failure policies, independently.
- **An `objectSelector` on this rule too.** Rejected on the mechanism, not on taste: it makes the
  third row unreachable, per *Contract*. Worth recording because it is the obvious first
  suggestion in review.
- **Kyverno or Gatekeeper for the guard.** Both express "deny writes to objects with this label
  by anyone but this ServiceAccount" perfectly well, and a cluster already running one has a real
  case for using it. Rejected for this project for the reason RFC 0004 gave: the guard shares a
  mode, a `namespaceSelector` and an `allowedIdentities` list with the features it protects, and
  splitting that across two policy engines means an admin reading `WeeboSiConfig` cannot tell
  what is enforced.
- **Guarding by owner reference instead of by label.** An `ownerReference` on a cluster-scoped
  operator's namespaced objects has garbage-collection semantics we do not want (deleting the
  operator would cascade to every policy in the fleet). The label stays the ownership boundary.

## Drawbacks and risks

One more resource whose every write goes through this operator's admission path, with the
availability consequence that implies at `failurePolicy: Fail`. A crate move that touches every
import of `PolicyGuard` in the workspace — mechanical, but a large diff to review for a small
behavioural change, and the kind of diff a real bug hides in. And a guard covering three
resources invites the assumption that it covers everything this operator writes, which it does
not: the posture annotations are outside it, and saying so once here does not stop someone
believing otherwise later.

## Unresolved questions

Non-blocking:

- **Whether `kubearmor-policy`'s store should stop force-applying once this ships.** The argument
  for stopping: force is a blunt instrument, and with the guard in place no conflicting field
  manager should ever exist. The argument for keeping it: an object edited *before* the guard was
  installed already has one, and without force that object is wedged forever with a 409 on every
  pass — the guard prevents new conflicts, force is what recovers from old ones. Leaning toward
  keeping force and documenting why, which also keeps the two stores' asymmetry to a single
  comment rather than a behavioural difference nobody can explain.
- **Whether `allowedIdentities` should become per-resource.** Today one list exempts an identity
  from the third row for every guarded resource. A cluster with a network team that authors
  `NetworkPolicy` but should never author a `KubeArmorPolicy` cannot express that. No such
  cluster exists here yet.

Blocking, in the sense that acceptance should settle it:

- **Whether the namespace posture annotations are in scope.** They are the one output of
  `kubearmor-policy` this RFC leaves unguarded, and guarding them is a genuinely different
  mechanism: a rule on `namespaces/UPDATE` comparing old and new annotation values, with no
  ownership label to match on and every namespace write in the cluster passing through it. That
  is a much larger blast radius than anything above, for a gap whose exploitation (moving your
  own posture from `Block` to `Audit`) is visible in the reconcile log and corrected on the next
  pass. This RFC proposes **out of scope**, and asks reviewers to say so explicitly rather than
  inherit it by silence.

## Future work

- **RFC 0007's `ConfigMap`/`Secret` rule**, which is the second kind of guard rule described
  under *Contract* — ownership-selected, high-volume, `failurePolicy: Ignore`. That RFC already
  specifies it; this one supplies the vocabulary (`GuardedResource`, the resource-agnostic
  handler) it will extend.
- **Guarding the posture annotations**, if reviewers decide the gap above matters more than the
  blast radius of a `namespaces` webhook.
- **A drift-to-alert path**: `weebo_si_*_drift_total` climbing while the guard is on means an
  exempt identity or a pre-guard object, and today nobody is told.

## Implementation plan

- [ ] `crates/weebo-si-policy-guard`: move `PolicyGuard` and its tests out of
      `weebo-si-network-profiles`, renaming `NetworkPolicyWrite`→`GuardedWrite`,
      `NetworkPolicyOperation`→`WriteOperation`, adding `GuardedResource`
- [ ] `weebo-si-webhook`: the handler becomes resource-agnostic over `GuardedResource`; add
      `/validate/v1/kubearmorpolicies`; `resource` reaches the metric label and the log line
- [ ] `charts/weebo-si-operator`: the new `ValidatingWebhookConfiguration` rule, gated on
      `kubearmorPolicy.rbac.enabled`, no `objectSelector`, `DELETE` included
- [ ] Unit tests: the three-row table over each `GuardedResource`, proving the verdict does not
      vary by resource
- [ ] Envtest: a non-operator identity is refused `UPDATE` and `DELETE` on a managed
      `KubeArmorPolicy` and refused `CREATE` of an unmanaged one; the operator identity is not
- [ ] Docs updated (`docs/bricks/weebo-si-operator.md`'s RFC 0004 and RFC 0006 sections)
- [ ] RFC 0006's *Unresolved questions* entry closed, pointing here
- [ ] RFC flipped to `Implemented`

## References

- [RFC 0004](./0004-network-profiles.md) — `policy-guard`'s design, the three-row verdict table,
  and the `failurePolicy` argument this RFC reuses.
- [RFC 0006](./0006-kubearmor-policy.md) — the brick whose objects this RFC brings under the
  guard, and whose *Unresolved questions* raised it.
- [RFC 0007](./0007-registry-config.md) — the next two resources, and the ownership-selected
  variety of guard rule.
- [Kubernetes: dynamic admission control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) —
  `objectSelector`, `failurePolicy`, and `oldObject` on `DELETE`.
- [KubeArmor: policy specification](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/security_policy_specification.md) —
  how multiple policies selecting one pod are evaluated, behind the *third row* argument.

## Changelog

| Date | Change |
| --- | --- |
