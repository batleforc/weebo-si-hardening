---
rfc: 0015
title: platform API group for teams and users
status: Draft
authors: [batleforc]
created: 2026-10-06
updated: 2026-10-06
decided:
brick: crates/weebo-si-crd
supersedes: []
superseded-by: []
---

# RFC 0015 — platform API group for teams and users

## Summary

`WeeboSiTeam` and `WeeboSiUser` move from `hardening.weebo.io` to a new `platform.weebo.io` group,
next to the upcoming `WeeboSiProject` (RFC 0016). `WeeboSiConfig` and every guardrail feature stay
in `hardening.weebo.io`. Because Kubernetes cannot convert objects between API groups, the move is
a served-in-parallel migration with an ownership handover, guarded by a finalizer so that no
provisioned `AuthentikUser` or Argo CD `Application` is garbage-collected on the way.

## Motivation

**Two groups, two jobs.** `hardening.weebo.io` is the guardrail surface: the singleton, the
catalogues, the enforcement modes. Teams and users have become the entry point of the platform
(weebo-si RFC 0002): they provision identities and workspaces today, Forgejo organizations and
projects tomorrow. Keeping them in the guardrail group means every platform kind added later either
lands there too, blurring what an `edit` on `hardening.weebo.io` grants, or lands in another group
and leaves teams and users stranded in the wrong one.

**Why now.** `WeeboSiProject` is about to reference `WeeboSiTeam`, and a team is about to own Forgejo
objects. Moving two kinds with a handful of objects each is cheap today and expensive once projects
hang off them.

**Why not a conversion webhook.** A CRD conversion webhook converts between *versions of one CRD*
(`hardening.weebo.io/v1alpha1` → `v1beta1`). A different group is a different CRD and a different
resource; the API server has no notion of converting one into the other. The decision recorded in
weebo-si RFC 0002 P6 ("migration with conversion") is therefore implemented as this RFC's migration
— same intent: both shapes served during the move, no object lost, no manual re-creation.

**Once this exists:** `kubectl get weebositeams.platform.weebo.io` answers what
`weebositeams.hardening.weebo.io` answers today, the legacy kinds are gone, and every
`AuthentikUser` and `Application` created before the move is still there, owned by the new object.

## Guide-level explanation

What changes for the person writing manifests is the `apiVersion`:

```yaml
apiVersion: platform.weebo.io/v1alpha1   # was hardening.weebo.io/v1alpha1
kind: WeeboSiUser
metadata:
  name: batleforc
spec:
  username: batleforc
  team: weebo
  # unchanged
```

The migration, on a cluster managed by Argo CD from weebo-si's `che/hardening` chart:

1. Upgrade `weebo-si-operator` to the release that serves both groups. Legacy objects gain the
   finalizer `hardening.weebo.io/handover`.
2. Switch the chart templates to `platform.weebo.io/v1alpha1`. Argo CD creates the new objects and
   prunes the legacy ones. Each legacy object stays `Terminating` until its successor has taken over
   its children:

   ```console
   $ kubectl get weebosiusers.hardening.weebo.io
   NAME        USERNAME    TEAM    READY   HANDOVER   AGE
   batleforc   batleforc   weebo   True    Pending    41d

   $ kubectl get weebosiusers.platform.weebo.io
   NAME        USERNAME    TEAM    AUTHENTIK   CHE       READY   AGE
   batleforc   batleforc   weebo   Created     Created   True    12s
   ```

   Seconds later the legacy object is gone, the `AuthentikUser` and `Application` were never
   touched.
3. A later release stops serving the legacy kinds and the chart drops their CRDs.

## Design

### Contract

**New CRDs**: `weebositeams.platform.weebo.io` and `weebosiusers.platform.weebo.io`, version
`v1alpha1`, cluster-scoped, schema identical to the `hardening.weebo.io` ones at the time of the
move (RFC 0011's contract carries over field for field). Short names `wsteam` and `wsuser` move to
the new CRDs; the legacy CRDs lose their short names in the transition release so `kubectl get
wsteam` is unambiguous.

**Transition rules** (operator release N, serving both):

| Situation | Behaviour |
| --- | --- |
| Only a legacy object exists | Reconciled as today. Gains the `hardening.weebo.io/handover` finalizer. Reports `Deprecated` (advisory). |
| Legacy and new object with the same `metadata.name` | The new one is authoritative. The legacy one is not reconciled any more and reports `Superseded`. |
| New object finds a child owned by its legacy namesake | **Handover**: one patch on the child adds the new owner as `controller: true` and turns the legacy `ownerReference` into `controller: false`. The child is then reported `Created`, as if the new object had made it. |
| Legacy object being deleted | The finalizer is removed only when no child still has the legacy object as its *only* owner — either the successor took them over, or there were none. |
| Legacy object deleted without a successor | Same as deleting a `WeeboSiUser` today: the finalizer is removed and garbage collection deprovisions. A deletion without a successor is a deprovisioning, not a migration. |

The handover is the narrow exception to RFC 0011's rule that an object owned by another
`WeeboSiUser` is read-only: it applies only when the other owner is the **legacy-group object of the
same name**. Any other owner still yields `Conflict`.

Team references (`WeeboSiUser.spec.team`, feature resolution, `endpoint-auth` membership) resolve
against the union of both groups during the transition, new group first.

**Release N+1** removes the legacy kinds from the operator and the chart. Its upgrade notes require
`kubectl get weebosiusers.hardening.weebo.io,weebositeams.hardening.weebo.io` to be empty — deleting
a CRD deletes its remaining objects, and without the operator running the finalizer they would hang.

### Architecture

The CRD crate gains the two types under the new group — the same Rust structs, derived twice with
a `kube` attribute per group, so the schema cannot drift between them. No ports there, as RFC 0011
said for this crate.

The identity controller is already hexagonal (RFC 0011). The handover is a decision inside the
existing pure function — "this child is owned by my legacy namesake" is one more `Observation`
variant — and the extra `ownerReference` patch goes through the existing `Provisioner` port. No new
port.

### Data and state

Stateless, as before. The only state the migration relies on is `ownerReferences` on the children,
which is the API server's: after a restart mid-migration, the operator re-derives which children
were handed over by reading them.

## Security considerations

- **Privileges.** `update` on the legacy kinds (finalizer), already held for status; `patch` on
  `AuthentikUser` and `Application`, already held. No new verb, no new resource.
- **Trust boundary.** The handover reads `ownerReferences` written by the API server, and matches
  on group, kind, name *and* the legacy object's `uid`. Someone able to create a legacy object can
  already create a new one; the migration grants them nothing extra.
- **Bypass.** A new object named after someone else's legacy object would take over its children.
  That is the same capability as editing the legacy object, which the same RBAC grants — the
  RBAC for the new group must mirror the legacy one exactly (chart `ClusterRole`s updated in the
  same release).
- **Blast radius.** The failure that matters is a lost child — an `Application` deleted takes a
  person's namespace and workspaces with it. The finalizer is what makes the order of Argo CD's
  create/prune irrelevant.
- **Secrets.** None involved.

## Operational considerations

- **Failure mode.** Fail-safe toward keeping objects: when in doubt (successor not reconciled yet,
  operator down), the legacy object stays `Terminating` and its children stay. The cost is a
  `Terminating` object, never a deprovisioned person.
- **Rollout.** As in the guide: operator first, manifests second. Doing them in the other order
  means new objects with no operator to reconcile them and legacy objects deleted without the
  finalizer — exactly the incident this RFC exists to prevent. The chart therefore refuses to
  render `platform.weebo.io` objects unless the operator image is at least release N.
- **Rollback.** Before the legacy deletion completes: revert the manifests, the legacy objects are
  still there. After: re-applying legacy manifests next to the new ones makes them `Superseded`,
  harmless; going back for real is the same migration in reverse, which release N supports.
- **Observability.** `Deprecated`, `Superseded` and `HandoverPending` conditions; a `HANDOVER` printer
  column on the legacy kinds; a counter of handovers performed. An alert on any legacy object
  `Terminating` for more than one reconcile period.
- **Upgrade.** Old and new replicas side by side: the old one only knows the legacy group and keeps
  reconciling it, without the finalizer — the leader lease means only one writes. The finalizer is
  added by the new release before any manifest switches, per *Rollout*.

## Alternatives considered

- **Stay in `hardening.weebo.io`** — no migration at all. Rejected: platform kinds would either
  join the guardrail group or split from teams and users (*Motivation*).
- **A conversion webhook** — not possible across groups (*Motivation*).
- **New `v1alpha2` in the same group** — would make conversion possible, but leaves the kinds in the
  wrong group, which is the whole point.
- **Delete and re-create with orphan propagation** (`kubectl delete --cascade=orphan`, then create
  the new objects, which adopt the orphans) — works by hand, but depends on every operator running
  the right command, and Argo CD's prune does not orphan. The finalizer makes it safe by default.

## Drawbacks and risks

- One release serves duplicated kinds, with duplicated RBAC and a handover code path that exists
  only for the migration and is removed in N+1.
- A finalizer on legacy objects means an operator removed during the window leaves them
  `Terminating` until someone patches the finalizer out.

## Unresolved questions

- Whether `WeeboSiConfig` should eventually follow (non-blocking; this RFC says no — it is the
  guardrail singleton).

## Future work

- Release N+1: drop the legacy kinds.
- RFC 0016 adds `WeeboSiProject` and the team's `projects` and `forgejo` blocks to the new group.

## Implementation plan

- [ ] CRD types under `platform.weebo.io`, short names moved, CRDs regenerated
- [ ] Dual-group resolution for teams
- [ ] Finalizer, handover and `Superseded` in the identity controller
- [ ] Chart: RBAC for both groups, version guard
- [ ] weebo-si `che/hardening` chart switched to the new group
- [ ] Release N+1: legacy kinds removed
- [ ] Docs updated
- [ ] RFC flipped to `Implemented`

## References

- RFC 0011 — teams and users as objects
- RFC 0016 — `WeeboSiProject`
- weebo-si `.rfc/0002` — platform engineering end to end, decisions P1 and P6
- Kubernetes: CRD versioning and conversion, garbage collection and owner references

## Changelog

| Date | Change |
| --- | --- |
