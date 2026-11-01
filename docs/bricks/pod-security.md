# `pod-security`

A feature of the [`weebo-si-operator`](./weebo-si-operator.md). Design and rationale:
[RFC 0013](../rfc/0013-pod-security.md). Field reference:
[`features.podSecurity`](../weebosiconfig.md#featurespodsecurity) and the team block in
[`weebositeam.md`](../weebositeam.md#featurespodsecurity). This page assumes the operator is
installed.

Without this feature, nothing constrains what a workspace pod may ask of its node. A Che user is
the administrator of their own namespace and can create a pod directly, with `privileged: true`,
`hostPID` and the node's root filesystem mounted. The image is a permitted one, so `image-policy`
lets it through.

This feature gives every workspace namespace a **Pod Security Admission level**, per team. It
writes the upstream `pod-security.kubernetes.io/*` labels, and the kube-apiserver's built-in
`PodSecurity` admission plugin does the refusing. **The operator writes no admission code here.**
It decides which namespace gets which level, and it remembers what the namespace carried before so
that `mode: Off` puts it back.

## Install checklist

1. **Grant the RBAC.** Off by default:

   ```bash
   helm upgrade weebo-si-operator charts/weebo-si-operator \
     -n weebo-si-hardening --set podSecurity.rbac.enabled=true
   ```

   This adds `patch` on `namespaces`. RBAC cannot narrow it to label keys, so the narrowing is in
   the adapter: a server-side apply whose object holds exactly six labels and one annotation. The
   chart grants the same verb under `kubearmorPolicy.rbac.enabled`, and either switch is enough.
   Without it the controller logs `pod-security is inert` and does nothing. **On OpenShift the
   feature only observes** (see below), so it can stay off there.

2. **Turn on `seccompDefault: true` in every node's kubelet configuration.** Without it, a container that sets no
   seccomp profile runs `Unconfined`, and `baseline` admits it. See RFC 0013's *Seccomp*, and
   [`seccomp-profiles.md`](../seccomp-profiles.md) for the profiles a build team needs.

3. **Pick a `version`.** It is required and has no default: `latest`, or a pinned `v1.N`. Pinning
   means a cluster upgrade cannot tighten a level overnight. If build teams run nested containers
   with `procMount: Unmasked`, the version must be one where `baseline` admits that on a pod with
   `hostUsers: false` (KEP-4265). The runtime matrix measured it on 1.35 with `latest`.

4. **Audit before you enforce.** See *Rollout*.

## What gets written

For each namespace in scope, exactly six labels and one annotation, under the server-side apply
field manager `weebo-si-pod-security`:

| Key | Value |
| --- | --- |
| `pod-security.kubernetes.io/enforce` | the team's level |
| `pod-security.kubernetes.io/enforce-version` | `version` |
| `pod-security.kubernetes.io/warn` | the team's `warnLevel` |
| `pod-security.kubernetes.io/warn-version` | `version` |
| `pod-security.kubernetes.io/audit` | the team's `warnLevel` |
| `pod-security.kubernetes.io/audit-version` | `version` |
| annotation `hardening.weebo.io/pod-security-previous` | the six labels as found before the first write, as JSON |

Which level a namespace gets:

1. its team's `level`, or the cluster `default` when it has no team or the team sets none;
2. a stricter level named by the namespace annotation `hardening.weebo.io/pod-security`, which
   **can only tighten**, so the namespace's own user may set it;
3. clamped to the `ceiling`, `baseline` by default, so nobody gets `privileged` unless an admin
   raises it.

Two rules decide what is **not** written:

- **A stricter level somebody else set is left alone.** An admin who labelled a namespace
  `restricted` by hand keeps it, and the controller logs `result=stricter_existing`.
- **The `-previous` annotation is written once.** It records the namespace before the operator
  touched it, never the state before the last write.

```console
$ kubectl get ns user-bob -o jsonpath='{.metadata.labels}' | tr ',' '\n' | grep pod-security
"pod-security.kubernetes.io/audit":"restricted"
"pod-security.kubernetes.io/audit-version":"v1.34"
"pod-security.kubernetes.io/enforce":"restricted"
...
```

Pods already running keep running. Pod Security Admission checks a pod when it is created, never
afterwards. A violating pod is refused the next time it is created, which for a workspace means the
next restart.

## Rollout

1. **Audit.** With the admin's own kubeconfig:

   ```console
   $ weebo-si-operator pods audit --all-namespaces
   NAMESPACE                TEAM           LEVEL       VIOLATIONS
   user-alice               team-1         restricted  0
   user-bob                 team-1         restricted  2  python-web-7d9c: allowPrivilegeEscalation != false; debug: runAsNonRoot != true
   user-carol               team-build     baseline    0
   ```

   It is a server-side dry run of the `enforce` label. The apiserver answers, and nothing is
   written. `--level restricted` asks about a level before any configuration exists, and
   `--version v1.35` asks about a version bump. It needs `patch` on namespaces, like the write.

2. **`mode: DryRun`.** The controller logs what it would write, without writing it:

   ```text
   feature=pod-security mode=DryRun ns=user-bob team=team-1 level=restricted warn=restricted result=applied diff=set:enforce=restricted,set:enforce-version=v1.34,...
   ```

3. **`mode: Enforce` on a pilot**, with `namespaceSelector` narrowed to one team. Watch the
   workspace restarts: a workspace whose DWOC asks for more than its level allows does not start,
   and the error lands on its ReplicaSet and in the DevWorkspace status.

4. **Widen the selector**, one team at a time.

**A stock Che workspace does not start at `restricted`.** Measured on kind with stock Che and
DevWorkspace Operator: the `tools` container and Che's `che-gateway` sidecar set neither
`allowPrivilegeEscalation: false`, nor `capabilities.drop: [ALL]`, nor a seccomp profile, and the
pod is refused. The DevWorkspace's status carries the message, so the user sees why. Before a
`restricted` default, set those three in the DWOC (`containerSecurityContext` and
`podSecurityContext`) and check the gateway sidecar gets them too. At `baseline` a stock workspace
runs.

A team that builds images gets `baseline` and the build profile, set up through the DWOC. See RFC
0013's *A build workspace* for the exact `hostUsers` / `procMount` / seccomp settings, and why
`restricted` cannot work for it.

## Rollback

- **`mode: Off`** puts every namespace back: the six labels as they were, the annotation removed.
  A namespace that had no Pod Security labels before ends up with none.
- **Narrowing `namespaceSelector`** does the same for the namespaces it drops.
- **Removing the `podSecurity` block** is *not* a rollback: with no configuration the controller
  does nothing, including restore. Go through `mode: Off` first.
- **One namespace, now:** `kubectl label ns <ns> pod-security.kubernetes.io/enforce=privileged
  --overwrite` works, and the controller takes it back on its next pass (and counts it as drift).
  For a lasting exception, take the namespace out of the selector or out of the team.

## OpenShift

OpenShift's label syncer (`cluster-policy-controller`) already writes the
`pod-security.kubernetes.io/*` labels from the SCCs each namespace's service accounts can use. The
fleet keeps it on, so the SCC grant remains the one place a level is decided. With `backend: Auto`
the controller discovers `security.openshift.io` at startup and **observes instead of writing**.
It resolves each namespace's level, compares it with the synced one, and logs
`result=looser_synced` when the synced level is looser. The lever is then the SCC grant, not a
label. `backend: Labels` forces writing, and should only be used with the syncer turned off for
those namespaces.

## Reading the logs

```text
feature=pod-security mode=Enforce ns=user-bob team=team-1 level=restricted warn=restricted result=applied diff=set:enforce=restricted,...
WARN feature=pod-security ns=user-bob level=restricted apiserver: python-web-7d9c: allowPrivilegeEscalation != false
WARN feature=pod-security ns=user-dave team=loose result=clamped,applied notes=[Clamped { from: Privileged }]
WARN feature=pod-security ns=user-erin result=drift a Pod Security label was changed by another field manager and is put back
feature=pod-security ns=user-bob result=restored set={} removed=6
```

The `apiserver:` lines are the warnings the write returned: one per existing pod, or per group of
pods with the same violations, that the new level refuses.

## Observability

| Metric | Labels | Read it for |
| --- | --- | --- |
| `weebo_si_pod_security_namespaces` | `level`, `state` | `state` is `applied`, `stricter_existing` or `pending`. `pending > 0` in `Enforce` means a namespace does not enforce its level yet (a looser OpenShift sync, or a write that keeps failing). |
| `weebo_si_pod_security_reconcile_total` | `result` | `applied`/`unchanged`/`restored`/`clamped`/`not_tightening`/`stricter_existing`/`looser_synced`/`previous_lost`/`error`. `clamped` is an admin who wrote a level they cannot have. |
| `weebo_si_pod_security_drift_total` | none | Someone changing a label this feature owns. Climbing for one namespace is a person, not a bug. |
| `weebo_si_pod_security_violations` | `level` | Existing pods the apiserver warned about on the last write: the pods that will not come back after their next restart. |

No metric carries a namespace or a pod name, for the reason every feature here gives. Which
namespace is in the log line and in `pods audit`.

The `WeeboSiConfig` status lists `pod-security`, and goes `Degraded` when the `version` is not
`latest` or `v1.N`, or when the `default` is looser than the ceiling. A team asking for more than
the ceiling is reported on that team's own `WeeboSiTeam` status too.

## Known limitations, specific to this feature

- **Existing pods are not evicted.** Upstream checks pods at creation only. A workspace keeps its
  current pod until it restarts.
- **`baseline` relies on the node for seccomp.** Without `seccompDefault: true`, a pod that sets
  no profile runs unconfined and `baseline` admits it.
- **Nested containers are invisible to Pod Security.** A `podman run` inside a build workspace is
  not a pod; the user namespace and the seccomp profile are what bound it. See RFC 0013's *Nested
  containers are invisible to image-policy*.
- **The envtest proves what is written and what the apiserver warns about**, not that a pod is
  refused. That is upstream's admission plugin, and the kind e2e is where it is checked.
- **Removing the configuration block leaves the labels in place.** Covered under *Rollback*.
