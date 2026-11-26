# `devfile-contract`

Tells a developer, at `kubectl apply`, that their devfile was written for older platform rules
or follows a parent that can change under it. A devfile declares the rules it was written for
with one top-level attribute, `weebo.io/platform-contract: <n>`; the platform team bumps
`currentContract` each time a rule changes in a way that can break a devfile, and the User Guide
lists what changed for each number. The feature warns and records a verdict; it refuses a
workspace start only for a contract or a parent an admin listed as denied.

Design and threat model: [RFC 0019](../rfc/0019-devfile-contract.md). Every field:
[`weebosiconfig.md`](../weebosiconfig.md#featuresdevfilecontract).

## Configure it

```yaml
spec:
  features:
    devfileContract:
      mode: DryRun
      namespaceSelector:
        matchLabels: { hardening.weebo.io/workspace-namespace: "true" }
      currentContract: 1
      minimumContract: 1
      minimumSchemaVersion: "2.2.0"
      deniedContracts: []
      deniedParents: []
      onDenied: Deny
```

The developer side, in the devfile:

```yaml
schemaVersion: 2.3.0
attributes:
  weebo.io/platform-contract: 1
parent:
  uri: https://raw.githubusercontent.com/batleforc/WeeboDevImage/v1.4.0/che-min-mise/devfile.yaml
```

## What a developer sees

Under `Enforce`, `kubectl` prints each finding as a `Warning:` line and the workspace is
created. A correct devfile prints nothing.

| Devfile | Warning |
| --- | --- |
| no contract attribute | `devfile has no weebo.io/platform-contract attribute; add "weebo.io/platform-contract: 3" to its attributes` |
| contract not an integer | `weebo.io/platform-contract must be an integer, read as absent; current is 3` |
| contract above `currentContract` | `weebo.io/platform-contract 9 is newer than this platform (3): check the value` |
| contract below `minimumContract` | `devfile written for platform contract 1, minimum is 2: see the User Guide changes for contracts 2 to 3` |
| `parent.uri` on a branch | `devfile parent follows branch "main": pin parent.uri to a tag or a commit` |
| `parent.uri` with no recognisable tag, commit or version | `devfile parent is not pinned to a tag or a commit: pin parent.uri to one` |
| `parent.id` without `version` | `devfile parent "che-min-mise" has no version: set parent.version` |
| `parent.kubernetes` | `devfile parent is a DevWorkspaceTemplate (parent.kubernetes): the workspace itself can change it` |
| dashboard-kept `schemaVersion` below the minimum | `devfile schemaVersion 2.1.0 is below the platform minimum 2.2.0` |

A missing contract counts as `1` and gets only the first line, even when `1` is below the
minimum. The **Che dashboard shows none of these warnings**: its backend drops the `Warning`
headers (RFC 0019, D-10). On that path a developer sees only a refusal; the verdict is still
recorded on the object.

**The verdict**, on every `Enforce` admission, written only when it changed:

```bash
kubectl get dw <name> -o jsonpath='{.metadata.annotations}' | jq 'with_entries(select(.key|startswith("hardening.weebo.io/devfile")))'
# { "hardening.weebo.io/devfile-contract": "unknown",
#   "hardening.weebo.io/devfile-contract-reason": "contract-absent,parent-branch,schema-unknown" }
```

`current`, `outdated` or `unknown` (worst wins: `unknown` > `outdated` > `current`), and the
reason codes from a fixed list. A workspace user can write these annotations, and the webhook
rewrites them at the next admission: do not base a security decision on them.

## The denied list

`deniedContracts` and `deniedParents` are the only path to a refusal, and they are empty by
default. A match refuses a **start** only: a `CREATE`, `spec.started` turning `true`, or a
`spec.template` change while the workspace runs. Any other update — a stop, a finalizer removed
by DevWorkspace Operator, a label — gets a warning instead, so a workspace can always be stopped
and deleted. `onDenied: Warn` turns every refusal into a warning.

The two refusals, joined by `. ` when both match:

```text
Error from server: admission webhook "devworkspaces.hardening.weebo.io" denied the request: devfile parent is denied by the platform (deniedParents entry 1: https://raw.githubusercontent.com/batleforc/WeeboDevImage/v1.2.0/): move parent.uri to a newer version; contract 3 in the User Guide lists them
Error from server: admission webhook "devworkspaces.hardening.weebo.io" denied the request: platform contract 1 is denied (devfiles without weebo.io/platform-contract count as 1): add "weebo.io/platform-contract: 3" and follow the User Guide
```

The parenthesis after `platform contract 1 is denied` appears for contract `1` only. A parent
entry written as `id` reads `(deniedParents entry 2: id che-min-mise): move parent.version to a
newer version; …`. The refusal quotes the admin's entry, normalised (credentials dropped), never
the developer's URI. kubectl prints a bare `Error from server:`, not the RFC mock's `Forbidden`:
the route's denials carry no status reason (seen on kind, Kubernetes 1.35).

A match that is not refused is a warning `<subject>: <action>`, short enough that the
120-character cut keeps the action:

| Subject | Action |
| --- | --- |
| `platform contract 1 is denied` | `this workspace will be refused at its next start` (an update that is not a start, under `onDenied: Deny`) |
| `devfile parent is denied by the platform (deniedParents entry 1)` | the same |
| `platform contract 1 is denied` | `add "weebo.io/platform-contract: 3" and follow the User Guide` (`onDenied: Warn`) |
| `devfile parent is denied by the platform (deniedParents entry 1)` | `move parent.uri to a newer version` for a `uriPrefix` entry, `move parent.version to a newer version` for an `id` entry (`onDenied: Warn`) |

Writing a `uriPrefix`:

- **It stops at a path segment.** It is a prefix after normalisation (scheme and host
  lowercased, `http` read as `https`, a trailing `.` on the host, userinfo, query and fragment
  dropped, unreserved escapes decoded, `.` and `..` resolved), compared without case. Without a
  trailing `/` it matches only whole segments: `…/v1.2.0` denies `…/v1.2.0` and `…/v1.2.0/…`,
  not `…/v1.2.01/…`. The URI is also compared with its path left as written, so an encoded
  `%2e%2e` cannot step out of a denied prefix.
- **Never a scheme alone.** `uriPrefix: "https://"` passes the CRD's validation and denies every
  `https` parent of every workspace start under `Enforce`.
- `deniedContracts: [1]` makes the attribute mandatory: a devfile without it counts as `1`.
- `{id: che-min-mise}` with no `versions` denies every version of that stack, an unversioned
  parent included.

## How it works

- **Where it runs.** On the existing `/mutate/v1alpha1/devworkspaces` route, in a fixed order:
  `network-profiles` workspace gate, `devfile-contract`, `dwoc-pin`, then `team-tools` (RFC 0019
  D-14, RFC 0020). The first refusal wins and stops the rest: a gate refusal beats this
  feature's, and a denied parent is refused before a pin is computed. Otherwise one patch carries
  this feature's annotations, `dwoc-pin`'s pin and `team-tools`' mutations, in that order. No new
  webhook, no new RBAC, no chart change.
- **It reads** `spec.template.attributes` (the contract, and `weebo.io/generator`, logged only),
  `spec.template.parent` as written, the first 4 KiB of the dashboard's `che.eclipse.org/devfile`
  annotation, and `spec.started`/`spec.template` of the old and new object. It never fetches the
  parent.
- **It never errs on a bad devfile**: every parse failure is a verdict, so a malformed devfile
  cannot refuse every workspace under the route's `failurePolicy: Fail`.
- **`DryRun` is invisible to developers**: no warning, no annotation, no refusal. It counts and
  logs exactly what `Enforce` would do.
- **Bounds.** One response carries at most 6 warnings of 120 characters, control characters
  removed, every feature on the route together; `devfile-contract` runs second, so the gate's
  warnings come first.

## Operate it

| Where | What |
| --- | --- |
| `weebo_si_devfile_contract_total{result, mode}` | `result` ∈ `current`, `outdated`, `unknown`, `denied` — the adoption curve of each contract bump |
| `weebo_si_admission_warnings_total{feature="devfile-contract", mode}` | warnings decided, `DryRun` included |
| `weebo_si_admission_requests_total{feature="devfile-contract", outcome="denied"}` | refusals |
| `weebo_si_feature_mode{feature="devfile-contract"}` | the mode in force |
| webhook logs | `devfile-contract namespace=… workspace=… decision=allow\|deny devfile=<verdict> reasons=<codes> contract=<n\|absent> [generator=<excerpt>]`, then the route's `allow`/`deny` line. Never the parent URI |

Alert on any `denied` rate above zero shortly after the denied list changed: a list that refuses
more than intended.

## Roll it out

1. Ship with no block: nothing changes.
2. `mode: DryRun` on one test namespace, then every workspace namespace, for at least a week.
   Watch `weebo_si_devfile_contract_total` by `result` and the log reasons.
3. Fix the devfiles that would warn: pin their parent, add the attribute.
4. `Enforce` on the test namespace, then everywhere. Keep the denied list empty until an incident
   needs it.

**Break-glass and rollback**: `mode: Off` (hot-reloaded, no restart), or empty the denied lists.
`Off` leaves the annotations already written in place; they go stale.

## Failure modes

| Failure | Direction |
| --- | --- |
| webhook down | DevWorkspace writes refused (`failurePolicy: Fail` on the existing route): no workspace starts, stops or is deleted until a replica is Ready |
| `WeeboSiConfig` absent or unparsed | **open**: every feature reads `Off` (house-wide), no warning, no annotation, no refusal |
| `devfileContract` block removed mid-request | **open**: admitted unjudged, logged `devfile=no_config`, not counted in `weebo_si_devfile_contract_total` |
| malformed devfile, attribute or parent | a verdict (`unknown` or `outdated`), never an error: the route's `Fail` cannot turn a bad devfile into a refusal |
| invalid block (`minimumContract` above `currentContract`, a denied contract above `currentContract`, a parent entry with both `uriPrefix` and `id`) | refused at `kubectl apply` by the CRD's CEL rules; the previous configuration stays in force |
| namespace labelled `hardening.weebo.io/exclude` | the route never sees it: nothing judged, nothing written |
| Che dashboard | warnings dropped by its backend (D-10): only refusals and the annotations are visible |
