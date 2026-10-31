# Seccomp profiles for workspace nodes

[RFC 0013](./rfc/0013-pod-security.md) puts every workspace namespace under a Pod Security level.
A team doing container builds needs `baseline`, and `baseline` does not require a seccomp profile.
This page covers the two `Localhost` profiles that give those teams a syscall filter anyway: what
they contain, how they were measured, and how they reach the nodes.

## The profiles

| File | `localhostProfile` | For |
| --- | --- | --- |
| [`deploy/seccomp/weebo/workspace.json`](../deploy/seccomp/weebo/workspace.json) | `weebo/workspace.json` | Any workspace. The upstream default, the same on every container runtime. |
| [`deploy/seccomp/weebo/container-build.json`](../deploy/seccomp/weebo/container-build.json) | `weebo/container-build.json` | Workspaces that run rootless `podman` / `buildah`. |
| [`deploy/seccomp/weebo/container-build-log.json`](../deploy/seccomp/weebo/container-build-log.json) | `weebo/container-build-log.json` | **Test nodes only.** The build profile, but anything it would refuse is logged and allowed. |

All three are generated, never edited by hand:

```bash
task seccomp:gen     # regenerate deploy/seccomp/ from the pinned upstream file
task seccomp:check   # fail if deploy/seccomp/ is stale (part of `task lint`)
```

The source is moby's default profile, `github.com/moby/profiles` tag `seccomp/v0.2.4`, committed
as [`deploy/seccomp/upstream/moby-default.json`](../deploy/seccomp/upstream/moby-default.json) and
checked against its sha256 by [`scripts/seccomp-profiles.sh`](../scripts/seccomp-profiles.sh).
To move to a newer upstream, replace the file, update the checksum in the script, regenerate, and
measure again.

### Why the upstream file is not used directly

The upstream file is in Docker's format. Some of its rules apply only when the container holds a
capability: `mount`, `unshare`, `bpf` and about twenty others are allowed only with
`CAP_SYS_ADMIN`. A kubelet `Localhost` profile is read in the OCI format, which has no such
condition, and containerd drops the field. Used as-is, every one of those rules would become an
unconditional allow.

The generator resolves each condition once, and writes profiles without any:

- **Architecture:** `amd64`, with its `x86` and `x32` compatibility modes. Rules for other
  architectures are dropped.
- **Capabilities:** the set Pod Security `baseline` allows a container to add — `AUDIT_WRITE`,
  `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `MKNOD`, `NET_BIND_SERVICE`, `SETFCAP`,
  `SETGID`, `SETPCAP`, `SETUID`, `SYS_CHROOT`. A rule that requires anything else
  (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_BPF`...) is dropped. A rule excluded for one of them is
  kept.

The `restricted` level drops every capability. Rules gated on a capability the container does not
hold stay harmless: the kernel's own capability check still refuses the call.

### What the build profile adds

The workspace profile, plus:

| Syscalls | Action | Why |
| --- | --- | --- |
| `clone`, `unshare` | allow, without argument filter | create the user namespace a rootless build runs in |
| `mount`, `umount2` | allow | overlay storage, and the build's own mounts |
| `pivot_root` | allow | crun entering a nested container's root (`podman run`) |
| `keyctl`, `add_key`, `request_key` | `ENOSYS` | the kernel keyring stays closed; runc and crun skip the session keyring on `ENOSYS` |

`clone3` keeps upstream's `ENOSYS`: glibc then falls back to `clone`.

Inside the user namespace a build creates, the process holds `CAP_SYS_ADMIN` over that namespace,
and the kernel checks those capabilities, not the host's. Upstream refuses these calls for any
container without `CAP_SYS_ADMIN`, so for a rootless build the seccomp filter is the only thing in
the way. Everything else upstream reserves for `CAP_SYS_ADMIN` stays refused: `setns`, `bpf`,
`perf_event_open`, `syslog`, `quotactl`, `sethostname`, and the new mount API (`fsopen`,
`move_mount`, ...).

## How it was measured

Each candidate was tested as a workspace runs: as a non-root user, with `/dev/fuse`, with the
runtime's default capabilities and no `CAP_SYS_ADMIN`, under rootless podman.

```bash
podman run --rm --user build --device /dev/fuse --security-opt label=disable \
  --security-opt seccomp=deploy/seccomp/weebo/container-build.json \
  -v ./ctx:/ctx:Z quay.io/buildah/stable:latest \
  buildah build --storage-driver=overlay -t t /ctx
```

Scenarios: `buildah build` (chroot isolation, as `quay.io/buildah/stable` sets it), `podman build`
and a nested `podman run` (`quay.io/podman/stable`).

| Profile | `buildah build` | `podman build` | `podman run` |
| --- | --- | --- | --- |
| podman's default (`containers/common`, = CRI-O's `RuntimeDefault`) | ✅ | ✅ | ✅ |
| `workspace.json` (= containerd/moby `RuntimeDefault`) | ❌ `unshare(CLONE_NEWUSER)` | ❌ `cannot clone` | ❌ `cannot clone` |
| `container-build.json` | ✅ | ✅ | ✅ |

The five added syscalls were found by elimination. Starting from a broader set (the five, plus
`setns`, `umount`, `sethostname`, `setdomainname`, `clone3` and the new mount API), each was
removed in turn:

| Removed | Result |
| --- | --- |
| `clone` | `fork/exec /proc/self/exe: operation not permitted` |
| `unshare` | `unshare(CLONE_NEWUSER): Operation not permitted` |
| `mount` | `overlay: failed to make mount private` |
| `umount2` | build fails after `failed to unmount check directory` |
| `pivot_root` | nested `podman run`: `crun: pivot_root: Operation not permitted` |
| any other | all three scenarios pass |

Versions: podman 5.8.9, buildah 1.43.5, crun 1.28, kernel 7.2.13 (Fedora 44), on 2026-10-31.

**Measure again when podman or crun changes in the workspace image.** A newer crun may move to the
new mount API and need `fsopen` / `fsmount` / `move_mount`. Two ways to find out:

- Run the same commands with the fleet's workspace image instead of `quay.io/*/stable`.
- On a **test node**, use `weebo/container-build-log.json`. What the build profile would refuse is
  allowed and logged to the audit log (`type=SECCOMP`) instead. Each logged syscall is a candidate
  to add. Never install it on a node that runs real workspaces: any pod naming it is unfiltered.

### What seccomp does not fix

`buildah build --isolation oci` fails on `open /proc/sys/net/ipv4/ping_group_range`, even with
podman's own default profile. That is a masked `/proc/sys`, not a syscall: it is Che's
container-run mode (unmasked `/proc`, user namespaces), and it is a `procMount` and Pod Security
level question. See RFC 0013's *Unresolved questions*.

## Installing on the nodes

The kubelet reads `Localhost` profiles relative to `/var/lib/kubelet/seccomp/`, so the files go to
`/var/lib/kubelet/seccomp/weebo/`. **Install them before any DWOC references them:** a pod naming
a profile that is missing on its node fails with `CreateContainerError`.

### OpenShift

[`deploy/seccomp/machineconfig-worker.yaml`](../deploy/seccomp/machineconfig-worker.yaml) is
generated with the two production profiles embedded. The log profile is deliberately left out.

```bash
oc apply -f deploy/seccomp/machineconfig-worker.yaml   # the worker pool reboots, node by node
```

The SCC a building workspace runs under must also allow the profile. Check the one Che grants for
container builds:

```bash
oc get scc container-build -o jsonpath='{.seccompProfiles}'
```

If `localhost/weebo/container-build.json` is not listed, use a copy of that SCC with it added to
`seccompProfiles`, granted the same way Che grants the original.

### Kubernetes

The same two files, by whatever manages the nodes' configuration: the image the nodes boot from,
a configuration management tool, or Security Profiles Operator `SeccompProfile` objects. Security
Profiles Operator writes under `operator/<namespace>/`, so `localhostProfile` changes accordingly.

For kind, mount the directory into each node:

```yaml
nodes:
  - role: worker
    extraMounts:
      - hostPath: ./deploy/seccomp/weebo
        containerPath: /var/lib/kubelet/seccomp/weebo
        readOnly: true
```

## Using a profile

The profile is chosen in the DWOC a team's workspaces use. That DWOC is routed by `dwoc-pin`
([RFC 0002](./rfc/0002-weebo-si-operator.md)):

```yaml
apiVersion: controller.devfile.io/v1alpha1
kind: DevWorkspaceOperatorConfig
metadata:
  name: team-build
  namespace: weebo-si-hardening
config:
  workspace:
    podSecurityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: weebo/container-build.json
```

The team's Pod Security level stays `baseline`. Builds also need `allowPrivilegeEscalation` for
`newuidmap`/`newgidmap`, which `restricted` refuses whatever the seccomp profile. Every other team
keeps `RuntimeDefault`, or uses `weebo/workspace.json` on a cluster that mixes runtimes and wants
one filter everywhere.
