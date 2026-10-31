# Seccomp profiles for workspace nodes

[RFC 0013](./rfc/0013-pod-security.md) puts every workspace namespace under a Pod Security level.
A team doing container builds needs `baseline`, and `baseline` does not require a seccomp profile.
This page covers the `Localhost` profiles that give those teams a syscall filter anyway: what they
contain, how they were measured, and how they reach the nodes.

A build workspace is isolated in two layers: a **user namespace** for the pod (`hostUsers:
false`), which makes an escape land on the node as an unprivileged UID, and one of these
**profiles**, which narrows the kernel surface a build reaches. The first limits what an escape is
worth. The second makes one harder: creating nested user namespaces and mounting inside them is
where most recent kernel privilege escalations start, and a build has to do both.

## The profiles

| File | `localhostProfile` | For |
| --- | --- | --- |
| [`deploy/seccomp/weebo/workspace.json`](../deploy/seccomp/weebo/workspace.json) | `weebo/workspace.json` | Any workspace. The upstream default, the same on every container runtime. |
| [`deploy/seccomp/weebo/container-build.json`](../deploy/seccomp/weebo/container-build.json) | `weebo/container-build.json` | Build workspaces with `hostUsers: false` and `procMount: Unmasked`: rootless `podman` / `buildah` with OCI isolation. **The target.** |
| [`deploy/seccomp/weebo/container-build-chroot.json`](../deploy/seccomp/weebo/container-build-chroot.json) | `weebo/container-build-chroot.json` | Build workspaces on nodes without user namespaces: chroot isolation only. |
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

The pod's user namespace does not change this: capabilities are then held over that namespace,
and the same rules apply. The `restricted` level drops every capability. Rules gated on a capability the container does not
hold stay harmless: the kernel's own capability check still refuses the call.

### What the build profiles add

The workspace profile, plus:

| Syscalls | `container-build-chroot` | `container-build` | Why |
| --- | --- | --- | --- |
| `clone`, `unshare` | allow | allow | create the user namespace a rootless build runs in (`clone` without argument filter) |
| `mount`, `umount2` | allow | allow | overlay storage, and the build's own mounts |
| `pivot_root` | allow | allow | crun entering a nested container's root (`podman run`) |
| `open_tree`, `move_mount`, `mount_setattr` | — | allow | crun's id-mapped and read-only mounts of `/sys` and `/proc` for an OCI build container |
| `sethostname` | — | allow | the build container's UTS namespace |
| `setns` | — | allow | joining the namespaces crun created |
| `keyctl`, `add_key`, `request_key` | `ENOSYS` | `ENOSYS` | the kernel keyring stays closed; runc and crun skip the session keyring on `ENOSYS` |

`clone3` keeps upstream's `ENOSYS` in both: glibc then falls back to `clone`.

Inside the user namespace a build creates, the process holds `CAP_SYS_ADMIN` over that namespace,
and the kernel checks those capabilities, not the host's. Upstream refuses these calls for any
container without `CAP_SYS_ADMIN`, so for a rootless build the seccomp filter is the only thing in
the way. Everything else upstream reserves for `CAP_SYS_ADMIN` stays refused: `bpf`,
`perf_event_open`, `syslog`, `quotactl`, `setdomainname`, `fsopen`, `fsconfig`, `fsmount`,
`fspick`.

## How it was measured

Each candidate was tested as a workspace runs: as a non-root user, with `/dev/fuse`, with the
runtime's default capabilities and no `CAP_SYS_ADMIN`, under rootless podman — so inside a user
namespace, as in a `hostUsers: false` pod. `--security-opt unmask=ALL` stands in for
`procMount: Unmasked`.

```bash
podman run --rm --user build --device /dev/fuse --security-opt label=disable \
  --security-opt unmask=ALL \
  --security-opt seccomp=deploy/seccomp/weebo/container-build.json \
  -v ./ctx:/ctx:Z quay.io/buildah/stable:latest \
  buildah build --isolation oci --network host --storage-driver=overlay -t t /ctx
```

The `Containerfile` has a `RUN` step, so the build really starts a container.

| Profile | `/proc` | `buildah` chroot | `podman build` | `podman run` | `buildah` OCI |
| --- | --- | --- | --- | --- | --- |
| podman's default (`containers/common`, = CRI-O's `RuntimeDefault`) | masked | ✅ | ✅ | ✅ | ❌ `/proc/sys` |
| `workspace.json` (= containerd/moby `RuntimeDefault`) | either | ❌ `unshare(CLONE_NEWUSER)` | ❌ `cannot clone` | ❌ `cannot clone` | ❌ `unshare(CLONE_NEWUSER)` |
| `container-build-chroot.json` | masked | ✅ | ✅ | ✅ | ❌ |
| `container-build-chroot.json` | unmasked | — | ✅ | ✅ | ❌ `open_tree /sys` |
| `container-build.json` | masked | ✅ | ✅ | ✅ | — |
| `container-build.json` | unmasked | — | ✅ | ✅ | ✅ |

The syscalls were found by elimination: starting from a broader set, each was removed in turn.

| Removed | Result |
| --- | --- |
| `clone` | `fork/exec /proc/self/exe: operation not permitted` |
| `unshare` | `unshare(CLONE_NEWUSER): Operation not permitted` |
| `mount` | `overlay: failed to make mount private` |
| `umount2` | build fails after `failed to unmount check directory` |
| `pivot_root` | nested `podman run`: `crun: pivot_root: Operation not permitted` |
| `open_tree` | OCI build: `open_tree /sys: Operation not permitted` |
| `move_mount` | OCI build: `move mount to /proc/self/fd/…` refused |
| `mount_setattr` | OCI build: `mount_setattr /sys: Operation not permitted` |
| `sethostname` | OCI build: `sethostname: Operation not permitted` |
| `setns` | OCI build: `did not get container start message from parent` |
| `umount`, `setdomainname`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `clone3` | every scenario passes |

Versions: podman 5.8.9, buildah 1.43.5, crun 1.28, kernel 7.2.13 (Fedora 44), on 2026-10-31.

**Builds use the pod's network.** An OCI build with pasta, rootless podman's default network, needs
`/dev/net/tun`. A pod has no `/dev/net/tun` by default, and the build fails even unconfined.
`--network host` (or `netns="host"` in the workspace image's `containers.conf`) puts the build in
the pod's network namespace. That is also the one `network-profiles` writes policy for, so a build
reaches exactly what its workspace reaches.

### Running containers (Che's container-run mode)

`container-build.json` also covers running containers, with no syscall added. Measured in the same
setup, with `/dev/net/tun` as that mode provides it:

| Scenario | `container-build.json` | `container-build-chroot.json` |
| --- | --- | --- |
| `podman run` with pasta networking | ✅ | ❌ `pasta failed` |
| `podman run -d`, then `exec` and `stop` | ✅ | ❌ |
| `podman pod create` and a container in it | ✅ | — |
| `podman run --userns=keep-id` | ✅ | — |
| `podman network create` and a container on it | ✅ | — |
| egress from a nested container | ✅ | — |

Publishing a port (`-p`) could not be checked here: it failed the same way with every syscall
allowed, so the cause is this test setup, not the profile. To check on the kind e2e.

A nested container's traffic leaves through the pod's network namespace, so `network-profiles`
applies to it. A published port stays inside the pod unless a Service or a route exposes it.
**The images it runs are not checked by `image-policy`**, which only sees the pod's own spec: see
RFC 0013's *Future work* for the per-team `policy.json` that would close that.

A caveat on `podman build` with `BUILDAH_ISOLATION=oci`: it passed even under the chroot profile,
which suggests podman did not switch isolation. `buildah build --isolation oci` is the reference
for OCI isolation.

**Measure again when podman or crun changes in the workspace image.** A newer crun may use more of
the new mount API and need `fsopen` / `fsmount`. Two ways to find out:

- Run the same commands with the fleet's workspace image instead of `quay.io/*/stable`.
- On a **test node**, use `weebo/container-build-log.json`. What the build profile would refuse is
  allowed and logged to the audit log (`type=SECCOMP`) instead. Each logged syscall is a candidate
  to add. Never install it on a node that runs real workspaces: any pod naming it is unfiltered.

## Installing on the nodes

The kubelet reads `Localhost` profiles relative to `/var/lib/kubelet/seccomp/`, so the files go to
`/var/lib/kubelet/seccomp/weebo/`. **Install them before any DWOC references them:** a pod naming
a profile that is missing on its node fails with `CreateContainerError`.

### OpenShift

[`deploy/seccomp/machineconfig-worker.yaml`](../deploy/seccomp/machineconfig-worker.yaml) is
generated with the three production profiles embedded. The log profile is deliberately left out.

```bash
oc apply -f deploy/seccomp/machineconfig-worker.yaml   # the worker pool reboots, node by node
```

The SCC a building workspace runs under must also allow the profile. Check the one Che grants for
container builds:

```bash
oc get scc container-build -o jsonpath='{.seccompProfiles}'
```

If `localhost/weebo/container-build.json` is not listed, use a copy of that SCC with it added to
`seccompProfiles`, granted the same way Che grants the original. The SCC must also allow user
namespaces for the pod and `procMount: Unmasked`.

### Kubernetes

The same files, by whatever manages the nodes' configuration: the image the nodes boot from,
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
([RFC 0002](./rfc/0002-weebo-si-operator.md)). A build team's DWOC sets the user namespace, the
unmasked `/proc` and the profile together:

```yaml
apiVersion: controller.devfile.io/v1alpha1
kind: DevWorkspaceOperatorConfig
metadata:
  name: team-build
  namespace: weebo-si-hardening
config:
  workspace:
    hostUsers: false
    podSecurityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: weebo/container-build.json
    containerSecurityContext:
      procMount: Unmasked
```

On nodes without user namespaces, drop `hostUsers` and `procMount`, and use
`weebo/container-build-chroot.json`: builds then run with chroot isolation only.

The team's Pod Security level stays `baseline`. Builds also need `allowPrivilegeEscalation` for
`newuidmap`/`newgidmap`, which `restricted` refuses whatever the seccomp profile. Whether the
pinned standards version admits `procMount: Unmasked` with `hostUsers: false` is an open question
in RFC 0013. Every other team keeps `RuntimeDefault`, or uses `weebo/workspace.json` on a cluster
that mixes runtimes, and is worth giving `hostUsers: false` too where the nodes support it.
