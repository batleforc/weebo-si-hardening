# Runtime matrix

Which container runtime should run workspaces? [RFC 0013](./rfc/0013-pod-security.md) isolates a
build workspace with a user namespace and a `Localhost` seccomp profile
([`seccomp-profiles.md`](./seccomp-profiles.md)). Both depend on the runtime that starts the pod.
This page describes the harness that compares runtimes on the same scenarios, how to run it, how
to add a runtime, and what has been measured so far.

The harness lives in this repo and only reads the clusters it runs against. Installing a runtime
or a profile on weebo-si's nodes is done in weebo-si, never from here.

## What is compared

| Runtime | Where it comes from | Tier it can be measured in |
| --- | --- | --- |
| runc | containerd's default; the weebo-si default | local and cluster |
| crun | `siderolabs/crun` extension, installed on weebo-si | local and cluster |
| youki | `siderolabs/youki` extension, installed on weebo-si | cluster only — refuses rootless podman (`unprivileged user can't set supplementary groups`) |
| gVisor (`runsc`) | `siderolabs/gvisor` extension, not installed | cluster only — refuses rootless podman (`cannot set up cgroup`) |
| Kata Containers | `siderolabs/kata-containers` extension, not installed | cluster only — needs virtualization on the node |
| wasmedge | `siderolabs/wasmedge` extension, installed | not compared: it runs WebAssembly modules, not workspace images |

### Scenarios

Each scenario runs as a non-root user (UID 1000), in a user namespace, without `CAP_SYS_ADMIN` and
without `/dev/fuse`. Every build has a `RUN` step, so it really starts a nested container.

| Scenario | Image | `/proc` | What it does |
| --- | --- | --- | --- |
| `buildah-chroot` | `quay.io/buildah/stable` | masked | `buildah build`, chroot isolation |
| `buildah-oci` | `quay.io/buildah/stable` | unmasked | `buildah build --isolation oci --network host`: a real OCI container per `RUN` |
| `podman-build` | `quay.io/podman/stable` | masked | `podman build` |
| `podman-run` | `quay.io/podman/stable` | masked | nested `podman run` |
| `podman-run-detached` | `quay.io/podman/stable` | unmasked | `podman run -d`, then `exec` and `rm` |

Images are pinned by digest in both scripts, so a cell changes only when a runtime or a profile
changes.

Each scenario runs under each profile. The profiles double as a check that the runtime applies
them at all:

| Profile | Expected | If it does not happen |
| --- | --- | --- |
| `weebo-container-build` | every scenario passes | the runtime needs a syscall the profile lacks |
| `weebo-container-build-chroot` | masked scenarios pass, unmasked ones fail | as above, or the runtime treats `/proc` differently |
| `weebo-workspace` | every scenario fails | **the runtime is not enforcing the pod's profile** |

The last row matters most for sandboxed runtimes. By default, gVisor does not load the OCI seccomp
filter inside its sandbox (`runsc --oci-seccomp` is off), and Kata does not apply it in its guest
(`disable_guest_seccomp = true`). Both have their own isolation instead. If either passes a
scenario under `weebo-workspace`, the profile is being ignored, and the comparison has to weigh
their sandbox against a filter that is not there. These defaults come from upstream
configuration and have not been measured here yet.

## The two tiers

### Local: rootless podman

[`scripts/runtime-matrix.sh`](../scripts/runtime-matrix.sh) uses the runtime under test as
podman's OCI runtime (`podman --runtime`). Rootless podman already puts every container in a user
namespace, which is the `hostUsers: false` situation. `--security-opt unmask=ALL` stands in for
`procMount: Unmasked`.

```bash
task runtimes:local                                   # crun (the system's) and runc (pinned)
RUNTIMES="crun /path/to/other-runtime" task runtimes:local
```

`check` mode, which the task uses, fails when a cell differs from the *Expected* column above.
`runc` is pinned (1.5.2) and fetched through mise, so it needs no system package.

### Cluster: Pods

[`scripts/runtime-matrix-k8s.sh`](../scripts/runtime-matrix-k8s.sh) runs the same scenarios as
Pods, one per runtime class × profile × scenario. Each Pod has:

- `hostUsers: false`;
- `runtimeClassName`, unless the class is `default`;
- the profile as `seccompProfile: {type: Localhost, localhostProfile: profiles/<profile>.json}`;
- `allowPrivilegeEscalation: true`, and `procMount: Unmasked` for the unmasked scenarios.

The namespace carries a Pod Security level, so an admission refusal is reported as a result. That
is how the matrix answers RFC 0013's open question: does `baseline` admit `procMount: Unmasked`
on a user-namespaced pod at the pinned version?

```bash
# against the current kubectl context
RUNTIME_CLASSES="default crun youki gvisor kata" PSA_LEVEL=baseline task runtimes:k8s
task runtimes:k8s:clean
```

What the nodes need:

- the profiles under `/var/lib/kubelet/seccomp/profiles/`
  ([`deploy/seccomp/`](../deploy/seccomp/), see *Installing on the nodes* in
  [`seccomp-profiles.md`](./seccomp-profiles.md));
- for every class other than `default`, the objects in
  [`e2e/runtime-matrix/runtimeclasses.yaml`](../e2e/runtime-matrix/runtimeclasses.yaml) and the
  matching handler.

A missing profile or handler shows up as a `CreateContainerError` cell, not as a hang.

Use a test cluster, not weebo-si: the matrix creates Pods that build images and run nested
containers, at whichever Pod Security level it is given.

On kind (`default` class only, since kind nodes ship runc alone):

```bash
task runtimes:kind        # creates weebo-runtimes from e2e/runtime-matrix/kind.yaml, runs the matrix
task runtimes:kind:down
```

kind could not start a node on a Fedora laptop under rootless podman with SELinux enforcing:
`mount: must be superuser`, then `can't read /etc/containerd/config.toml`. A plain kind
configuration fails the same way, so the cause is the host, not this configuration. Under rootful
docker, which is what CI uses, it works.

### In CI

[`runtime-matrix`](../.github/workflows/runtime-matrix.yaml) runs the local tier in `check` mode
on pull requests that touch the profiles or the harness, weekly, and on demand. The kind tier runs
on the same triggers, at `baseline` and then `privileged`, so an admission refusal and a runtime
failure can be told apart. The kind tier only reports. Both tables go to the job summary.

## Adding a runtime

1. **Local tier**, if it runs under rootless podman: pass its binary in `RUNTIMES`. If it does not,
   record the error in the table above, as for youki and gVisor.
2. **Cluster tier:** install its handler on a test cluster's nodes, add a `RuntimeClass` to
   `e2e/runtime-matrix/runtimeclasses.yaml`, and add its class to `RUNTIME_CLASSES`.
3. **Read the `weebo-workspace` rows first:** they say whether the runtime enforces the profile at
   all.
4. Record the result under *Results* with the runtime's version and the date.

## Results

### Local tier, 2026-10-31

Fedora 44, kernel 7.2.13, podman 5.8.9 rootless, inner podman 5.8.9 / buildah 1.43.5 / crun 1.28.

| Runtime | `weebo-container-build` | `weebo-container-build-chroot` | `weebo-workspace` |
| --- | --- | --- | --- |
| crun 1.28 | ✅ 5/5 | ✅ masked 3/3, ❌ unmasked 2/2 | ❌ 5/5 (`unshare(CLONE_NEWUSER)` / `cannot clone`) |
| runc 1.5.2 | ✅ 5/5 | ✅ masked 3/3, ❌ unmasked 2/2 | ❌ 5/5 (same) |

runc and crun give the same result on every cell. The node's runtime applies the filter, and the
syscalls the scenarios need come from the tools inside the workspace. So for these two runtimes,
the choice does not change the profiles.

**No `/dev/fuse` needed.** Every scenario passes without it: buildah and podman use the kernel's
native overlay inside a user namespace. On a containerd node, a pod has no `/dev/fuse` without a
device plugin, so this matters for weebo-si.

### Cluster tier

Not measured yet. The kind tier's first CI run will give the `default` (runc) row, and answer the
`baseline` admission question. youki, gVisor and Kata need a test cluster with their handlers.
