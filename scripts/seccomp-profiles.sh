#!/bin/sh
# Generate the Localhost seccomp profiles of RFC 0013 from the pinned upstream default.
#
#   scripts/seccomp-profiles.sh          regenerate deploy/seccomp/
#   scripts/seccomp-profiles.sh check    fail if deploy/seccomp/ differs from a regeneration
#
# Every profile is named weebo-*.json and installed under /var/lib/kubelet/seccomp/profiles/, the
# directory Talos writes `machine.seccompProfiles` to, so `localhostProfile:
# profiles/weebo-<name>.json` is the same on Talos, OpenShift and anything else.
#
# The upstream file is moby's default profile, in Docker's format: some rules carry
# `includes`/`excludes` conditions on capabilities and architectures. The OCI format a kubelet
# Localhost profile is read in has no such conditions, and containerd drops the fields — which
# would turn every CAP_SYS_ADMIN-only rule (mount, unshare, bpf, ...) into an unconditional
# allow. So the conditions are resolved here, once, for one architecture and for the capability
# set Pod Security `baseline` allows, and the output carries no condition at all.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DIR="$ROOT/deploy/seccomp"
UPSTREAM="$DIR/upstream/moby-default.json"
# github.com/moby/profiles, tag seccomp/v0.2.4, seccomp/default.json (upstream sha256
# 785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334). The committed copy differs
# only by the final newline the repo's end-of-line hook adds, hence its own checksum here.
UPSTREAM_SHA256=200cf222cf627531184ad85f37bb5b8a96bad37c5a1afbe58627698306734432

# The primary architecture the profiles are resolved for, and its compat sub-architectures.
ARCH=amd64
ARCHES='["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"]'

# Pod Security `baseline`'s allowed added capabilities: the most a workspace container holds.
# A rule gated on a capability outside this set is dropped; a rule excluded for one is kept.
CAPS='["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL",
"CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID",
"CAP_SYS_CHROOT"]'

# What rootless podman/buildah need beyond the default, measured rather than guessed (see
# docs/seccomp-profiles.md): one syscall removed at a time, each of these breaks a build or a
# nested `podman run`. Upstream allows them only with CAP_SYS_ADMIN, which a workspace never
# holds; inside the user namespace a build creates it does, and the kernel then checks that
# namespace's capabilities, so the filter is what stands in the way.
#
# container-build-chroot: chroot isolation, masked /proc — a pod without user namespaces.
#   clone, unshare  create the user namespace (clone: fork/exec with namespace flags)
#   mount, umount2  the overlay storage and the build's mounts
#   pivot_root      crun entering a nested container's root (`podman run`)
BUILD_CHROOT_ALLOW='["clone","unshare","mount","umount2","pivot_root"]'
# container-build: OCI isolation, in a `hostUsers: false` pod with `procMount: Unmasked` — the
# target. crun then builds a real container: the chroot set, plus
#   open_tree, move_mount, mount_setattr  crun's id-mapped and read-only mounts of /sys and /proc
#   sethostname                           the build container's UTS namespace
#   setns                                 joining the namespaces it created
BUILD_ALLOW='["clone","unshare","mount","umount2","pivot_root","open_tree","move_mount",
"mount_setattr","sethostname","setns"]'
# clone3 keeps upstream's ENOSYS in both: glibc falls back to clone, which is allowed.
# The kernel keyring stays closed. ENOSYS rather than EPERM: runc and crun skip joining a session
# keyring on ENOSYS and fail on EPERM.
BUILD_ENOSYS='["keyctl","add_key","request_key"]'

if [ "$(sha256sum "$UPSTREAM" | cut -d' ' -f1)" != "$UPSTREAM_SHA256" ]; then
  echo "seccomp-profiles: $UPSTREAM does not match the pinned sha256" >&2
  exit 1
fi

resolve() {
  jq --sort-keys --arg arch "$ARCH" --argjson arches "$ARCHES" --argjson caps "$CAPS" '
    def has_cap($c): $caps | index($c) != null;
    {
      defaultAction,
      defaultErrnoRet,
      architectures: $arches,
      syscalls: [
        .syscalls[]
        | select((.includes.arches // null) == null or (.includes.arches | index($arch) != null))
        | select((.excludes.arches // null) == null or (.excludes.arches | index($arch) == null))
        | select((.includes.caps // null) == null or all(.includes.caps[]; has_cap(.)))
        | select((.excludes.caps // null) == null or (any(.excludes.caps[]; has_cap(.)) | not))
        | del(.includes, .excludes, .comment)
      ]
    }' "$UPSTREAM"
}

# Remove $names from every rule, drop rules left empty, then append one rule for them.
override() {
  jq --sort-keys --argjson names "$1" --argjson rule "$2" '
    .syscalls |= ([
      .[] | .names -= $names | select(.names | length > 0)
    ] + [$rule + {names: $names}])'
}

build_profile() {
  override "$1" '{"action":"SCMP_ACT_ALLOW"}' \
    | override "$BUILD_ENOSYS" '{"action":"SCMP_ACT_ERRNO","errnoRet":38}'
}

generate() {
  out=$1
  p="$out/profiles"
  mkdir -p "$p"
  resolve > "$p/weebo-workspace.json"
  build_profile "$BUILD_ALLOW" < "$p/weebo-workspace.json" > "$p/weebo-container-build.json"
  build_profile "$BUILD_CHROOT_ALLOW" < "$p/weebo-workspace.json" \
    > "$p/weebo-container-build-chroot.json"
  # Recording only: what the build profile would refuse is logged instead. Never on a node that
  # runs real workspaces — any pod naming it is unfiltered.
  jq --sort-keys '.defaultAction = "SCMP_ACT_LOG" | del(.defaultErrnoRet)' \
    "$p/weebo-container-build.json" > "$p/weebo-container-build-log.json"
  machineconfig > "$out/machineconfig-worker.yaml"
  talos_patch > "$out/talos-patch.yaml"
}

# The production profiles, the ones the two node patches below install. The recording profile is
# deliberately not among them.
PRODUCTION="weebo-workspace.json weebo-container-build.json weebo-container-build-chroot.json"

file_entry() {
  printf '        - path: /var/lib/kubelet/seccomp/profiles/%s\n' "$1"
  printf '          mode: 420\n'
  printf '          overwrite: true\n'
  printf '          contents:\n'
  printf '            source: data:;base64,%s\n' \
    "$(jq -c . "$out/profiles/$1" | base64 | tr -d '\n')"
}

# OpenShift: the production profiles onto every worker. Generated, so it cannot drift from the
# JSON next to it.
machineconfig() {
  cat <<'YAML'
# Generated by scripts/seccomp-profiles.sh — do not edit by hand.
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 99-worker-weebo-seccomp
  labels:
    machineconfiguration.openshift.io/role: worker
spec:
  config:
    ignition:
      version: 3.2.0
    storage:
      files:
YAML
  for f in $PRODUCTION; do file_entry "$f"; done
}

# Talos: a machine config patch (`talosctl patch mc --patch @deploy/seccomp/talos-patch.yaml`, or
# the same entries in the Pulumi program). Talos writes each entry to
# /var/lib/kubelet/seccomp/profiles/<name>. The value is JSON, which is valid YAML.
talos_patch() {
  cat <<'YAML'
# Generated by scripts/seccomp-profiles.sh — do not edit by hand.
machine:
  seccompProfiles:
YAML
  for f in $PRODUCTION; do
    printf '    - name: %s\n' "$f"
    printf '      value: %s\n' "$(jq -c . "$out/profiles/$f")"
  done
}

case "${1:-gen}" in
  gen)
    rm -rf "$DIR/profiles"
    generate "$DIR"
    echo "seccomp-profiles: regenerated $DIR"
    ;;
  check)
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    generate "$tmp"
    for f in profiles/weebo-workspace.json profiles/weebo-container-build.json \
      profiles/weebo-container-build-chroot.json profiles/weebo-container-build-log.json \
      machineconfig-worker.yaml talos-patch.yaml; do
      if ! cmp -s "$tmp/$f" "$DIR/$f"; then
        echo "seccomp-profiles: deploy/seccomp/$f is stale — run task seccomp:gen" >&2
        exit 1
      fi
    done
    echo "seccomp-profiles: up to date"
    ;;
  *)
    echo "usage: $0 [gen|check]" >&2
    exit 2
    ;;
esac
