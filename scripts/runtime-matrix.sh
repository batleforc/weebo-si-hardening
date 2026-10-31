#!/bin/sh
# Measure the RFC 0013 seccomp profiles against nested builds and runs, per container runtime.
#
#   scripts/runtime-matrix.sh           print the matrix as a markdown table
#   scripts/runtime-matrix.sh check     same, and fail if a cell differs from what is expected
#
# The local tier: rootless podman on this machine, with the runtime under test as podman's OCI
# runtime. Rootless podman already puts every container in a user namespace, which is the
# `hostUsers: false` situation; `unmask=ALL` stands in for `procMount: Unmasked`; no `/dev/fuse`,
# as on a containerd node without a device plugin. The cluster tier, for runtimes that need root
# (youki, gVisor, Kata), is scripts/runtime-matrix-k8s.sh. See docs/runtime-matrix.md.
#
# Environment:
#   RUNTIMES   runtimes to compare: `crun` (the system's), `runc` (pinned below, through mise),
#              or a path to any OCI runtime binary. Default: "crun runc".
#   PROFILES   profile names under deploy/seccomp/profiles/, without .json.
#              Default: the three production profiles.
#   RUNC_BIN   the runc binary for `runc`, instead of the pinned one fetched through mise (CI).
#   OUT        also write the table to this file.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PROFILE_DIR="$ROOT/deploy/seccomp/profiles"
RUNTIMES=${RUNTIMES:-"crun runc"}
PROFILES=${PROFILES:-"weebo-container-build weebo-container-build-chroot weebo-workspace"}
RUNC_VERSION=1.5.2 # = RUNC_VERSION in .github/workflows/runtime-matrix.yaml

# Pinned by digest, so a cell changes because a runtime or a profile changed, not an image.
BUILDAH=quay.io/buildah/stable@sha256:77a555756c942f4f0e2916a2a95bace8f109622201b3b70b008a597cf5b7aa69
PODMAN=quay.io/podman/stable@sha256:90c7dcc328ae74710338fbb37f4505fafe38e63c93cfa61b43e1907d0817871a
BUSYBOX=quay.io/libpod/busybox@sha256:a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d

# id | image | user | /proc | command. Every build has a RUN step, so it really starts a container.
SCENARIOS="buildah-chroot|$BUILDAH|build|masked|buildah build --storage-driver=overlay -t t /ctx
buildah-oci|$BUILDAH|build|unmasked|buildah build --isolation oci --network host --storage-driver=overlay -t t /ctx
podman-build|$PODMAN|podman|masked|podman build -t t /ctx
podman-run|$PODMAN|podman|masked|podman run --rm $BUSYBOX echo ran
podman-run-detached|$PODMAN|podman|unmasked|podman run -d --name s $BUSYBOX sleep 60 && podman exec s true && podman rm -f -t0 s"

# What each profile is expected to do, per scenario and /proc: pass, or fail. The chroot profile
# is for nodes without user namespaces, so without an unmasked /proc: every unmasked scenario
# fails under it. A profile not listed here is measured and printed, never checked.
expected() {
  case "$1:$3" in
    weebo-container-build:*) echo pass ;;
    weebo-workspace:*) echo fail ;;
    weebo-container-build-chroot:masked) echo pass ;;
    weebo-container-build-chroot:unmasked) echo fail ;;
    *) echo "" ;;
  esac
}

resolve_runtime() {
  case "$1" in
    runc)
      if [ -n "${RUNC_BIN:-}" ]; then echo "$RUNC_BIN"; else
        mise x "aqua:opencontainers/runc@$RUNC_VERSION" -- sh -c 'command -v runc' | tail -n 1
      fi ;;
    */*) echo "$1" ;;
    *) command -v "$1" ;;
  esac
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/ctx"
printf 'FROM %s\nRUN echo built > /built\n' "$BUSYBOX" > "$tmp/ctx/Containerfile"

table="$tmp/table.md"
{
  echo "| Runtime | Profile | Scenario | Result |"
  echo "| --- | --- | --- | --- |"
} > "$table"
mismatches=0

for rt in $RUNTIMES; do
  bin=$(resolve_runtime "$rt")
  version=$("$bin" --version 2>/dev/null | head -n 1)
  for profile in $PROFILES; do
    echo "$SCENARIOS" | while IFS='|' read -r id image user proc cmd; do
      unmask=""
      [ "$proc" = unmasked ] && unmask="--security-opt unmask=ALL"
      # shellcheck disable=SC2086 # $unmask is one option or nothing
      if timeout 300 podman --runtime "$bin" run --rm --user "$user" --security-opt label=disable \
        $unmask --security-opt "seccomp=$PROFILE_DIR/$profile.json" \
        -v "$tmp/ctx:/ctx:Z" "$image" sh -c "$cmd" > "$tmp/log" 2>&1; then
        got=pass; cell="✅"
      else
        rc=$?
        got=fail
        why=$(grep -m 1 -iE 'not permitted|denied|error' "$tmp/log" | cut -c 1-80 | tr '|' '/')
        cell="❌ ${why:-exit $rc}"
      fi
      want=$(expected "$profile" "$id" "$proc")
      if [ -n "$want" ] && [ "$want" != "$got" ]; then
        cell="$cell **(expected $want)**"
        echo x >> "$tmp/mismatches"
      fi
      echo "| $rt ($version) | $profile | $id ($proc) | $cell |" >> "$table"
    done
  done
done

[ -f "$tmp/mismatches" ] && mismatches=$(wc -l < "$tmp/mismatches")
cat "$table"
if [ -n "${OUT:-}" ]; then cp "$table" "$OUT"; fi

if [ "${1:-}" = check ] && [ "$mismatches" -gt 0 ]; then
  echo "runtime-matrix: $mismatches cell(s) differ from what is expected" >&2
  exit 1
fi
