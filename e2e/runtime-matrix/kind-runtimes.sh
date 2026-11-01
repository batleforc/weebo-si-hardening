#!/bin/sh
# Give a kind node the runtimes weebo-si ships besides runc — crun and youki (the siderolabs
# extensions) — plus gVisor, and the RuntimeClass objects that select them. kind nodes ship runc
# alone; this is what lets the runtime matrix's cluster tier compare them in CI.
#
# Kata is not installed: its static bundle is a gigabyte and it needs virtualization the runner's
# kind node does not have. It is measured on a test cluster (docs/runtime-matrix.md).
#
#   e2e/runtime-matrix/kind-runtimes.sh [node]    default node: weebo-runtimes-control-plane
#   ENGINE=podman e2e/runtime-matrix/kind-runtimes.sh
#
# Every binary is pinned by version and checksum. Bump them together.
set -eu

NODE=${1:-weebo-runtimes-control-plane}
ENGINE=${ENGINE:-docker}

CRUN_VERSION=1.30.1
CRUN_SHA256=86d1e6a0e76945975d3aebfab39cbc6a26eea15f1c3fc66b6776d19e5dc346a0
YOUKI_VERSION=0.7.0
YOUKI_SHA256=a211a16b6b1a985f8ca61bba9a30b9ae40352d04dd7eca04cdecfe7b98b47038
GVISOR_RELEASE=20261026
GVISOR_SHA256=096589d2d6078ba4caa26aa0200932f571aa5da9d08a5156b98ab1d93fa54468

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # url out sha256
  curl -fsSL -o "$2" "$1"
  echo "$3  $2" | sha256sum -c - >/dev/null
}

fetch "https://github.com/containers/crun/releases/download/$CRUN_VERSION/crun-$CRUN_VERSION-linux-amd64" \
  "$work/crun" "$CRUN_SHA256"
fetch "https://github.com/youki-dev/youki/releases/download/v$YOUKI_VERSION/youki-$YOUKI_VERSION-x86_64-musl.tar.gz" \
  "$work/youki.tgz" "$YOUKI_SHA256"
fetch "https://storage.googleapis.com/gvisor/releases/release/$GVISOR_RELEASE/x86_64/gvisor.tar.bz2" \
  "$work/gvisor.tar.bz2" "$GVISOR_SHA256"
tar xzf "$work/youki.tgz" -C "$work" youki
# The whole bundle: runsc starts its sandbox through the helpers in gvisor-bin/ (gvisor_sentry, ...).
tar xjf "$work/gvisor.tar.bz2" -C "$work"
chmod 0755 "$work/crun" "$work/youki" "$work/runsc" "$work/containerd-shim-runsc-v1"
for binary in crun youki runsc containerd-shim-runsc-v1 gvisor-bin; do
  "$ENGINE" cp "$work/$binary" "$NODE:/usr/local/bin/$binary"
done

# containerd 2 writes its CRI runtimes under `io.containerd.cri.v1.runtime`; containerd 1.x under
# `io.containerd.grpc.v1.cri`. Whichever the node's config already uses is the one appended to.
if "$ENGINE" exec "$NODE" grep -q "io.containerd.cri.v1.runtime" /etc/containerd/config.toml; then
  prefix="plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes"
else
  prefix="plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes"
fi
cat > "$work/runtimes.toml" <<EOF

[$prefix.crun]
  runtime_type = 'io.containerd.runc.v2'
  [$prefix.crun.options]
    BinaryName = '/usr/local/bin/crun'

[$prefix.youki]
  runtime_type = 'io.containerd.runc.v2'
  [$prefix.youki.options]
    BinaryName = '/usr/local/bin/youki'

[$prefix.runsc]
  runtime_type = 'io.containerd.runsc.v1'
EOF
# Through stdin, not `cp`: the node's /tmp is a tmpfs `docker cp` does not write into.
"$ENGINE" exec -i "$NODE" sh -c 'cat >> /etc/containerd/config.toml' < "$work/runtimes.toml"
"$ENGINE" exec "$NODE" systemctl restart containerd
kubectl wait --for=condition=Ready node --all --timeout=120s >/dev/null

# Kata's class is left out: no handler, and a class with no handler is a CreateContainerError on
# every cell rather than a measurement.
kubectl apply -f "$ROOT/e2e/runtime-matrix/runtimeclasses.yaml" -l 'weebo.io/runtime notin (kata)' >/dev/null
printf 'runtimes: crun %s, youki %s, gVisor %s\n' "$CRUN_VERSION" "$YOUKI_VERSION" "$GVISOR_RELEASE"
"$ENGINE" exec "$NODE" sh -c 'crun --version | head -1; youki --version | head -1; runsc --version | head -1'
