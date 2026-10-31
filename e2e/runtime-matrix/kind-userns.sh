#!/bin/sh
# Make a kind node start Pods with `hostUsers: false`. Out of the box it cannot, for two reasons
# that a real node does not have:
#
#   1. A user-namespaced Pod mounts its own sysfs, and the kernel allows that only when the sysfs
#      it would reveal is fully visible already: nothing mounted over a file or a non-empty
#      directory. kind bind-mounts its own product_name and product_uuid over
#      /sys/devices/virtual/dmi/id/ (product_uuid twice), so every sandbox fails with
#      `error mounting "sysfs" to rootfs at "/sys": operation not permitted`.
#   2. A createContainer hook in containerd's base OCI spec mounts the same files into every
#      container, and it cannot run inside a user namespace:
#      `fork/exec /kind/bin/mount-product-files.sh: permission denied`.
#
# This lifts both on the node: unmount what is stacked under /sys/devices/ (and any tmpfs mask),
# drop the hook from the base spec, restart containerd. A one-node test cluster does not need a
# unique product_uuid. Use it on a throwaway kind node only.
#
#   e2e/runtime-matrix/kind-userns.sh [node]    default node: weebo-runtimes-control-plane
#   ENGINE=podman e2e/runtime-matrix/kind-userns.sh
set -eu

NODE=${1:-weebo-runtimes-control-plane}
ENGINE=${ENGINE:-docker}

# shellcheck disable=SC2016 # expanded by the node's shell, not this one
"$ENGINE" exec "$NODE" sh -c '
  findmnt -rno TARGET,FSTYPE -R /sys \
    | awk "\$1 ~ \"^/sys/devices/\" || \$2 == \"tmpfs\" || \$2 == \"devtmpfs\" {print \$1}" \
    | sort -r | while read -r m; do while umount "$m" 2>/dev/null; do echo "unmounted $m"; done; done
  echo "left under /sys:"; findmnt -rno TARGET,FSTYPE -R /sys'

spec=$("$ENGINE" exec "$NODE" sh -c "grep -oE '/etc/containerd/[^\"]+\.json' /etc/containerd/config.toml | head -1")
if [ -n "$spec" ]; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  "$ENGINE" exec "$NODE" cat "$spec" \
    | jq 'if .hooks then .hooks |= with_entries(.value |= map(select(.path | test("mount-product-files") | not))) else . end' \
    > "$tmp"
  "$ENGINE" cp "$tmp" "$NODE:$spec"
  echo "dropped the product-files hook from $spec"
  "$ENGINE" exec "$NODE" systemctl restart containerd
fi
kubectl wait --for=condition=Ready node --all --timeout=120s
