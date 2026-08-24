#!/bin/sh
# Regenerate every checked-in copy of the WeeboSiConfig CRD from crates/weebo-si-crd's Rust
# types: the plain manifest under crates/weebo-si-operator/deploy/, and the copy Helm's crds/
# convention requires in charts/weebo-si-operator/ (that directory is never templated, so it
# needs a real file, not a reference to the other one).
#
#   scripts/crd-regen.sh            regenerate only if the CRD schema is staged for commit
#   scripts/crd-regen.sh --check    exit 1 if either generated file is stale, write nothing
#
# The default mode is deliberately conditional, unlike rfc-index.sh's unconditional rewrite: the
# RFC index is a few lines of text, cheap to recompute on every commit, but this regenerates via
# `cargo run`, which is not free to pay on every commit regardless of what changed. `--check`
# (used by `task lint`, on any commit and in CI) always verifies freshness — "staged" is a
# git-index concept that does not exist in a CI checkout.
set -eu

REPO_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO_ROOT"

CRD_SRC="crates/weebo-si-crd"
OUTPUTS="crates/weebo-si-operator/deploy/crd.yaml charts/weebo-si-operator/crds/weebosiconfigs.hardening.weebo.io.yaml"

check_only=0
case "${1:-}" in
  --check) check_only=1 ;;
  '') ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

if [ "$check_only" = 0 ]; then
  if ! git diff --cached --name-only | grep -q "^${CRD_SRC}/"; then
    exit 0
  fi
fi

generated=$(mktemp)
trap 'rm -f "$generated"' EXIT INT TERM

if ! cargo run --quiet --locked -p weebo-si-operator -- crd > "$generated" 2>/dev/null; then
  echo "crd-regen: 'weebo-si-operator crd' failed to run" >&2
  exit 1
fi

stale=0
for out in $OUTPUTS; do
  if [ -f "$out" ] && cmp -s "$generated" "$out"; then
    if [ "$check_only" = 0 ]; then
      echo "crd-regen: $out already up to date"
    fi
    continue
  fi

  if [ "$check_only" = 1 ]; then
    echo "crd-regen: $out is stale — run 'task recu'" >&2
    diff -u "$out" "$generated" >&2 || true
    stale=1
    continue
  fi

  mkdir -p "$(dirname "$out")"
  cat "$generated" > "$out"
  echo "crd-regen: regenerated $out"
done

[ "$stale" = 0 ]
