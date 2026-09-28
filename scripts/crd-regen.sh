#!/bin/sh
# Regenerate every checked-in copy of this operator's CRDs from crates/weebo-si-crd's Rust
# types: the plain multi-document manifest under crates/weebo-si-operator/deploy/, and the
# one-file-per-kind copies Helm's crds/ convention requires in charts/weebo-si-operator/ (that
# directory is never templated, so it needs real files, not a reference to the other one).
#
# Three kinds since RFC 0011: weebosiconfigs, weebositeams, weebosiusers.
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
# "<output path>:<kind>", where an empty kind means "every kind, as one stream".
OUTPUTS="crates/weebo-si-operator/deploy/crd.yaml:
charts/weebo-si-operator/crds/weebosiconfigs.hardening.weebo.io.yaml:weebosiconfigs
charts/weebo-si-operator/crds/weebositeams.hardening.weebo.io.yaml:weebositeams
charts/weebo-si-operator/crds/weebosiusers.hardening.weebo.io.yaml:weebosiusers"

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

# No pipeline here on purpose: a `while read` loop is a subshell, and a failure inside one is a
# failure the caller has to remember to re-raise. Entries carry no whitespace, so word splitting
# over the default IFS is the whole parser needed.
for entry in $OUTPUTS; do
  out=${entry%%:*}
  kind=${entry#*:}

  # An empty kind means "every kind": passed as no argument at all rather than as an empty one,
  # which the binary would read as the name of a CRD it does not have.
  if [ -n "$kind" ]; then
    generate="cargo run --quiet --locked -p weebo-si-operator -- crd $kind"
  else
    generate="cargo run --quiet --locked -p weebo-si-operator -- crd"
  fi
  if ! $generate > "$generated" 2>/dev/null; then
    echo "crd-regen: '$generate' failed to run" >&2
    exit 1
  fi

  if [ -f "$out" ] && cmp -s "$generated" "$out"; then
    if [ "$check_only" = 0 ]; then
      echo "crd-regen: $out already up to date"
    fi
    continue
  fi

  if [ "$check_only" = 1 ]; then
    echo "crd-regen: $out is stale — run 'task recu'" >&2
    diff -u "$out" "$generated" >&2 || true
    exit 1
  fi

  mkdir -p "$(dirname "$out")"
  cat "$generated" > "$out"
  echo "crd-regen: regenerated $out"
done
