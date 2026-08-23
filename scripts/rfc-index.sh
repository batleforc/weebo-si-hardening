#!/bin/sh
# Regenerate the index table in docs/rfc/readme.md from the RFC front-matter.
#
#   scripts/rfc-index.sh            rewrite the index in place
#   scripts/rfc-index.sh --check    exit 1 if the index is stale, write nothing
#
# The table lives between the rfc-index markers; everything else in the readme is hand-written
# and left untouched.
set -eu

REPO_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
. "$REPO_ROOT/scripts/rfc-lib.sh"

check_only=0
case "${1:-}" in
  --check) check_only=1 ;;
  '') ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

if ! grep -qF "$RFC_INDEX_START" "$RFC_README" || ! grep -qF "$RFC_INDEX_END" "$RFC_README"; then
  echo "rfc-index: markers missing from $RFC_README" >&2
  echo "  expected a block delimited by '$RFC_INDEX_START' and '$RFC_INDEX_END'" >&2
  exit 1
fi

block=$(mktemp)
rendered=$(mktemp)
trap 'rm -f "$block" "$rendered"' EXIT INT TERM

rfc_render_index > "$block"

# Replace everything from the start marker through the end marker with the rendered block.
awk -v start="$RFC_INDEX_START" -v end="$RFC_INDEX_END" -v block="$block" '
  $0 == start {
    while ((getline line < block) > 0) print line
    close(block)
    skipping = 1
    next
  }
  $0 == end { skipping = 0; next }
  !skipping { print }
' "$RFC_README" > "$rendered"

if cmp -s "$rendered" "$RFC_README"; then
  if [ "$check_only" = 0 ]; then
    echo "rfc-index: already up to date"
  fi
  exit 0
fi

if [ "$check_only" = 1 ]; then
  echo "rfc-index: the index in docs/rfc/readme.md is stale — run 'task rfc:index'" >&2
  diff -u "$RFC_README" "$rendered" >&2 || true
  exit 1
fi

cat "$rendered" > "$RFC_README"
echo "rfc-index: updated the index in docs/rfc/readme.md"
