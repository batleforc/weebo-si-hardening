#!/bin/sh
# Shared helpers for the RFC scripts. Sourced, never executed.
# POSIX sh on purpose: this runs in the pre-commit hook, where "it works on my shell" is not
# a property we get to rely on.

# shellcheck shell=sh
# shellcheck disable=SC2034  # every variable here is consumed by the scripts that source this

RFC_DIR="$REPO_ROOT/docs/rfc"
RFC_README="$RFC_DIR/readme.md"
RFC_INDEX_START='<!-- rfc-index:start -->'
RFC_INDEX_END='<!-- rfc-index:end -->'

# Every status the process defines. Kept in sync with docs/rfc/readme.md by rfc-check.sh.
RFC_STATUSES='Draft Proposed Accepted Implemented Rejected Superseded'

# rfc_fm <file> <key> -> value of a front-matter key, empty if absent or valueless.
# Only looks inside the leading `---` block, so a `status: ...` in prose cannot shadow it.
rfc_fm() {
  awk -v key="$2" '
    NR == 1 { if ($0 != "---") exit 0; next }
    $0 == "---" { exit 0 }
    {
      if (index($0, key ": ") == 1) { print substr($0, length(key) + 3); exit 0 }
      if ($0 == key ":") { exit 0 }
    }
  ' "$1"
}

# rfc_has_fm_key <file> <key> -> 0 if the key exists at all, valued or not.
# The status is carried in a flag rather than `exit 0`, because awk runs END after exit and
# END's own exit code wins.
rfc_has_fm_key() {
  awk -v key="$2" '
    NR == 1 { if ($0 != "---") exit; next }
    $0 == "---" { exit }
    { if (index($0, key ":") == 1) { found = 1; exit } }
    END { exit(found ? 0 : 1) }
  ' "$1"
}

# rfc_files -> every real RFC, template excluded, in numeric order.
rfc_files() {
  for f in "$RFC_DIR"/[0-9][0-9][0-9][0-9]-*.md; do
    [ -e "$f" ] || continue
    case "$(basename "$f")" in
      0000-*) continue ;;
    esac
    printf '%s\n' "$f"
  done
}

# rfc_num <file> -> the four-digit number from the filename.
rfc_num() {
  b=$(basename "$1")
  printf '%s' "${b%%-*}"
}

# rfc_render_index -> the index block, markers included, on stdout.
rfc_render_index() {
  printf '%s\n\n' "$RFC_INDEX_START"
  printf '| # | Title | Status | Brick |\n'
  printf '| --- | --- | --- | --- |\n'
  found=0
  for f in $(rfc_files); do
    found=1
    base=$(basename "$f")
    num=$(rfc_num "$f")
    title=$(rfc_fm "$f" title)
    status=$(rfc_fm "$f" status)
    brick=$(rfc_fm "$f" brick)
    if [ -n "$brick" ]; then
      brick="\`$brick\`"
    else
      brick='—'
    fi
    # shellcheck disable=SC2016  # the backticks are markdown, not command substitution
    printf '| [%s](./%s) | %s | `%s` | %s |\n' "$num" "$base" "$title" "$status" "$brick"
  done
  if [ "$found" = 0 ]; then
    printf '| — | _no RFC yet_ | | |\n'
  fi
  printf '\n%s\n' "$RFC_INDEX_END"
}
