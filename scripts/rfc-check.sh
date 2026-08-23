#!/bin/sh
# Validate that every RFC follows the format defined in docs/rfc/readme.md.
#
#   scripts/rfc-check.sh
#
# Reports every problem it finds, then exits non-zero. Runs in the pre-commit hook via
# `task lint`, so it stays fast and never rewrites anything.
set -eu

REPO_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
. "$REPO_ROOT/scripts/rfc-lib.sh"

# Failures are counted in a file rather than a variable: some checks run inside a pipeline,
# which is a subshell, and a variable incremented there would not survive.
counter=$(mktemp)
trap 'rm -f "$counter"' EXIT INT TERM

fail() {
  printf '  ✗ %s\n' "$1" >&2
  printf 'x' >> "$counter"
}

# Sections the template mandates. A RFC that drops one is usually dropping the thinking with it,
# which is the whole reason the section is in the template.
REQUIRED_H2='Summary
Motivation
Guide-level explanation
Design
Security considerations
Operational considerations
Alternatives considered
Drawbacks and risks
Unresolved questions
Future work
Implementation plan
References
Changelog'

# Sub-sections under Design. "Architecture" is the one that forces the explicit
# hexagonal-or-not answer, so it is not optional.
REQUIRED_H3='Contract
Architecture
Data and state'

REQUIRED_FM_KEYS='rfc
title
status
authors
created
updated
decided
brick
supersedes
superseded-by'

is_iso_date() {
  printf '%s' "$1" | grep -qE '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'
}

check_file() {
  file=$1
  is_template=$2
  base=$(basename "$file")
  num=$(rfc_num "$file")
  printf '%s\n' "$base"

  # --- filename -----------------------------------------------------------------------------
  if ! printf '%s' "$base" | grep -qE '^[0-9]{4}-[a-z0-9]+(-[a-z0-9]+)*\.md$'; then
    fail "filename must be NNNN-kebab-case-title.md"
  fi

  # --- front-matter -------------------------------------------------------------------------
  if [ "$(head -n 1 "$file")" != "---" ]; then
    fail "missing front-matter: the file must start with a '---' line"
    return
  fi

  for key in $REQUIRED_FM_KEYS; do
    if ! rfc_has_fm_key "$file" "$key"; then
      fail "front-matter is missing the '$key' key"
    fi
  done

  fm_rfc=$(rfc_fm "$file" rfc)
  fm_title=$(rfc_fm "$file" title)
  fm_status=$(rfc_fm "$file" status)
  fm_created=$(rfc_fm "$file" created)
  fm_updated=$(rfc_fm "$file" updated)
  fm_decided=$(rfc_fm "$file" decided)

  if [ "$fm_rfc" != "$num" ]; then
    fail "front-matter says 'rfc: $fm_rfc' but the filename says $num"
  fi

  if [ -z "$fm_title" ]; then
    fail "front-matter 'title' is empty"
  fi

  case " $RFC_STATUSES " in
    *" $fm_status "*) ;;
    *) fail "status '$fm_status' is not one of: $RFC_STATUSES" ;;
  esac

  if ! is_iso_date "$fm_created"; then
    fail "'created: $fm_created' is not a YYYY-MM-DD date"
  fi
  if ! is_iso_date "$fm_updated"; then
    fail "'updated: $fm_updated' is not a YYYY-MM-DD date"
  fi

  # A decision nobody dated is a decision nobody can audit.
  case "$fm_status" in
    Accepted|Implemented|Rejected)
      if [ -z "$fm_decided" ]; then
        fail "status is '$fm_status' but 'decided' is empty — record the decision date"
      elif ! is_iso_date "$fm_decided"; then
        fail "'decided: $fm_decided' is not a YYYY-MM-DD date"
      fi
      ;;
  esac

  if [ "$fm_status" = "Superseded" ] && [ -z "$(rfc_fm "$file" superseded-by)" ]; then
    fail "status is 'Superseded' but 'superseded-by' is empty — point at the replacement"
  fi

  # --- title line ---------------------------------------------------------------------------
  expected_h1="# RFC $num — $fm_title"
  if ! grep -qxF "$expected_h1" "$file"; then
    fail "missing the title line '$expected_h1'"
  fi

  # --- sections -----------------------------------------------------------------------------
  printf '%s\n' "$REQUIRED_H2" | while IFS= read -r section; do
    if ! grep -qxF "## $section" "$file"; then
      fail "missing section \"## $section\""
    fi
  done
  printf '%s\n' "$REQUIRED_H3" | while IFS= read -r section; do
    if ! grep -qxF "### $section" "$file"; then
      fail "missing section \"### $section\""
    fi
  done

  # --- leftovers ----------------------------------------------------------------------------
  if [ "$is_template" = 0 ] && grep -qF 'Copy this file with' "$file"; then
    fail "still contains the template's own instruction block — delete it"
  fi
}

# The template is validated too: it is the source every RFC is copied from, so a section
# missing there silently becomes a section missing everywhere.
check_file "$RFC_DIR/0000-template.md" 1

rfcs=$(rfc_files)
if [ -z "$rfcs" ]; then
  printf 'no RFC yet, only the template was checked\n'
else
  for file in $rfcs; do
    check_file "$file" 0
  done
fi

# --- repo-wide ------------------------------------------------------------------------------
printf 'repo\n'

dupes=$(rfc_files | while IFS= read -r f; do rfc_num "$f"; printf '\n'; done | sort | uniq -d)
for d in $dupes; do
  fail "number $d is used by more than one RFC"
done

if ! "$REPO_ROOT/scripts/rfc-index.sh" --check >/dev/null 2>&1; then
  fail "the index in docs/rfc/readme.md is stale — run 'task rfc:index'"
fi

# The statuses this script enforces must be the ones the process documents. Without this the
# two drift and the script silently becomes the real spec.
for status in $RFC_STATUSES; do
  if ! grep -qF "\`$status\`" "$RFC_README"; then
    fail "status '$status' is enforced here but not documented in docs/rfc/readme.md"
  fi
done

failures=$(wc -c < "$counter" | tr -d ' ')
if [ "$failures" -gt 0 ]; then
  printf '\nrfc-check: %s problem(s) found\n' "$failures" >&2
  exit 1
fi

printf '\nrfc-check: all RFCs valid\n'
