#!/usr/bin/env bash
# Hermetic pin for scripts/docker-tags.sh (image tag policy). No docker.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAGS="$ROOT/scripts/docker-tags.sh"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"
export GIT_AUTHOR_NAME=rbitcoin-docker-tags-test
export GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=rbitcoin-docker-tags-test
export GIT_COMMITTER_EMAIL=test@example.invalid
# The caller's git config (tag.gpgsign, commit.gpgsign) is not the test's.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-docker-tags.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# Fresh repo with one commit and the given lightweight tags. Callers use
# $(...), where set -e is off, so each git failure returns explicitly and
# the outer assignment stops the test (bash 3.2 has no inherit_errexit).
repo() {
  local dir="$WORKDIR/$1"
  shift
  git init -q "$dir" || return 1
  git -C "$dir" commit -q --allow-empty -m init || return 1
  local t
  for t in "$@"; do
    git -C "$dir" tag "$t" || return 1
  done
  printf '%s\n' "$dir"
}

# Output of docker-tags.sh joined to one line, or FAILED.
tags_for() {
  local dir="$1" tag="$2" out
  if out="$(bash "$TAGS" "$tag" --root "$dir" 2>/dev/null)"; then
    printf '%s\n' "$out" | paste -sd ' ' -
  else
    echo FAILED
  fi
}

expect() {
  local name="$1" want="$2" got="$3"
  assert_ok "$name (got: $got)" test "$got" = "$want"
}

assert_ok "script exists" test -f "$TAGS"

r="$(repo first v0.9.0)"
expect "first release is latest" "0.9.0 0.9 latest" "$(tags_for "$r" v0.9.0)"

r="$(repo patch v0.9.0 v0.9.1)"
expect "patch on newest line is latest" "0.9.1 0.9 latest" "$(tags_for "$r" v0.9.1)"

r="$(repo oldline v0.8.0 v0.8.1 v0.9.0 v0.8.2)"
expect "patch on older line moves X.Y only" "0.8.2 0.8" "$(tags_for "$r" v0.8.2)"

r="$(repo rerun v0.8.0 v0.8.2 v0.8.3 v0.9.0)"
expect "rerun of an old patch moves nothing" "0.8.2" "$(tags_for "$r" v0.8.2)"

r="$(repo numeric v0.9.0 v0.10.0 v0.9.5)"
expect "0.10 sorts above 0.9" "0.10.0 0.10 latest" "$(tags_for "$r" v0.10.0)"
expect "0.9.5 below 0.10.0 is not latest" "0.9.5 0.9" "$(tags_for "$r" v0.9.5)"

r="$(repo noise v0.9.0 v0.9.x v1.0.0-rc1 foo)"
expect "non-ship tags are ignored" "0.9.0 0.9 latest" "$(tags_for "$r" v0.9.0)"

r="$(repo untagged v0.8.0)"
expect "argument counts even before the tag is fetched" \
  "0.9.0 0.9 latest" "$(tags_for "$r" v0.9.0)"

r="$(repo refuse v0.9.0)"
expect "patch 99 is refused" FAILED "$(tags_for "$r" v0.9.99)"
expect "missing v is refused" FAILED "$(tags_for "$r" 0.9.0)"
expect "prerelease is refused" FAILED "$(tags_for "$r" v1.0.0-rc1)"
expect "empty is refused" FAILED "$(tags_for "$r" '')"

echo
echo "passed=$PASS failed=$FAIL"
test "$FAIL" -eq 0
