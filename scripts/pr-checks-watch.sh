#!/usr/bin/env bash
# Poll a PR's required checks (plus optional --interest jobs). Exit 1 as
# soon as any watched job fails — do not wait for coverage / zizmor
# after windows (or another job of interest) is already red.
set -euo pipefail

REPO="${PR_CHECKS_REPO:-rbitcoin-org/rbitcoin}"
PR=""
ONCE=0
SLEEP_S=10
INTEREST=()
WATCHED=()

REQUIRED=(
  qc
  test
  windows
  macos
  coverage
  pread
  rust-forward
  nixos-module-eval
)

usage() {
  echo "usage: $0 --pr <n> [--repo owner/name] [--interest NAME]... [--once] [--sleep N]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pr)
      PR="${2:-}"
      shift 2
      ;;
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --interest)
      INTEREST+=("${2:-}")
      shift 2
      ;;
    --once)
      ONCE=1
      shift
      ;;
    --sleep)
      SLEEP_S="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

WATCHED=("${REQUIRED[@]}")
if ((${#INTEREST[@]})); then
  WATCHED+=("${INTEREST[@]}")
fi

snapshot() {
  if [[ -n "${CI_PR_CHECKS_TEXT:-}" ]]; then
    if [[ "${CI_PR_CHECKS_TEXT}" == "-" ]]; then
      cat
    else
      printf '%s\n' "${CI_PR_CHECKS_TEXT}"
    fi
    return
  fi
  if [[ -z "$PR" ]]; then
    usage
  fi
  # `gh pr checks` exits 8 while any check is pending or failing; the table
  # is still what we poll.
  gh pr checks "$PR" --repo "$REPO" || true
}

is_watched() {
  local name="$1"
  local w
  for w in "${WATCHED[@]}"; do
    if [[ "$name" == "$w" ]]; then
      return 0
    fi
  done
  return 1
}

eval_snapshot() {
  local name status elapsed url
  local pending=0
  FAILED_JOB=""
  FAILED_URL=""
  local seen=""
  while IFS=$'\t' read -r name status elapsed url _rest || [[ -n "${name:-}" ]]; do
    [[ -z "${name:-}" ]] && continue
    is_watched "$name" || continue
    seen="${seen}${name}"$'\n'
    case "$status" in
      fail | failure | cancelled | timed_out)
        FAILED_JOB="$name"
        FAILED_URL="${url:-}"
        return 1
        ;;
      pending | queued | in_progress | running | startup_failure)
        pending=1
        ;;
      pass | success | skipping | skipped | neutral)
        ;;
      *)
        pending=1
        ;;
    esac
  done
  local w
  for w in "${WATCHED[@]}"; do
    if ! grep -qx "$w" <<<"$seen"; then
      pending=1
    fi
  done
  if [[ "$pending" -eq 1 ]]; then
    return 2
  fi
  return 0
}

while true; do
  snap="$(snapshot)"
  set +e
  FAILED_JOB=""
  FAILED_URL=""
  eval_snapshot <<<"$snap"
  rc=$?
  set -e
  if [[ "$rc" -eq 1 ]]; then
    echo "pr-checks-watch: required job failed: ${FAILED_JOB}" >&2
    echo "pr-checks-watch: start the fix now (do not wait for the rest of the run)${FAILED_URL:+: ${FAILED_URL}}" >&2
    echo "$snap" >&2
    exit 1
  fi
  if [[ "$rc" -eq 0 ]]; then
    echo "pr-checks-watch: required jobs green"
    exit 0
  fi
  if [[ "$ONCE" -eq 1 ]]; then
    echo "pr-checks-watch: required jobs still pending" >&2
    exit 2
  fi
  sleep "$SLEEP_S"
done
