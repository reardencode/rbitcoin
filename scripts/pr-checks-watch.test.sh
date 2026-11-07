#!/usr/bin/env bash
# Contract: required-job fail returns immediately even if coverage is still
# pending. Does not invoke gh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/scripts/pr-checks-watch.sh"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"


windows_red_coverage_pending="$(
  printf '%s\t%s\t%s\t%s\n' \
    windows fail 1m4s https://example/windows \
    coverage pending 0 https://example/coverage \
    qc pass 18s https://example/qc
)"

rc=0
out="$(CI_PR_CHECKS_TEXT="$windows_red_coverage_pending" "$RUN" --once 2>&1)" || rc=$?
assert_ok "windows fail exits 1 while coverage pending" test "$rc" -eq 1
assert_ok "windows fail names the job" \
  grep -q "required job failed: windows" <<<"$out"
assert_ok "windows fail prints start-the-fix with job URL" \
  grep -q "start the fix now (do not wait for the rest of the run): https://example/windows" <<<"$out"

all_green="$(
  printf '%s\t%s\t%s\n' \
    qc pass 2m \
    test pass 2m \
    windows pass 1m \
    macos pass 50s \
    coverage pass 2m \
    pread pass 2m \
    rust-forward pass 2m
)"
rc=0
out="$(CI_PR_CHECKS_TEXT="$all_green" "$RUN" --once 2>&1)" || rc=$?
assert_ok "all required pass exits 0" test "$rc" -eq 0
assert_ok "green line is printed" grep -q "required jobs green" <<<"$out"

analyze_pending_windows_green="$(
  printf '%s\t%s\t%s\n' \
    qc pass 2m \
    test pass 2m \
    windows pass 1m \
    macos pass 50s \
    coverage pass 2m \
    pread pass 2m \
    rust-forward pass 2m \
    'Analyze (rust)' pending 0
)"
rc=0
out="$(CI_PR_CHECKS_TEXT="$analyze_pending_windows_green" "$RUN" --once 2>&1)" || rc=$?
assert_ok "non-required Analyze pending does not block green" test "$rc" -eq 0

required_pending="$(
  printf '%s\t%s\t%s\n' \
    qc pass 18s \
    windows pending 0
)"
rc=0
out="$(CI_PR_CHECKS_TEXT="$required_pending" "$RUN" --once 2>&1)" || rc=$?
assert_ok "required pending with --once exits 2" test "$rc" -eq 2

incomplete="$(
  printf '%s\t%s\t%s\n' \
    qc pass 18s
)"
rc=0
out="$(CI_PR_CHECKS_TEXT="$incomplete" "$RUN" --once 2>&1)" || rc=$?
assert_ok "missing required jobs count as pending" test "$rc" -eq 2

analyze_red_windows_pending="$(
  printf '%s\t%s\t%s\t%s\n' \
    'Analyze (rust)' fail 2m https://example/analyze \
    windows pending 0 https://example/windows
)"
rc=0
out="$(CI_PR_CHECKS_TEXT="$analyze_red_windows_pending" "$RUN" --once --interest "Analyze (rust)" 2>&1)" || rc=$?
assert_ok "job of interest fail exits 1 while required still pending" test "$rc" -eq 1
assert_ok "job of interest fail names Analyze" \
  grep -q "required job failed: Analyze (rust)" <<<"$out"
assert_ok "job of interest fail prints start-the-fix URL" \
  grep -q "start the fix now (do not wait for the rest of the run): https://example/analyze" <<<"$out"

if [[ "$FAIL" -ne 0 ]]; then
  echo "pr-checks-watch.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "pr-checks-watch.test.sh: $PASS passed"
