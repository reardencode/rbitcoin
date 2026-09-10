#!/usr/bin/env bash
# Contract: PR OS smoke is store platform-diff tests + node --smoke, not a
# packaged musl/Windows/Darwin snapshot. Does not invoke cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/scripts/ci-os-smoke.sh"
PASS=0
FAIL=0

assert_ok() {
  local name="$1"
  shift
  if "$@"; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name"
    FAIL=$((FAIL + 1))
  fi
}

out="$(CI_OS_SMOKE_DRY_RUN=1 "$RUN")"
assert_ok "dry-run names store platform + node --smoke" \
  grep -qx "smoke=store-platform+node-smoke" <<<"$out"
assert_ok "dry-run does not export deleted RBITCOIN_HEAD_SCALE" \
  test "$(grep -c 'RBITCOIN_HEAD_SCALE' <<<"$out" || true)" = "0"
assert_ok "dry-run lists TableFile advise tests" \
  grep -q "file::advise_tests" <<<"$out"
assert_ok "dry-run has no skips off Windows" \
  grep -qx "skip=" <<<"$out"
assert_ok "dry-run lists SH RAM / host_mem probes" \
  grep -q "sorted_run::tests::host_mem" <<<"$out"
assert_ok "dry-run lists Darwin vm page math" \
  grep -q "sorted_run::tests::darwin_vm" <<<"$out"
assert_ok "dry-run lists IOCP session tests" \
  grep -q "io_session_iocp" <<<"$out"
assert_ok "dry-run lists default session kind" \
  grep -q "uring_session::tests::default_kind_follows_os" <<<"$out"
assert_ok "dry-run lists pool session tests" \
  grep -q "uring_session::tests::pool_" <<<"$out"

out="$(CI_OS_SMOKE_DRY_RUN=1 CI_OS_SMOKE_UNAME=MINGW64_NT-10.0-20348 "$RUN")"
assert_ok "Windows dry-run skips concurrent grow/read abort" \
  grep -qx "skip=concurrent_readers_during_append_and_grow" <<<"$out"

out="$(CI_OS_SMOKE_DRY_RUN=1 CI_OS_SMOKE_UNAME=Darwin "$RUN")"
assert_ok "Darwin dry-run runs concurrent grow/read" \
  grep -qx "skip=" <<<"$out"

if [[ "$FAIL" -ne 0 ]]; then
  echo "ci-os-smoke.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "ci-os-smoke.test.sh: $PASS passed"
