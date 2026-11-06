#!/usr/bin/env bash
# Contract: PR OS smoke is store platform-diff tests (including mmap
# sealed fuse) + a few-block query confirm + node --smoke, not a packaged
# musl/Windows/Darwin snapshot. Does not invoke cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/scripts/ci-os-smoke.sh"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"


out="$(CI_OS_SMOKE_DRY_RUN=1 "$RUN")"
assert_ok "dry-run names store platform + query confirm + node --smoke" \
  grep -qx "smoke=store-platform+query-confirm+node-smoke" <<<"$out"
assert_ok "dry-run does not export deleted RBITCOIN_HEAD_SCALE" \
  test "$(grep -c 'RBITCOIN_HEAD_SCALE' <<<"$out" || true)" = "0"
assert_ok "dry-run lists TableFile advise tests" \
  grep -q "file::advise_tests" <<<"$out"
assert_ok "dry-run lists mmap sealed fuse roundtrip" \
  grep -q "fuse8_filter::no_false_negatives_and_roundtrip" <<<"$out"
assert_ok "dry-run lists seal publish remap" \
  grep -q "segmented_head::insert_roll_seal_lookup_roundtrip" <<<"$out"
assert_ok "dry-run lists mapped SH BDZ3 occ" \
  grep -q "bdz::compact_packed_fd_is_bdz3_and_matches_ram" <<<"$out"
assert_ok "dry-run lists the exact pread errno pin" \
  grep -q "pread_file_exact_reports_the_pread_errno" <<<"$out"
assert_ok "dry-run lists query connect-chain confirm" \
  grep -q "chain_view_pin_asof_reorg" <<<"$out"
assert_ok "dry-run lists query SH-cap confirm" \
  grep -q "sh_history_caps" <<<"$out"
assert_ok "dry-run has no skips off Windows" \
  grep -qx "skip=" <<<"$out"
assert_ok "dry-run lists SH RAM / host_mem probes" \
  grep -q "sorted_run::host_mem" <<<"$out"
assert_ok "dry-run lists Darwin vm page math" \
  grep -q "sorted_run::darwin_vm" <<<"$out"
assert_ok "dry-run lists the default IO session per OS" \
  grep -q "bulk_io::unset_io_env_opens_a_session" <<<"$out"
assert_ok "only Windows lists the default session kind test" \
  test "$(grep -c 'uring_session::default_kind_follows_os' <<<"$out" || true)" = "0"
assert_ok "dry-run lists pool session tests" \
  grep -q "uring_session::pool_" <<<"$out"
assert_ok "only Windows lists the exclusive listen bind" \
  grep -qx "net=" <<<"$out"

out="$(CI_OS_SMOKE_DRY_RUN=1 CI_OS_SMOKE_UNAME=MINGW64_NT-10.0-20348 "$RUN")"
assert_ok "Windows dry-run skips concurrent grow/read abort" \
  grep -qx "skip=concurrent_readers_during_append_and_grow" <<<"$out"
assert_ok "Windows dry-run still maps sealed fuse" \
  grep -q "fuse8_filter::no_false_negatives_and_roundtrip" <<<"$out"
assert_ok "Windows dry-run still rolls seal + maps fuse" \
  grep -q "segmented_head::insert_roll_seal_lookup_roundtrip" <<<"$out"
assert_ok "Windows dry-run still maps SH BDZ3 occ" \
  grep -q "bdz::compact_packed_fd_is_bdz3_and_matches_ram" <<<"$out"
assert_ok "Windows dry-run still confirms a few blocks" \
  grep -q "chain_view_pin_asof_reorg" <<<"$out"
assert_ok "Windows dry-run lists IOCP session tests" \
  grep -q "io_session_iocp" <<<"$out"
assert_ok "Windows dry-run pins the IOCP default session kind" \
  grep -q "uring_session::default_kind_follows_os" <<<"$out"
assert_ok "Windows dry-run lists the exclusive listen bind" \
  grep -qx "net=listen::" <<<"$out"
assert_ok "Windows dry-run pins loc SIMD (SSE2) vs scalar" \
  grep -qx "primitives=loc_simd::" <<<"$out"

out="$(CI_OS_SMOKE_DRY_RUN=1 CI_OS_SMOKE_UNAME=Darwin "$RUN")"
assert_ok "Darwin dry-run runs concurrent grow/read" \
  grep -qx "skip=" <<<"$out"
assert_ok "Darwin dry-run still confirms a few blocks" \
  grep -q "chain_view_pin_asof_reorg" <<<"$out"
assert_ok "Darwin dry-run pins loc SIMD (NEON) vs scalar" \
  grep -qx "primitives=loc_simd::" <<<"$out"
assert_ok "Darwin dry-run binds RPC unix sockets under its TMPDIR" \
  grep -qx "rpc=unix_socket" <<<"$out"
assert_ok "Darwin dry-run binds Esplora unix sockets under its TMPDIR" \
  grep -qx "esplora=unix" <<<"$out"

out="$(CI_OS_SMOKE_DRY_RUN=1 CI_OS_SMOKE_UNAME=Linux "$RUN")"
assert_ok "Linux dry-run leaves loc SIMD to the full suite" \
  grep -qx "primitives=" <<<"$out"
assert_ok "Linux dry-run leaves unix sockets to the full suite" \
  grep -qx "rpc=" <<<"$out"

if [[ "$FAIL" -ne 0 ]]; then
  echo "ci-os-smoke.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "ci-os-smoke.test.sh: $PASS passed"
