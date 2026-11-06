#!/usr/bin/env bash
# Native OS smoke for ci.yml windows / macos (and local). Store tests that
# hit OS-specific IO / RAM / mmap probes, a few-block query confirm (IOCP /
# pool vs uring), Darwin's RPC / Esplora unix socket binds, plus
# rbitcoin-node --smoke. Not a packaged snapshot.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Substring filters (one cargo test each — libtest ANDs extra args).
# Keep this list the platform-diff surface, not the whole store suite.
STORE_PLATFORM_FILTERS=(
  file::advise_tests
  sorted_run::workers_for_free_ram
  sorted_run::mem_available
  sorted_run::host_mem
  sorted_run::darwin_vm
  io_backend::
  bulk_io::unset_io_env_opens_a_session
  uring_session::pool_
  fuse8_filter::no_false_negatives_and_roundtrip
  segmented_head::insert_roll_seal_lookup_roundtrip
  bdz::compact_packed_fd_is_bdz3_and_matches_ram
  pread_file_exact_reports_the_pread_errno
)
# Query confirm: TableFile + Class C write-behind on the native completion
# session (IOCP / pool). Not the full query suite. Windows and Darwin run
# the same confirm + seal-roll surface (mmap fuse + a few blocks).
QUERY_PLATFORM_FILTERS=(
  chain_view_pin_asof_reorg
  sh_history_caps
)
# create.loc SSE2 / NEON vs the scalar golden. Linux CI is x86_64 and runs the
# full workspace suite, so this is appended per-platform below: the Windows
# smoke is the SSE2 pin, the Darwin smoke the aarch64 NEON pin.
PRIMITIVES_PLATFORM_FILTERS=()
# Unix socket binds under TMPDIR. Darwin's default TMPDIR leaves the
# 104-byte sun_path little room, and Linux CI's tmpfs TMPDIR is short.
RPC_PLATFORM_FILTERS=()
ESPLORA_PLATFORM_FILTERS=()
NET_PLATFORM_FILTERS=()
# Windows OVERLAPPED + concurrent grow can `pread short` and abort the
# process (STATUS_STACK_BUFFER_OVERRUN). Same-thread fuse roundtrip, seal
# roll, and query confirm still run. CI_OS_SMOKE_UNAME overrides uname
# for the self-test.
STORE_PLATFORM_SKIPS=()
case "${CI_OS_SMOKE_UNAME:-$(uname -s)}" in
  MINGW* | MSYS* | CYGWIN* | Windows_NT*)
    STORE_PLATFORM_SKIPS+=(concurrent_readers_during_append_and_grow)
    # `mod io_session_iocp` is #[cfg(windows)] — the tests do not exist elsewhere.
    STORE_PLATFORM_FILTERS+=(io_session_iocp)
    # Linux and Windows only: Darwin opens no session by default.
    STORE_PLATFORM_FILTERS+=(uring_session::default_kind_follows_os)
    PRIMITIVES_PLATFORM_FILTERS+=(loc_simd::)
    # `mod listen` is #[cfg(windows)]: SO_EXCLUSIVEADDRUSE on listen sockets.
    NET_PLATFORM_FILTERS+=(listen::)
    ;;
  Darwin*)
    PRIMITIVES_PLATFORM_FILTERS+=(loc_simd::)
    RPC_PLATFORM_FILTERS+=(unix_socket)
    ESPLORA_PLATFORM_FILTERS+=(unix)
    ;;
esac

if [[ "${CI_OS_SMOKE_DRY_RUN:-}" == "1" ]]; then
  echo "smoke=store-platform+query-confirm+node-smoke"
  echo "filters=${STORE_PLATFORM_FILTERS[*]}"
  echo "query=${QUERY_PLATFORM_FILTERS[*]}"
  echo "primitives=${PRIMITIVES_PLATFORM_FILTERS[*]:-}"
  echo "rpc=${RPC_PLATFORM_FILTERS[*]:-}"
  echo "esplora=${ESPLORA_PLATFORM_FILTERS[*]:-}"
  echo "net=${NET_PLATFORM_FILTERS[*]:-}"
  echo "skip=${STORE_PLATFORM_SKIPS[*]:-}"
  exit 0
fi

skip_args=()
for s in ${STORE_PLATFORM_SKIPS[@]+"${STORE_PLATFORM_SKIPS[@]}"}; do
  skip_args+=(--skip "$s")
done

# A filter that matches nothing is a stale filter, not a pass: libtest reports
# "running 0 tests" and exits 0, so the gate would silently shrink on a rename.
# Capture the list first: `grep -q` on cargo's pipe is SIGPIPE under `pipefail`.
assert_filter_matches() {
  local pkg="$1" f="$2"
  local listed
  if ! listed="$(cargo test -q -p "$pkg" --test suite -- --list "$f")"; then
    echo "ci-os-smoke: failed to list tests for '$f' in $pkg" >&2
    exit 1
  fi
  if ! grep -q ': test' <<<"$listed"; then
    echo "ci-os-smoke: stale filter '$f' matches no test in $pkg" >&2
    exit 1
  fi
}

for f in "${STORE_PLATFORM_FILTERS[@]}"; do
  assert_filter_matches rbitcoin-store "$f"
  cargo test -p rbitcoin-store --test suite -- "$f" ${skip_args[@]+"${skip_args[@]}"}
done

for f in "${QUERY_PLATFORM_FILTERS[@]}"; do
  assert_filter_matches rbitcoin-query "$f"
  cargo test -p rbitcoin-query --test suite -- "$f"
done

for f in ${PRIMITIVES_PLATFORM_FILTERS[@]+"${PRIMITIVES_PLATFORM_FILTERS[@]}"}; do
  assert_filter_matches rbitcoin-primitives "$f"
  cargo test -p rbitcoin-primitives --test suite -- "$f"
done

for f in ${RPC_PLATFORM_FILTERS[@]+"${RPC_PLATFORM_FILTERS[@]}"}; do
  assert_filter_matches rbitcoin-rpc "$f"
  cargo test -p rbitcoin-rpc --test suite -- "$f"
done

for f in ${ESPLORA_PLATFORM_FILTERS[@]+"${ESPLORA_PLATFORM_FILTERS[@]}"}; do
  assert_filter_matches rbitcoin-esplora "$f"
  cargo test -p rbitcoin-esplora --test suite -- "$f"
done

for f in ${NET_PLATFORM_FILTERS[@]+"${NET_PLATFORM_FILTERS[@]}"}; do
  assert_filter_matches rbitcoin-net "$f"
  cargo test -p rbitcoin-net --test suite -- "$f"
done

cargo build -p rbitcoin-node -p rbitcoin-cli

bin_root="${CARGO_TARGET_DIR:-target}/debug"
node="${bin_root}/rbitcoin-node"
if [[ -f "${node}.exe" ]]; then
  node="${node}.exe"
fi
if [[ ! -f "$node" ]]; then
  echo "ci-os-smoke: missing $node" >&2
  exit 1
fi

datadir="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-os-smoke.XXXXXX")"
cleanup() { rm -rf "$datadir"; }
trap cleanup EXIT

"$node" --smoke --network regtest --datadir "$datadir" \
  --no-seeds --log-level error

body="$datadir/store/scripthash.body"
if [[ -d "$body" ]]; then
  test -f "$body/00"
  test -f "$datadir/store/scripthash.ovf/body"
else
  test -f "$body"
fi
