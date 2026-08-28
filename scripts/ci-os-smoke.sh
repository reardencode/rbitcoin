#!/usr/bin/env bash
# Native OS smoke for ci.yml windows / macos (and local). Store tests that
# hit OS-specific IO / RAM probes, plus rbitcoin-node --smoke. Not a
# packaged snapshot.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export RBITCOIN_HEAD_SCALE="${RBITCOIN_HEAD_SCALE:-tiny}"

# Substring filters (one cargo test each — libtest ANDs extra args).
# Keep this list the platform-diff surface, not the whole store suite.
STORE_PLATFORM_FILTERS=(
  file::advise_tests
  sorted_run::tests::workers_for_free_ram
  sorted_run::tests::mem_available
  sorted_run::tests::host_mem
  sorted_run::tests::darwin_vm
  io_backend::tests
  uring_session::tests::default_kind_follows_os
  uring_session::tests::pool_
  io_session_iocp
)
# Windows OVERLAPPED + concurrent grow can `pread short` and abort the
# process (STATUS_STACK_BUFFER_OVERRUN). Windows-only skip; Linux and
# Darwin run it. CI_OS_SMOKE_UNAME overrides uname for the self-test.
STORE_PLATFORM_SKIPS=()
case "${CI_OS_SMOKE_UNAME:-$(uname -s)}" in
  MINGW* | MSYS* | CYGWIN* | Windows_NT*)
    STORE_PLATFORM_SKIPS+=(concurrent_readers_during_append_and_grow)
    ;;
esac

if [[ "${CI_OS_SMOKE_DRY_RUN:-}" == "1" ]]; then
  echo "smoke=store-platform+node-smoke"
  echo "RBITCOIN_HEAD_SCALE=$RBITCOIN_HEAD_SCALE"
  echo "filters=${STORE_PLATFORM_FILTERS[*]}"
  echo "skip=${STORE_PLATFORM_SKIPS[*]:-}"
  exit 0
fi

skip_args=()
for s in ${STORE_PLATFORM_SKIPS[@]+"${STORE_PLATFORM_SKIPS[@]}"}; do
  skip_args+=(--skip "$s")
done

for f in "${STORE_PLATFORM_FILTERS[@]}"; do
  cargo test -p rbitcoin-store --lib -- "$f" ${skip_args[@]+"${skip_args[@]}"}
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
