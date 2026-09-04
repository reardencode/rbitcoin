#!/usr/bin/env bash
# Nightly libFuzzer. rust-toolchain.toml pins 1.95; cargo-fuzz needs nightly.
# Callers inherit RUSTUP_TOOLCHAIN if already set; default is nightly.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail_if_no_comparisons() {
  local log="$1"
  if [[ ! -f "$log" ]]; then
    echo "fuzz-run: missing comparison log $log" >&2
    return 1
  fi
  local n
  n="$(grep -Eo 'block-differential: comparisons=[0-9]+' "$log" | tail -1 | grep -Eo '[0-9]+$' || true)"
  if [[ -z "$n" || "$n" -lt 1 ]]; then
    echo "fuzz-run: no comparisons in $log (got ${n:-missing})" >&2
    return 1
  fi
  echo "fuzz-run: comparisons=$n"
}

if [[ "${1:-}" == "--check-log" ]]; then
  fail_if_no_comparisons "${2:?log file}"
  exit 0
fi

BIN="${1:-block_wire}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"

# Prebuilt cargo-fuzz (taiki-e/install-action musl binary) uses
# CURRENT_PLATFORM as cargo --target, so it builds
# x86_64-unknown-linux-musl. ASan cannot use statically linked musl
# (`sanitizer is incompatible with statically linked libc`). Pin the
# rustc host triple (gnu on GHA ubuntu-latest).
target="$(rustc "+${RUSTUP_TOOLCHAIN}" -vV 2>/dev/null | sed -n 's/^host: //p' || true)"
if [[ -z "$target" ]]; then
  target="$(rustc -vV | sed -n 's/^host: //p')"
fi
if [[ -z "$target" ]]; then
  echo "fuzz-run: could not read rustc host triple" >&2
  exit 1
fi

sanitizer="address"
jobs=""
if [[ "$BIN" == "block_differential" ]]; then
  sanitizer="none"
  jobs="-jobs=1"
fi

if [[ "${FUZZ_DRY_RUN:-}" == "1" ]]; then
  echo "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN"
  echo "CARGO_FUZZ_TARGET=$target"
  echo "FUZZ_BIN=$BIN"
  echo "FUZZ_SANITIZER=$sanitizer"
  echo "FUZZ_JOBS=${jobs:--}"
  echo "CARGO_TARGET_DIR_UNSET=1"
  if [[ "$BIN" == "block_differential" ]]; then
    echo "RBITCOIN_CORE_BITCOIND=${RBITCOIN_CORE_BITCOIND:-}"
  fi
  exit 0
fi

if [[ "$BIN" == "block_wire" ]]; then
  mkdir -p fuzz/corpus/block_wire
  cp crates/rbitcoin-consensus/tests/fixtures/signet_block_1.bin \
    fuzz/corpus/block_wire/signet_block_1.bin
  exec env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" block_wire -- \
    -max_total_time="${FUZZ_MAX_TOTAL_TIME:-120}" \
    -timeout=10 \
    -max_len=1048576
fi

if [[ "$BIN" != "block_differential" ]]; then
  echo "fuzz-run: unknown target $BIN" >&2
  exit 1
fi

export RBITCOIN_HEAD_SCALE="${RBITCOIN_HEAD_SCALE:-tiny}"
export RBITCOIN_IO="${RBITCOIN_IO:-fd}"
export RBITCOIN_CORE_BITCOIND="$(./scripts/core-functional/fetch-bitcoind.sh)"

mkdir -p fuzz/corpus/block_differential
cp crates/rbitcoin-consensus/tests/fixtures/regtest_height1.bin \
  fuzz/corpus/block_differential/height1.bin

log="${TMPDIR:-/tmp}/rbtc-fuzz-diff.$$.log"
set +e
env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" --sanitizer none block_differential -- \
  -jobs=1 \
  -max_total_time="${FUZZ_MAX_TOTAL_TIME:-480}" \
  -timeout=30 \
  -max_len=262144 \
  2>&1 | tee "$log"
st=${PIPESTATUS[0]}
set -e
if [[ "$st" -ne 0 ]]; then
  exit "$st"
fi
fail_if_no_comparisons "$log"
