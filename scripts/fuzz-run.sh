#!/usr/bin/env bash
# Nightly libFuzzer for fuzz/block_wire. rust-toolchain.toml pins 1.95;
# cargo-fuzz needs nightly -Zsanitizer. Callers inherit RUSTUP_TOOLCHAIN
# if already set; default is nightly.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"

if [[ "${FUZZ_DRY_RUN:-}" == "1" ]]; then
  echo "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN"
  exit 0
fi

mkdir -p fuzz/corpus/block_wire
cp crates/rbitcoin-consensus/tests/fixtures/signet_block_1.bin \
  fuzz/corpus/block_wire/signet_block_1.bin

exec cargo fuzz run block_wire -- \
  -max_total_time="${FUZZ_MAX_TOTAL_TIME:-120}" \
  -timeout=10 \
  -max_len=1048576
