#!/usr/bin/env bash
# Contract: fuzz runner forces nightly so rust-toolchain.toml 1.95 cannot
# feed cargo-fuzz (-Zsanitizer), and pins --target to rustc host so a
# musl cargo-fuzz binary does not ASan-build musl. Does not invoke cargo-fuzz.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/scripts/fuzz-run.sh"
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

out="$(FUZZ_DRY_RUN=1 "$RUN" addrv2_wire)"
assert_ok "addrv2_wire dry-run bin" \
  grep -qx "FUZZ_BIN=addrv2_wire" <<<"$out"
assert_ok "addrv2_wire dry-run sanitizer address" \
  grep -qx "FUZZ_SANITIZER=address" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" v2_contents)"
assert_ok "v2_contents dry-run bin" \
  grep -qx "FUZZ_BIN=v2_contents" <<<"$out"
assert_ok "v2_contents dry-run sanitizer address" \
  grep -qx "FUZZ_SANITIZER=address" <<<"$out"
assert_ok "v2_contents dry-run in-process (no -jobs)" \
  grep -qx "FUZZ_JOBS=in-process" <<<"$out"
assert_ok "v2_contents dry-run timeout 10" \
  grep -qx "FUZZ_TIMEOUT=10" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" v2_session)"
assert_ok "v2_session dry-run bin" \
  grep -qx "FUZZ_BIN=v2_session" <<<"$out"
assert_ok "v2_session dry-run sanitizer address" \
  grep -qx "FUZZ_SANITIZER=address" <<<"$out"
assert_ok "v2_session dry-run in-process (no -jobs)" \
  grep -qx "FUZZ_JOBS=in-process" <<<"$out"
assert_ok "v2_session dry-run timeout 90" \
  grep -qx "FUZZ_TIMEOUT=90" <<<"$out"
assert_ok "v2_session dry-run prints CORE_BITCOIND" \
  grep -q "^RBITCOIN_CORE_BITCOIND=" <<<"$out"
assert_ok "v2_session dry-run BITCOIND_LISTEN=1" \
  grep -qx "BITCOIND_LISTEN=1" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" cmpct_differential)"
assert_ok "cmpct-differential dry-run bin" \
  grep -qx "FUZZ_BIN=cmpct_differential" <<<"$out"
assert_ok "cmpct-differential dry-run sanitizer address" \
  grep -qx "FUZZ_SANITIZER=address" <<<"$out"
assert_ok "cmpct-differential dry-run in-process (no -jobs)" \
  grep -qx "FUZZ_JOBS=in-process" <<<"$out"
assert_ok "cmpct-differential dry-run timeout 90" \
  grep -qx "FUZZ_TIMEOUT=90" <<<"$out"
assert_ok "cmpct-differential dry-run prints CORE_BITCOIND" \
  grep -q "^RBITCOIN_CORE_BITCOIND=" <<<"$out"
assert_ok "cmpct-differential dry-run BITCOIND_LISTEN=1" \
  grep -qx "BITCOIND_LISTEN=1" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN")"
assert_ok "dry-run default toolchain is nightly" \
  grep -qx "RUSTUP_TOOLCHAIN=nightly" <<<"$out"
assert_ok "dry-run unsets CARGO_TARGET_DIR" \
  grep -qx "CARGO_TARGET_DIR_UNSET=1" <<<"$out"
assert_ok "dry-run prints seed" \
  grep -q "^FUZZ_SEED=" <<<"$out"
assert_ok "dry-run corpus merge" \
  grep -qx "FUZZ_CORPUS_MERGE=1" <<<"$out"
assert_ok "dry-run skip-rate gate" \
  grep -qx "FUZZ_SKIP_RATE=1" <<<"$out"
assert_ok "dry-run crashers dir" \
  grep -q "^FUZZ_CRASHERS=" <<<"$out"

out="$(FUZZ_DRY_RUN=1 FUZZ_SEED=42 "$RUN")"
assert_ok "dry-run honors FUZZ_SEED" \
  grep -qx "FUZZ_SEED=42" <<<"$out"

out="$(FUZZ_DRY_RUN=1 RUSTUP_TOOLCHAIN=nightly-2026-01-01 "$RUN")"
assert_ok "dry-run honors an explicit RUSTUP_TOOLCHAIN" \
  grep -qx "RUSTUP_TOOLCHAIN=nightly-2026-01-01" <<<"$out"

host="$(rustc -vV | sed -n 's/^host: //p')"
out="$(FUZZ_DRY_RUN=1 "$RUN")"
assert_ok "dry-run pins cargo-fuzz --target to rustc host (not musl)" \
  grep -qx "CARGO_FUZZ_TARGET=${host}" <<<"$out"
assert_ok "dry-run target is not musl" \
  bash -c 'grep -q CARGO_FUZZ_TARGET= <<<"$1" && ! grep -q musl <<<"$1"' _ "$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" block_differential)"
assert_ok "differential dry-run bin" \
  grep -qx "FUZZ_BIN=block_differential" <<<"$out"
assert_ok "differential dry-run sanitizer none" \
  grep -qx "FUZZ_SANITIZER=none" <<<"$out"
assert_ok "differential dry-run in-process (no -jobs)" \
  grep -qx "FUZZ_JOBS=in-process" <<<"$out"
assert_ok "differential dry-run timeout 90" \
  grep -qx "FUZZ_TIMEOUT=90" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" block_spend_differential)"
assert_ok "spend-differential dry-run bin" \
  grep -qx "FUZZ_BIN=block_spend_differential" <<<"$out"
assert_ok "spend-differential dry-run keeps tiny header heads" \
  grep -qx "RBITCOIN_HEAD_SCALE=tiny" <<<"$out"
assert_ok "spend-differential dry-run uses tiny 16-bit tx.head (no BITS override)" \
  test "$(grep -c '^RBITCOIN_TX_HEAD_BITS=' <<<"$out" || true)" = "0"
assert_ok "spend-differential dry-run sanitizer none" \
  grep -qx "FUZZ_SANITIZER=none" <<<"$out"
assert_ok "spend-differential dry-run in-process (no -jobs)" \
  grep -qx "FUZZ_JOBS=in-process" <<<"$out"
assert_ok "spend-differential dry-run timeout 180" \
  grep -qx "FUZZ_TIMEOUT=180" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" script_differential)"
assert_ok "script-differential dry-run bin" \
  grep -qx "FUZZ_BIN=script_differential" <<<"$out"
assert_ok "script-differential dry-run sanitizer none" \
  grep -qx "FUZZ_SANITIZER=none" <<<"$out"
assert_ok "script-differential dry-run in-process (no -jobs)" \
  grep -qx "FUZZ_JOBS=in-process" <<<"$out"
assert_ok "script-differential dry-run timeout 180" \
  grep -qx "FUZZ_TIMEOUT=180" <<<"$out"
assert_ok "script-differential dry-run prints CORE_BITCOIND" \
  grep -q "^RBITCOIN_CORE_BITCOIND=" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" block_fork_differential)"
assert_ok "fork-differential dry-run bin" \
  grep -qx "FUZZ_BIN=block_fork_differential" <<<"$out"
assert_ok "fork-differential dry-run sanitizer none" \
  grep -qx "FUZZ_SANITIZER=none" <<<"$out"
assert_ok "fork-differential dry-run in-process (no -jobs)" \
  grep -qx "FUZZ_JOBS=in-process" <<<"$out"
assert_ok "fork-differential dry-run timeout 180" \
  grep -qx "FUZZ_TIMEOUT=180" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" cmpct_reorg_differential)"
assert_ok "cmpct-reorg-differential dry-run bin" \
  grep -qx "FUZZ_BIN=cmpct_reorg_differential" <<<"$out"
assert_ok "cmpct-reorg-differential dry-run sanitizer none" \
  grep -qx "FUZZ_SANITIZER=none" <<<"$out"
assert_ok "cmpct-reorg-differential dry-run in-process (no -jobs)" \
  grep -qx "FUZZ_JOBS=in-process" <<<"$out"
assert_ok "cmpct-reorg-differential dry-run timeout 180" \
  grep -qx "FUZZ_TIMEOUT=180" <<<"$out"
assert_ok "cmpct-reorg-differential dry-run prints CORE_BITCOIND" \
  grep -q "^RBITCOIN_CORE_BITCOIND=" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" block_reorg_n_differential)"
assert_ok "reorg-n-differential dry-run bin" \
  grep -qx "FUZZ_BIN=block_reorg_n_differential" <<<"$out"
assert_ok "reorg-n-differential dry-run sanitizer none" \
  grep -qx "FUZZ_SANITIZER=none" <<<"$out"
assert_ok "reorg-n-differential dry-run timeout 180" \
  grep -qx "FUZZ_TIMEOUT=180" <<<"$out"
assert_ok "reorg-n-differential dry-run tiny heads" \
  grep -qx "RBITCOIN_HEAD_SCALE=tiny" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" block_csv_differential)"
assert_ok "csv-differential dry-run bin" \
  grep -qx "FUZZ_BIN=block_csv_differential" <<<"$out"
assert_ok "csv-differential dry-run sanitizer none" \
  grep -qx "FUZZ_SANITIZER=none" <<<"$out"
assert_ok "csv-differential dry-run timeout 180" \
  grep -qx "FUZZ_TIMEOUT=180" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" mempool_differential)"
assert_ok "mempool-differential dry-run bin" \
  grep -qx "FUZZ_BIN=mempool_differential" <<<"$out"
assert_ok "mempool-differential dry-run sanitizer none" \
  grep -qx "FUZZ_SANITIZER=none" <<<"$out"

out="$(FUZZ_DRY_RUN=1 "$RUN" script_verify_differential)"
assert_ok "script-verify-differential dry-run bin" \
  grep -qx "FUZZ_BIN=script_verify_differential" <<<"$out"
assert_ok "dry-run rustc wrapper" \
  grep -q "^RUSTC_WRAPPER=.*fuzz-rustc-allow-warnings.sh$" <<<"$out"
wrap="$ROOT/scripts/fuzz-rustc-allow-warnings.sh"
fake="$(mktemp "${TMPDIR:-/tmp}/rbtc-fake-rustc.XXXXXX")"
printf '#!/bin/sh\necho "$@"\n' >"$fake"
chmod +x "$fake"
wout="$("$wrap" "$fake" probe)"
rm -f "$fake"
assert_ok "wrapper execs given rustc (Cargo RUSTC_WRAPPER protocol)" \
  grep -qx "probe -A warnings" <<<"$wout"
assert_ok "differential dry-run unsets CARGO_TARGET_DIR" \
  grep -qx "CARGO_TARGET_DIR_UNSET=1" <<<"$out"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbtc-fuzz-log.XXXXXX")"
echo "noise" >"$WORKDIR/empty.log"
assert_ok "missing comparisons fail" \
  bash -c '! '"$RUN"' --check-log '"$WORKDIR/empty.log"
echo "block-differential: comparisons=0" >"$WORKDIR/zero.log"
assert_ok "zero comparisons fail" \
  bash -c '! '"$RUN"' --check-log '"$WORKDIR/zero.log"
echo "block-differential: comparisons=1" >"$WORKDIR/one.log"
assert_ok "comparisons=1 pass" "$RUN" --check-log "$WORKDIR/one.log"
echo "block-spend-differential: comparisons=1" >"$WORKDIR/spend.log"
assert_ok "spend comparisons=1 pass" "$RUN" --check-log "$WORKDIR/spend.log"
echo "block-fork-differential: comparisons=1" >"$WORKDIR/fork.log"
assert_ok "fork comparisons=1 pass" "$RUN" --check-log "$WORKDIR/fork.log"
echo "cmpct-differential: comparisons=1" >"$WORKDIR/cmpct.log"
assert_ok "cmpct comparisons=1 pass" "$RUN" --check-log "$WORKDIR/cmpct.log"
echo "script-differential: comparisons=1" >"$WORKDIR/script.log"
assert_ok "script comparisons=1 pass" "$RUN" --check-log "$WORKDIR/script.log"
echo "cmpct-reorg-differential: comparisons=1" >"$WORKDIR/cmpct-reorg.log"
assert_ok "cmpct-reorg comparisons=1 pass" "$RUN" --check-log "$WORKDIR/cmpct-reorg.log"

{
  echo "block-differential: comparisons=1"
  echo "Done 10000 runs in 120 second(s)"
} >"$WORKDIR/mute.log"
assert_ok "mute skip-rate (1 compare / 10000 runs) fails" \
  bash -c '! '"$RUN"' --check-log '"$WORKDIR/mute.log"
{
  echo "block-differential: comparisons=20"
  echo "Done 10000 runs in 120 second(s)"
} >"$WORKDIR/busy.log"
assert_ok "busy skip-rate (20 compare / 10000 runs) passes" \
  "$RUN" --check-log "$WORKDIR/busy.log"

mkdir -p "$WORKDIR/corpus"
echo grown >"$WORKDIR/corpus/height1.bin"
echo seed >"$WORKDIR/seed.bin"
"$RUN" --merge-seed "$WORKDIR/corpus" "$WORKDIR/seed.bin" height1.bin
assert_ok "merge does not overwrite grown corpus" \
  grep -qx grown "$WORKDIR/corpus/height1.bin"
"$RUN" --merge-seed "$WORKDIR/corpus" "$WORKDIR/seed.bin" extra.bin
assert_ok "merge copies missing seed" \
  grep -qx seed "$WORKDIR/corpus/extra.bin"

MAINNET="$ROOT/crates/rbitcoin-consensus/tests/fixtures/mainnet_block_290329.bin"
SIGNET="$ROOT/crates/rbitcoin-consensus/tests/fixtures/signet_block_1.bin"
assert_ok "Q-31 mainnet pack exists and is tiny" \
  bash -c "test -f '$MAINNET' && test \"\$(wc -c < '$MAINNET')\" -lt 1000000"
"$RUN" --merge-seed "$WORKDIR/corpus" "$MAINNET"
"$RUN" --merge-seed "$WORKDIR/corpus" "$SIGNET"
assert_ok "Q-31 mainnet pack merges as extra seed" \
  test -f "$WORKDIR/corpus/mainnet_block_290329.bin"
assert_ok "Q-31 signet pack merges as extra seed" \
  test -f "$WORKDIR/corpus/signet_block_1.bin"

mkdir -p "$WORKDIR/artifacts/block_differential"
echo boom >"$WORKDIR/artifacts/block_differential/crash-abc"
mkdir -p "$WORKDIR/crashers"
"$RUN" --copy-crashers "$WORKDIR/artifacts" "$WORKDIR/crashers"
assert_ok "copy-crashers copies artifact files" \
  test -f "$WORKDIR/crashers/crash-abc"

rm -rf "$WORKDIR"

# Pin/fetch tests land before the operator YAML commit; required CI already
# runs this script.
if [[ -x "$ROOT/scripts/core-functional/release_pin.test.sh" ]]; then
  assert_ok "release_pin.test.sh" "$ROOT/scripts/core-functional/release_pin.test.sh"
fi
if [[ -x "$ROOT/scripts/core-functional/fetch-bitcoind.test.sh" ]]; then
  assert_ok "fetch-bitcoind.test.sh" "$ROOT/scripts/core-functional/fetch-bitcoind.test.sh"
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "fuzz-run.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "fuzz-run.test.sh: $PASS passed"
