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

out="$(FUZZ_DRY_RUN=1 "$RUN")"
assert_ok "dry-run default toolchain is nightly" \
  grep -qx "RUSTUP_TOOLCHAIN=nightly" <<<"$out"
assert_ok "dry-run unsets CARGO_TARGET_DIR" \
  grep -qx "CARGO_TARGET_DIR_UNSET=1" <<<"$out"

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
assert_ok "differential dry-run jobs" \
  grep -qx "FUZZ_JOBS=-jobs=1" <<<"$out"
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
