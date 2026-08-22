#!/usr/bin/env bash
# Contract: fuzz runner forces nightly so rust-toolchain.toml 1.95 cannot
# feed cargo-fuzz (-Zsanitizer). Does not invoke cargo-fuzz.
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

out="$(FUZZ_DRY_RUN=1 RUSTUP_TOOLCHAIN=nightly-2026-01-01 "$RUN")"
assert_ok "dry-run honors an explicit RUSTUP_TOOLCHAIN" \
  grep -qx "RUSTUP_TOOLCHAIN=nightly-2026-01-01" <<<"$out"

if [[ "$FAIL" -ne 0 ]]; then
  echo "fuzz-run.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "fuzz-run.test.sh: $PASS passed"
