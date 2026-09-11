#!/usr/bin/env bash
# Contract: `cargo fmt --all -- --check` covers the nested fuzz crate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
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

assert_ok "clean tree passes cargo fmt --all --check" \
  cargo fmt --all -- --check

lib="$ROOT/fuzz/src/cmpct_fuzz.rs"
cp "$lib" "$lib.fmt-test.bak"
printf '\n\n\n' >>"$lib"
assert_ok "unformatted fuzz lib fails cargo fmt --all --check" \
  bash -c '! cargo fmt --all -- --check >/dev/null 2>&1'
mv "$lib.fmt-test.bak" "$lib"

tgt="$ROOT/fuzz/fuzz_targets/addrv2_wire.rs"
cp "$tgt" "$tgt.fmt-test.bak"
printf '\n\n\n' >>"$tgt"
assert_ok "unformatted fuzz target fails cargo fmt --all --check" \
  bash -c '! cargo fmt --all -- --check >/dev/null 2>&1'
mv "$tgt.fmt-test.bak" "$tgt"

if [[ "$FAIL" -ne 0 ]]; then
  echo "fmt.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "fmt.test.sh: $PASS passed"
