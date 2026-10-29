#!/usr/bin/env bash
# Contract: production 0x integer literals are frozen per file.
# Fixtures under lint/hex-ratchet/fixtures. Does not scan the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/scripts/hex-ratchet.py"
FIX="$ROOT/lint/hex-ratchet/fixtures"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"

assert_fail "a hex literal in src fails an empty baseline" \
  python3 "$PY" --root "$FIX/bare"
assert_ok "comments, strings, and char escapes are not counted" \
  python3 "$PY" --root "$FIX/comment"
assert_ok "cfg(test) hex is not counted" \
  python3 "$PY" --root "$FIX/cfg-test"
assert_ok "hex under tests/ is not counted" \
  python3 "$PY" --root "$FIX/in-tests"
assert_fail "count above the baseline fails" \
  python3 "$PY" --root "$FIX/over"
assert_fail "count below the baseline fails" \
  python3 "$PY" --root "$FIX/under"
assert_ok "a matching count passes" \
  python3 "$PY" --root "$FIX/match"
assert_fail "two hex literals on one line count as two" \
  python3 "$PY" --root "$FIX/two"
assert_ok "one underscored literal counts as one" \
  python3 "$PY" --root "$FIX/underscore"

if [[ "$FAIL" -ne 0 ]]; then
  echo "hex-ratchet.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "hex-ratchet.test.sh: $PASS passed"
