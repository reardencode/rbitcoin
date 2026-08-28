#!/usr/bin/env bash
# Unit pin for debug.log mapper (no node).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MAP="$HERE/debuglog_map.toml"
PASS=0
FAIL=0

run() {
  local name="$1"
  local line="$2"
  local want="$3"
  local got
  got="$(python3 "$HERE/map_debuglog.py" --map "$MAP" "$line")"
  if [[ "$got" == "$want" ]]; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name (got: $got want: $want)"
    FAIL=$((FAIL + 1))
  fi
}

run "listen maps to Bound to" \
  "2026-01-01T00:00:00Z INFO rbitcoin-node listening on 127.0.0.1:18444 (regtest)" \
  "Bound to 127.0.0.1:18444"

run "p2p dial maps to Core trying v1 needle" \
  "2026-01-01T00:00:00Z DEBUG p2p: trying connection (outbound-full-relay) to 25.0.0.1:8333" \
  "trying v1 connection (outbound-full-relay) to 25.0.0.1:8333"

run "unmapped is empty" \
  "2026-01-01T00:00:00Z INFO something else" \
  ""

echo
echo "$PASS passed, $FAIL failed"
if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi
