#!/usr/bin/env bash
# Text contract for the Warnet lab image (no docker required).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0

ok() { echo "ok - $1"; PASS=$((PASS + 1)); }
bad() { echo "not ok - $1"; FAIL=$((FAIL + 1)); }

EP="$HERE/entrypoint.sh"
DF="$HERE/Dockerfile"

if [[ -f "$EP" ]] && grep -q 'BITCOIN_DATA:-/root/.bitcoin' "$EP" \
  && grep -q 'exec' "$EP"; then
  ok "entrypoint defaults -datadir to BITCOIN_DATA or /root/.bitcoin"
else
  bad "entrypoint defaults -datadir to BITCOIN_DATA or /root/.bitcoin"
fi

if [[ -f "$DF" ]] \
  && grep -q 'rbitcoin-node' "$DF" \
  && grep -q 'bitcoind' "$DF" \
  && grep -q 'bitcoin-cli' "$DF" \
  && grep -q 'test_framework' "$DF" \
  && grep -q 'RBITCOIN_LOG_STDOUT' "$DF"; then
  ok "Dockerfile copies node, shims, test_framework, log tee"
else
  bad "Dockerfile copies node, shims, test_framework, log tee"
fi

echo
echo "$PASS passed, $FAIL failed"
if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi
