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

run "0.0.0.0 listen maps to Bound to" \
  "2026-01-01T00:00:00Z INFO rbitcoin-node listening on 0.0.0.0:18555 (regtest)" \
  "Bound to 0.0.0.0:18555"

run "p2p dial maps to Core trying v1 needle" \
  "2026-01-01T00:00:00Z DEBUG p2p: trying connection (outbound-full-relay) to 25.0.0.1:8333" \
  "trying v1 connection (outbound-full-relay) to 25.0.0.1:8333"

run "received tx TRACE maps to Core needle" \
  "2026-01-01T00:00:00Z TRACE p2p: received tx" \
  "received: tx"

run "tip best maps to Core UpdateTip" \
  "2026-01-01T00:00:00Z INFO tip: best=aabbccdd11223344556677889900aabbccddeeff00112233445566778899aabb height=1 version=4 tx=1 date=1296688602" \
  "UpdateTip: new best=aabbccdd11223344556677889900aabbccddeeff00112233445566778899aabb height=1 version=4 tx=1 date=1296688602 progress=tip"

run "header missing pow maps to AcceptBlockHeader" \
  "2026-01-01T00:00:00Z INFO p2p: header aabbccdd11223344556677889900aabbccddeeff00112233445566778899aabb missing pow proof — not stored" \
  "AcceptBlockHeader: not adding new block header aabbccdd11223344556677889900aabbccddeeff00112233445566778899aabb, missing anti-dos proof-of-work validation"

run "accept prev not found maps to AcceptBlock FAILED" \
  "2026-01-01T00:00:00Z INFO p2p: accept dropped aabbccdd11223344556677889900aabbccddeeff00112233445566778899aabb (prev not found)" \
  "AcceptBlock FAILED (prev-blk-not-found)"

run "ignore low-work headers maps to Core [net] needle" \
  "2026-01-01T00:00:00Z INFO p2p: ignore low-work headers height=14" \
  "[net] Ignoring low-work chain (height=14)"

run "headers sync height maps to Synchronizing blockheaders" \
  "2026-01-01T00:00:00Z INFO p2p: headers sync height=14" \
  "Synchronizing blockheaders, height: 14"

run "initial getheaders maps to Core needle" \
  "2026-01-01T00:00:00Z INFO p2p: initial getheaders height=0 peer=0" \
  "initial getheaders (0) to peer=0"

run "headers timeout disconnect maps to Core needle" \
  "2026-01-01T00:00:00Z INFO p2p: headers sync timeout, disconnect peer=0" \
  "Timeout downloading headers, disconnecting peer=0"

run "headers timeout keep peer maps to Core noban needle" \
  "2026-01-01T00:00:00Z INFO p2p: headers sync timeout, keep peer=0" \
  "Timeout downloading headers from noban peer, not disconnecting peer=0"

run "getdata wtx TRACE maps to Core needle" \
  "2026-01-01T00:00:00Z TRACE p2p: getdata wtx aabbccdd peer=3" \
  "received getdata for: wtx aabbccdd peer"

run "future tip maps to Core InitError needle" \
  "Store tip time is more than two hours ahead of the node clock. Check the clock (or --mocktime). Wipe the datadir and redo IBD only if you are sure the clock is correct." \
  "The block database contains a block which appears to be from the future."

run "parked orphan DEBUG maps to Core was-not-accepted needle" \
  "2026-01-01T00:00:00Z DEBUG txrelay: park 1111111111111111111111111111111111111111111111111111111111111111" \
  "was not accepted"

run "CLI InitError maps peer-timeout to Core peertimeout" \
  "Error: configuration error: peer-timeout must be a positive integer." \
  "Error: peertimeout must be a positive integer."

run "CLI InitError drops configuration error prefix (minchainwork)" \
  "Error: configuration error: Invalid minimum work specified (test), must be up to 64 hex digits" \
  "Error: Invalid minimum work specified (test), must be up to 64 hex digits"

run "unmapped is empty" \
  "2026-01-01T00:00:00Z INFO something else" \
  ""

echo
echo "$PASS passed, $FAIL failed"
if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi
