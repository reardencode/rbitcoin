#!/usr/bin/env bash
# Contract pin for the test-only bitcoind shim (argv / conf; no cargo).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SHIM="$ROOT/scripts/core-functional/bitcoind"
PASS=0
FAIL=0

assert_ok() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name"
    FAIL=$((FAIL + 1))
  fi
}

assert_fail_msg() {
  local name="$1"
  local needle="$2"
  shift 2
  local out
  if out="$("$@" 2>&1)"; then
    echo "not ok - $name (expected failure)"
    FAIL=$((FAIL + 1))
    return
  fi
  if printf '%s' "$out" | grep -q -- "$needle"; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name (missing '$needle' in: $out)"
    FAIL=$((FAIL + 1))
  fi
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-cf-shim.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# Fake node binary so --print-cmd does not require a cargo build.
FAKE="$WORKDIR/rbitcoin-node"
printf '#!/bin/sh\nexit 0\n' >"$FAKE"
chmod +x "$FAKE"
export RBITCOIN_NODE="$FAKE"

DATADIR="$WORKDIR/node0"
mkdir -p "$DATADIR"
cat >"$DATADIR/bitcoin.conf" <<'EOF'
regtest=1
[regtest]
port=18444
rpcport=18443
server=1
EOF

# Relative RBITCOIN_NODE is resolved from the repo root (TestNode cwd is a tmpdir).
REL_FAKE="scripts/core-functional/.bitcoind-test-fake-node"
ln -sfn "$FAKE" "$ROOT/$REL_FAKE"
cleanup_rel() { rm -f "$ROOT/$REL_FAKE"; cleanup; }
trap cleanup_rel EXIT
if RBITCOIN_NODE="$REL_FAKE" OUT_REL="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest 2>/dev/null)" \
  && printf '%s' "$OUT_REL" | grep -q -- '.bitcoind-test-fake-node'; then
  echo "ok - relative RBITCOIN_NODE resolves from repo root"
  PASS=$((PASS + 1))
else
  echo "not ok - relative RBITCOIN_NODE resolves from repo root"
  FAIL=$((FAIL + 1))
fi

OUT="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -debug 2>/dev/null)"
if printf '%s' "$OUT" | grep -q -- "--network regtest" \
  && printf '%s' "$OUT" | grep -q -- "--datadir ${DATADIR}/regtest" \
  && printf '%s' "$OUT" | grep -q -- "--rpc-listen 127.0.0.1:28443" \
  && printf '%s' "$OUT" | grep -q -- "--esplora-listen 127.0.0.1:38443" \
  && printf '%s' "$OUT" | grep -q -- "--listen 127.0.0.1:18444" \
  && printf '%s' "$OUT" | grep -q -- "--no-seeds" \
  && printf '%s' "$OUT" | grep -q -- "--log-level debug"; then
  echo "ok - print-cmd maps conf + -debug"
  PASS=$((PASS + 1))
else
  echo "not ok - print-cmd maps conf + -debug (got: $OUT)"
  FAIL=$((FAIL + 1))
fi

# TestNode always passes -debug and -loglevel=trace; take the more verbose.
OUTT="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -debug -loglevel=trace 2>/dev/null)"
if printf '%s' "$OUTT" | grep -q -- "--log-level trace"; then
  echo "ok - print-cmd maps -debug -loglevel=trace to --log-level trace"
  PASS=$((PASS + 1))
else
  echo "not ok - print-cmd maps -debug -loglevel=trace (got: $OUTT)"
  FAIL=$((FAIL + 1))
fi

# CLI -rpcport / -port override conf; -v2transport=0 ignored (we force v2).
OUT2="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -rpcport=19111 -port=19222 -v2transport=0 -disablewallet -server \
  -uacomment=testnode0 2>/dev/null)"
if printf '%s' "$OUT2" | grep -q -- "--rpc-listen 127.0.0.1:29111" \
  && printf '%s' "$OUT2" | grep -q -- "--esplora-listen 127.0.0.1:39111" \
  && printf '%s' "$OUT2" | grep -q -- "--listen 127.0.0.1:19222"; then
  echo "ok - CLI ports override conf"
  PASS=$((PASS + 1))
else
  echo "not ok - CLI ports override conf (got: $OUT2)"
  FAIL=$((FAIL + 1))
fi

# -bind=0.0.0.0:P supplies the P2P port; we still listen on 127.0.0.1.
OUT3="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -bind=0.0.0.0:19333 -bind=127.0.0.1:19444=onion 2>/dev/null)"
if printf '%s' "$OUT3" | grep -q -- "--listen 127.0.0.1:19333" \
  && ! printf '%s' "$OUT3" | grep -q -- "--listen 127.0.0.1:19444"; then
  echo "ok - bind port becomes listen (onion ignored)"
  PASS=$((PASS + 1))
else
  echo "not ok - bind port becomes listen (got: $OUT3)"
  FAIL=$((FAIL + 1))
fi

# Unknown flags abort like Core (feature_help.py -fakearg).
assert_fail_msg "unknown flag parse error" "Error parsing command line arguments" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -notarealflag
assert_fail_msg "fakearg still hard-fails" "Error parsing command line arguments" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -fakearg

# Consensus/mempool/peer flags are forwarded; harness-only extras stay ignored.
OUTX="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -whitelist=noban@127.0.0.1 -txindex -fastprune -limitclustercount=10 \
  -testactivationheight=csv@102 -permitbaremultisig=0 -maxconnections=8 \
  -minimumchainwork=0x65 -limitancestorcount=5 -blockversion=1337 -mocktime=1296688602 \
  -blockmintxfee=0.00000001 -proxy=127.0.0.1:1 -deprecatedrpc=startingheight \
  2>/dev/null)" || OUTX=""
if printf '%s' "$OUTX" | grep -q -- "--testactivationheight=csv@102" \
  && printf '%s' "$OUTX" | grep -q -- "--whitelist=noban@127.0.0.1" \
  && printf '%s' "$OUTX" | grep -q -- "--limitclustercount=10" \
  && printf '%s' "$OUTX" | grep -q -- "--permitbaremultisig=0" \
  && printf '%s' "$OUTX" | grep -q -- "--maxconnections=8" \
  && printf '%s' "$OUTX" | grep -q -- "--minimumchainwork=0x65" \
  && printf '%s' "$OUTX" | grep -q -- "--blockversion=1337" \
  && printf '%s' "$OUTX" | grep -q -- "--mocktime=1296688602" \
  && printf '%s' "$OUTX" | grep -q -- "--blockmintxfee=0.00000001" \
  && ! printf '%s' "$OUTX" | grep -q -- "limitancestor" \
  && ! printf '%s' "$OUTX" | grep -q -- "txindex" \
  && ! printf '%s' "$OUTX" | grep -q -- "fastprune" \
  && ! printf '%s' "$OUTX" | grep -q -- "proxy" \
  && ! printf '%s' "$OUTX" | grep -q -- "deprecatedrpc"; then
  echo "ok - consensus/mempool/peer flags forwarded"
  PASS=$((PASS + 1))
else
  echo "not ok - consensus/mempool/peer flags forwarded (got: $OUTX)"
  FAIL=$((FAIL + 1))
fi

OUTNO="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -nopersistmempool -printpriority=1 -addresstype=legacy 2>/dev/null)" || OUTNO=""
if printf '%s' "$OUTNO" | grep -q -- "--persistmempool=0" \
  && ! printf '%s' "$OUTNO" | grep -q -- "printpriority" \
  && ! printf '%s' "$OUTNO" | grep -q -- "addresstype"; then
  echo "ok - -nopersistmempool forwarded, printpriority/addresstype ignored"
  PASS=$((PASS + 1))
else
  echo "not ok - -nofoo / printpriority (got: $OUTNO)"
  FAIL=$((FAIL + 1))
fi

assert_fail_msg "txindex=0 cannot disable Class A lookup" "Error parsing command line arguments" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -txindex=0

# -h / -version exit 0 on stdout without starting the node.
if OUTH="$("$SHIM" -datadir="$DATADIR" -h 2>/dev/null)" && printf '%s' "$OUTH" | grep -q Options; then
  echo "ok - -h prints Options"
  PASS=$((PASS + 1))
else
  echo "not ok - -h prints Options"
  FAIL=$((FAIL + 1))
fi
if OUTV="$("$SHIM" -datadir="$DATADIR" -version 2>/dev/null)" && printf '%s' "$OUTV" | grep -qi version; then
  echo "ok - -version prints version"
  PASS=$((PASS + 1))
else
  echo "not ok - -version prints version"
  FAIL=$((FAIL + 1))
fi

OUT4="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -uacomment=testnode0 2>/dev/null)"
if printf '%s' "$OUT4" | grep -q -- '--uacomment=testnode0'; then
  echo "ok - uacomment forwarded"
  PASS=$((PASS + 1))
else
  echo "not ok - uacomment forwarded (got: $OUT4)"
  FAIL=$((FAIL + 1))
fi

assert_fail_msg "datadir required" "datadir is required" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -regtest

# Cache seed: dest looks like a Core cache copy (blocks+chainstate, no store).
CACHE="$WORKDIR/rbcache"
mkdir -p "$CACHE/store"
echo seeded >"$CACHE/store/marker"
CACHED="$WORKDIR/cached-node"
mkdir -p "$CACHED/regtest/blocks" "$CACHED/regtest/chainstate"
if RBITCOIN_CACHE="$CACHE" "$SHIM" --print-cmd -datadir="$CACHED" -regtest >/dev/null \
  && [[ -f "$CACHED/regtest/store/marker" ]] \
  && grep -q seeded "$CACHED/regtest/store/marker"; then
  echo "ok - cache store copied into cache-shaped dest"
  PASS=$((PASS + 1))
else
  echo "not ok - cache store copied into cache-shaped dest"
  FAIL=$((FAIL + 1))
fi

# Clean chain (no blocks/chainstate) must not receive the 199-block store.
CLEAN="$WORKDIR/clean-node"
mkdir -p "$CLEAN"
if RBITCOIN_CACHE="$CACHE" "$SHIM" --print-cmd -datadir="$CLEAN" -regtest >/dev/null \
  && [[ ! -e "$CLEAN/regtest/store" ]]; then
  echo "ok - clean chain is not seeded from cache"
  PASS=$((PASS + 1))
else
  echo "not ok - clean chain is not seeded from cache"
  FAIL=$((FAIL + 1))
fi

# -blocksdir missing dir refuses like Core (feature_blocksdir.py).
MISSING_BD="$WORKDIR/no-such-blocksdir"
assert_fail_msg "blocksdir missing refuses" "Specified blocks directory" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -blocksdir="$MISSING_BD"

# -blocksdir existing: Core-shaped <blocksdir>/<network>/blocks/blk00000.dat
BD="$WORKDIR/ext-blocks"
mkdir -p "$BD"
BD_NODE="$WORKDIR/bd-node"
mkdir -p "$BD_NODE"
if RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$BD_NODE" -regtest \
  -blocksdir="$BD" >/dev/null \
  && [[ -f "$BD/regtest/blocks/blk00000.dat" ]] \
  && [[ -d "$BD_NODE/regtest/blocks/index" ]]; then
  echo "ok - blocksdir layout + default blocks/index"
  PASS=$((PASS + 1))
else
  echo "not ok - blocksdir layout + default blocks/index"
  FAIL=$((FAIL + 1))
fi

# -peerbloomfilters is ignored (no bloom product; p2p_nobloomfilter_messages).
OUT_BLOOM="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -peerbloomfilters=0 2>/dev/null)" || OUT_BLOOM=""
if printf '%s' "$OUT_BLOOM" | grep -q -- "--network regtest"; then
  echo "ok - peerbloomfilters ignored"
  PASS=$((PASS + 1))
else
  echo "not ok - peerbloomfilters ignored (got: $OUT_BLOOM)"
  FAIL=$((FAIL + 1))
fi

# Live smoke when a real node binary is on disk (optional in this script).
REAL=""
if [[ -n "${RBITCOIN_NODE_REAL:-}" && -x "${RBITCOIN_NODE_REAL}" ]]; then
  REAL="$RBITCOIN_NODE_REAL"
elif [[ -x "${CARGO_TARGET_DIR:-$ROOT/target/dev}/debug/rbitcoin-node" ]]; then
  REAL="${CARGO_TARGET_DIR:-$ROOT/target/dev}/debug/rbitcoin-node"
fi
if [[ -n "$REAL" ]]; then
  if RBITCOIN_NODE="$REAL" python3 "$ROOT/scripts/core-functional/smoke_rpc_up.py"; then
    echo "ok - smoke_rpc_up"
    PASS=$((PASS + 1))
  else
    echo "not ok - smoke_rpc_up"
    FAIL=$((FAIL + 1))
  fi
else
  echo "ok - smoke_rpc_up skipped (no rbitcoin-node binary)"
  PASS=$((PASS + 1))
fi

echo
echo "$PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
