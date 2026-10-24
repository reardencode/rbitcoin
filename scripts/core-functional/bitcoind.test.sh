#!/usr/bin/env bash
# Contract pin for the test-only bitcoind shim (argv / conf; no cargo).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SHIM="$ROOT/scripts/core-functional/bitcoind"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"
assert_ok() { assert_ok_quiet "$@"; }


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
  && printf '%s' "$OUT" | grep -q -- "--listen 0.0.0.0:18444" \
  && printf '%s' "$OUT" | grep -q -- "--listen 127.0.0.1:18445" \
  && printf '%s' "$OUT" | grep -q -- "--no-seeds" \
  && printf '%s' "$OUT" | grep -q -- "--log-level debug" \
  && ! printf '%s' "$OUT" | grep -q -- "--sh-index"; then
  echo "ok - print-cmd maps conf + -debug"
  PASS=$((PASS + 1))
else
  echo "not ok - print-cmd maps conf + -debug (got: $OUT)"
  FAIL=$((FAIL + 1))
fi

# Core's runner uses `{script}_{n}/node{i}`. Address history gets
# --sh-index. Mining and compact-block scripts do not. Esplora stays on.
sh_cmd() {
  local parent="$1"
  local dd="$WORKDIR/$parent/node0"
  mkdir -p "$dd"
  cp "$DATADIR/bitcoin.conf" "$dd/bitcoin.conf"
  "$SHIM" --print-cmd -datadir="$dd" -regtest 2>/dev/null
}
assert_sh_off() {
  local parent="$1"
  local out
  out="$(sh_cmd "$parent")" || true
  if printf '%s' "$out" | grep -q -- "--esplora-listen" \
    && ! printf '%s' "$out" | grep -q -- "--sh-index"; then
    echo "ok - $parent starts without --sh-index"
    PASS=$((PASS + 1))
  else
    echo "not ok - $parent starts without --sh-index (got: $out)"
    FAIL=$((FAIL + 1))
  fi
}
assert_sh_on() {
  local parent="$1"
  local out
  out="$(sh_cmd "$parent")" || true
  if printf '%s' "$out" | grep -q -- "--sh-index" \
    && printf '%s' "$out" | grep -q -- "--esplora-listen"; then
    echo "ok - $parent starts with --sh-index"
    PASS=$((PASS + 1))
  else
    echo "not ok - $parent starts with --sh-index (got: $out)"
    FAIL=$((FAIL + 1))
  fi
}
assert_sh_off "p2p_compactblocks_hb_0"
assert_sh_off "feature_nulldummy_0"
assert_sh_off "p2p_v2_misbehaving_0"
assert_sh_on "rpc_getblockstats_0"
assert_sh_on "mempool_accept_wtxid_12"

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
  && printf '%s' "$OUT2" | grep -q -- "--listen 0.0.0.0:19222" \
  && printf '%s' "$OUT2" | grep -q -- "--listen 127.0.0.1:19223"; then
  echo "ok - CLI ports override conf"
  PASS=$((PASS + 1))
else
  echo "not ok - CLI ports override conf (got: $OUT2)"
  FAIL=$((FAIL + 1))
fi

# -bind=0.0.0.0:P supplies the P2P port; onion binds become extra --listen.
OUT3="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -bind=0.0.0.0:19333 -bind=127.0.0.1:19444=onion 2>/dev/null)"
if printf '%s' "$OUT3" | grep -q -- "--listen 0.0.0.0:19333" \
  && printf '%s' "$OUT3" | grep -q -- "--listen 127.0.0.1:19444"; then
  echo "ok - bind port becomes listen (onion as extra listen)"
  PASS=$((PASS + 1))
else
  echo "not ok - bind port becomes listen (got: $OUT3)"
  FAIL=$((FAIL + 1))
fi

# Unknown flags abort like Core (feature_help.py -fakearg).
assert_fail_msg "maxmempool below 5 MB" "Error: -maxmempool must be at least 5 MB" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -maxmempool=4

assert_fail_msg "unknown flag parse error" "Error parsing command line arguments" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -notarealflag
assert_fail_msg "fakearg still hard-fails" "Error parsing command line arguments" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -fakearg

# Consensus/mempool/peer flags are forwarded; harness-only extras stay ignored.
OUTX="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -whitelist=noban@127.0.0.1 -txindex -fastprune -limitclustercount=10 \
  -testactivationheight=csv@102 -permitbaremultisig=0 -maxconnections=8 \
  -minimumchainwork=0x65 -limitancestorcount=5 -blockversion=1337 -mocktime=1296688602 \
  -maxtipage=3600 -blockmintxfee=0.00000001 -externalip=42.42.42.42 \
  -checkblocks=0 -maxmempool=5 \
  -proxy=127.0.0.1:1 -deprecatedrpc=startingheight -par=1 \
  2>/dev/null)" || OUTX=""
if printf '%s' "$OUTX" | grep -q -- "--test-activation-height=csv@102" \
  && printf '%s' "$OUTX" | grep -q -- "--net-permission=noban@127.0.0.1" \
  && printf '%s' "$OUTX" | grep -q -- "--limit-cluster-count=10" \
  && ! printf '%s' "$OUTX" | grep -q -- "permitbaremultisig" \
  && printf '%s' "$OUTX" | grep -q -- "--max-inbound=1" \
  && printf '%s' "$OUTX" | grep -q -- "--min-chain-work=0x65" \
  && printf '%s' "$OUTX" | grep -q -- "--block-version=1337" \
  && printf '%s' "$OUTX" | grep -q -- "--mock-time=1296688602" \
  && printf '%s' "$OUTX" | grep -q -- "--max-tip-age=3600" \
  && printf '%s' "$OUTX" | grep -q -- "--block-min-tx-fee=0.00000001" \
  && printf '%s' "$OUTX" | grep -q -- "--external-ip=42.42.42.42" \
  && printf '%s' "$OUTX" | grep -q -- "--check-blocks=0" \
  && printf '%s' "$OUTX" | grep -q -- "--mempool-size-mb=20" \
  && ! printf '%s' "$OUTX" | grep -q -- "--whitelist" \
  && ! printf '%s' "$OUTX" | grep -q -- "--maxconnections" \
  && ! printf '%s' "$OUTX" | grep -q -- "limitancestor" \
  && ! printf '%s' "$OUTX" | grep -q -- "txindex" \
  && ! printf '%s' "$OUTX" | grep -q -- "fastprune" \
  && ! printf '%s' "$OUTX" | grep -q -- "proxy" \
  && ! printf '%s' "$OUTX" | grep -q -- "par" \
  && ! printf '%s' "$OUTX" | grep -q -- "deprecatedrpc"; then
  echo "ok - consensus/mempool/peer flags forwarded"
  PASS=$((PASS + 1))
else
  echo "not ok - consensus/mempool/peer flags forwarded (got: $OUTX)"
  FAIL=$((FAIL + 1))
fi

OUTNO="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -nopersistmempool -printpriority=1 -addresstype=legacy 2>/dev/null)" || OUTNO=""
if printf '%s' "$OUTNO" | grep -q -- "--persist-mempool=0" \
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
if printf '%s' "$OUT4" | grep -q -- '--ua-comment=testnode0'; then
  echo "ok - uacomment mapped to --ua-comment"
  PASS=$((PASS + 1))
else
  echo "not ok - uacomment mapped to --ua-comment (got: $OUT4)"
  FAIL=$((FAIL + 1))
fi

OUTMC="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -maxconnections=32 2>/dev/null)" || OUTMC=""
if printf '%s' "$OUTMC" | grep -q -- '--max-inbound=21' \
  && ! printf '%s' "$OUTMC" | grep -q -- maxconnections; then
  echo "ok - maxconnections=32 maps to --max-inbound=21"
  PASS=$((PASS + 1))
else
  echo "not ok - maxconnections=32 maps to --max-inbound=21 (got: $OUTMC)"
  FAIL=$((FAIL + 1))
fi

OUTWL="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -whitelist=noban,relay,forcerelay@127.0.0.1 2>/dev/null)" || OUTWL=""
if printf '%s' "$OUTWL" | grep -q -- '--net-permission=noban,relay,forcerelay@127.0.0.1' \
  && ! printf '%s' "$OUTWL" | grep -q -- '--whitelist' \
  && ! printf '%s' "$OUTWL" | grep -q -- whitelist=; then
  echo "ok - whitelist maps to --net-permission"
  PASS=$((PASS + 1))
else
  echo "not ok - whitelist maps to --net-permission (got: $OUTWL)"
  FAIL=$((FAIL + 1))
fi

OUTBO="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -blocksonly 2>/dev/null)" || OUTBO=""
if printf '%s' "$OUTBO" | grep -q -- '--blocks-only' \
  && ! printf '%s' "$OUTBO" | grep -q -- blocksonly; then
  echo "ok - -blocksonly maps to --blocks-only"
  PASS=$((PASS + 1))
else
  echo "not ok - -blocksonly maps to --blocks-only (got: $OUTBO)"
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
# (dummy layout only; the node has no --blocks-dir product).
BD="$WORKDIR/ext-blocks"
mkdir -p "$BD"
BD_NODE="$WORKDIR/bd-node"
mkdir -p "$BD_NODE"
if RBITCOIN_NODE="$FAKE" OUT_BD="$("$SHIM" --print-cmd -datadir="$BD_NODE" -regtest \
  -blocksdir="$BD" 2>/dev/null)" \
  && ! printf '%s' "$OUT_BD" | grep -q -- "--blocks-dir" \
  && [[ -f "$BD/regtest/blocks/blk00000.dat" ]] \
  && [[ -d "$BD_NODE/regtest/blocks/index" ]]; then
  echo "ok - blocksdir layout + default blocks/index"
  PASS=$((PASS + 1))
else
  echo "not ok - blocksdir layout + default blocks/index"
  FAIL=$((FAIL + 1))
fi

# -peerbloomfilters is ignored (no BIP37 product; disconnect is unconditional).
OUT_BLOOM="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -peerbloomfilters=0 2>/dev/null)" || OUT_BLOOM=""
if printf '%s' "$OUT_BLOOM" | grep -q -- "--network regtest" \
  && ! printf '%s' "$OUT_BLOOM" | grep -q -- 'peerbloomfilters'; then
  echo "ok - peerbloomfilters ignored"
  PASS=$((PASS + 1))
else
  echo "not ok - peerbloomfilters ignored (got: $OUT_BLOOM)"
  FAIL=$((FAIL + 1))
fi

# feature_port.py: -listen is a Core boolean; bare -port binds 0.0.0.0 + onion port+1.
OUT_LISTEN="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -listen -port=18555 2>/dev/null)" || OUT_LISTEN=""
if printf '%s' "$OUT_LISTEN" | grep -q -- "--listen 0.0.0.0:18555" \
  && printf '%s' "$OUT_LISTEN" | grep -q -- "--listen 127.0.0.1:18556"; then
  echo "ok - -listen accepted with -port"
  PASS=$((PASS + 1))
else
  echo "not ok - -listen accepted with -port (got: $OUT_LISTEN)"
  FAIL=$((FAIL + 1))
fi

# TestNode extra_conf bind=127.0.0.1 (no port) combines with -port.
BIND_DD="$WORKDIR/conf-bind-local"
mkdir -p "$BIND_DD"
printf 'regtest=1\nbind=127.0.0.1\nport=18444\nrpcport=18443\n' >"$BIND_DD/bitcoin.conf"
OUT_LOCAL="$("$SHIM" --print-cmd -datadir="$BIND_DD" -regtest 2>/dev/null)" || OUT_LOCAL=""
if printf '%s' "$OUT_LOCAL" | grep -q -- "--listen 127.0.0.1:18444" \
  && ! printf '%s' "$OUT_LOCAL" | grep -q -- "--listen 0.0.0.0:"; then
  echo "ok - conf bind=127.0.0.1 stays loopback"
  PASS=$((PASS + 1))
else
  echo "not ok - conf bind=127.0.0.1 stays loopback (got: $OUT_LOCAL)"
  FAIL=$((FAIL + 1))
fi

# Warnet Helm: addnode=tank name becomes --connect host:port and seeds rpc.token.
WN_DD="$WORKDIR/warnet-conf"
mkdir -p "$WN_DD"
printf 'regtest=1\nrpcuser=warnet\nrpcpassword=secret0\nrpcbind=0.0.0.0\naddnode=tank-0001\nhead_scale=tiny\nport=18444\nrpcport=18443\n' >"$WN_DD/bitcoin.conf"
OUT_WN="$("$SHIM" --print-cmd -datadir="$WN_DD" -regtest 2>/dev/null)" || OUT_WN=""
if printf '%s' "$OUT_WN" | grep -q -- "--connect tank-0001:18444" \
  && printf '%s' "$OUT_WN" | grep -q -- "--head-scale tiny" \
  && [[ "$(cat "$WN_DD/regtest/rpc.token")" == "secret0" ]]; then
  echo "ok - addnode= becomes --connect and rpcpassword seeds rpc.token"
  PASS=$((PASS + 1))
else
  echo "not ok - warnet conf translate (got: $OUT_WN token=$(cat "$WN_DD/regtest/rpc.token" 2>/dev/null))"
  FAIL=$((FAIL + 1))
fi

# Lab image: no head_scale in conf, entrypoint default selects tiny.
# Explicit head_scale=mainnet still wins. Unset lab env leaves the node default.
HS_DD="$WORKDIR/warnet-no-scale"
mkdir -p "$HS_DD"
printf 'regtest=1\nrpcpassword=secret0\nrpcbind=0.0.0.0\naddnode=tank-0001\nport=18444\nrpcport=18443\n' >"$HS_DD/bitcoin.conf"
OUT_HS="$(RBITCOIN_LAB_HEAD_SCALE=tiny "$SHIM" --print-cmd -datadir="$HS_DD" -regtest 2>/dev/null)" || OUT_HS=""
if printf '%s' "$OUT_HS" | grep -q -- "--head-scale tiny" \
  && printf '%s' "$OUT_HS" | grep -q -- "--connect tank-0001:18444" \
  && [[ "$(cat "$HS_DD/regtest/rpc.token")" == "secret0" ]]; then
  echo "ok - lab default head scale is tiny when conf omits it"
  PASS=$((PASS + 1))
else
  echo "not ok - lab default head scale is tiny (got: $OUT_HS)"
  FAIL=$((FAIL + 1))
fi
printf 'regtest=1\nhead_scale=mainnet\nport=18444\nrpcport=18443\n' >"$HS_DD/bitcoin.conf"
OUT_HM="$(RBITCOIN_LAB_HEAD_SCALE=tiny "$SHIM" --print-cmd -datadir="$HS_DD" -regtest 2>/dev/null)" || OUT_HM=""
if printf '%s' "$OUT_HM" | grep -q -- "--head-scale mainnet" \
  && ! printf '%s' "$OUT_HM" | grep -q -- "--head-scale tiny"; then
  echo "ok - conf head_scale=mainnet overrides the lab default"
  PASS=$((PASS + 1))
else
  echo "not ok - conf head_scale=mainnet overrides the lab default (got: $OUT_HM)"
  FAIL=$((FAIL + 1))
fi
# Conf still says mainnet; drop it and leave the lab env unset.
printf 'regtest=1\nport=18444\nrpcport=18443\n' >"$HS_DD/bitcoin.conf"
OUT_HU="$(env -u RBITCOIN_LAB_HEAD_SCALE "$SHIM" --print-cmd -datadir="$HS_DD" -regtest 2>/dev/null)" || OUT_HU=""
if ! printf '%s' "$OUT_HU" | grep -q -- "--head-scale"; then
  echo "ok - omitted head_scale without the lab env stays the node default"
  PASS=$((PASS + 1))
else
  echo "not ok - omitted head_scale without the lab env (got: $OUT_HU)"
  FAIL=$((FAIL + 1))
fi

# Lab log switch: node stdout is tee'd. Off, the shim stays quiet.
MARK="warnet-log-marker-$RANDOM-$$"
LOG_FAKE="$WORKDIR/rbitcoin-node-logmark"
printf '%s\n' '#!/bin/sh' "printf '%s\n' '$MARK'" 'exit 0' >"$LOG_FAKE"
chmod +x "$LOG_FAKE"
LOG_DD="$WORKDIR/log-on"
mkdir -p "$LOG_DD"
printf 'regtest=1\nport=18444\nrpcport=18443\n' >"$LOG_DD/bitcoin.conf"
LOG_OUT="$(RBITCOIN_NODE="$LOG_FAKE" RBITCOIN_LOG_STDOUT=1 "$SHIM" -datadir="$LOG_DD" -regtest 2>"$WORKDIR/log-on.err")" || true
if printf '%s\n' "$LOG_OUT" | grep -qx -- "$MARK" \
  && ! grep -q -- "$MARK" "$WORKDIR/log-on.err" \
  && grep -qx -- "$MARK" "$LOG_DD/regtest/debug.log"; then
  echo "ok - RBITCOIN_LOG_STDOUT=1 tees the node line to stdout and debug.log"
  PASS=$((PASS + 1))
else
  echo "not ok - log stdout on (out=$(printf %q "$LOG_OUT") err=$(cat "$WORKDIR/log-on.err") log=$(cat "$LOG_DD/regtest/debug.log" 2>/dev/null))"
  FAIL=$((FAIL + 1))
fi
LOG_DD2="$WORKDIR/log-off"
mkdir -p "$LOG_DD2"
printf 'regtest=1\nport=18444\nrpcport=18443\n' >"$LOG_DD2/bitcoin.conf"
LOG_OUT2="$(RBITCOIN_NODE="$LOG_FAKE" env -u RBITCOIN_LOG_STDOUT "$SHIM" -datadir="$LOG_DD2" -regtest 2>"$WORKDIR/log-off.err")" || true
if ! printf '%s\n' "$LOG_OUT2" | grep -q -- "$MARK" \
  && ! grep -q -- "$MARK" "$WORKDIR/log-off.err" \
  && grep -qx -- "$MARK" "$LOG_DD2/regtest/debug.log"; then
  echo "ok - log switch off keeps the node line in debug.log only"
  PASS=$((PASS + 1))
else
  echo "not ok - log stdout off (out=$(printf %q "$LOG_OUT2") err=$(cat "$WORKDIR/log-off.err") log=$(cat "$LOG_DD2/regtest/debug.log" 2>/dev/null))"
  FAIL=$((FAIL + 1))
fi

assert_fail_msg "port 65536 invalid" "Error: Invalid port specified in -port: '65536'" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -listen -port=65536
assert_fail_msg "port 0 invalid" "Error: Invalid port specified in -port: '0'" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -listen -port=0
assert_fail_msg "port +18444 invalid" "Error: Invalid port specified in -port: '+18444'" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -listen -port=+18444

# Onion-only -bind must not also take 0.0.0.0 (feature_bind_extra node0).
OUT_ONION="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -bind=127.0.0.1:18557=onion 2>/dev/null)" || OUT_ONION=""
if printf '%s' "$OUT_ONION" | grep -q -- "--listen 127.0.0.1:18557" \
  && ! printf '%s' "$OUT_ONION" | grep -q -- "--listen 0.0.0.0:"; then
  echo "ok - onion-only bind does not add 0.0.0.0"
  PASS=$((PASS + 1))
else
  echo "not ok - onion-only bind does not add 0.0.0.0 (got: $OUT_ONION)"
  FAIL=$((FAIL + 1))
fi

# Duplicate -bind / -whitebind on the same socket is Core InitError.
assert_fail_msg "duplicate bind InitError" "Error: Duplicate binding configuration" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -bind=127.0.0.1:11012 -bind=127.0.0.1:11012
assert_fail_msg "bind+whitebind same addr InitError" "Error: Duplicate binding configuration" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -bind=127.0.0.1:11012 -whitebind=noban@127.0.0.1:11012

assert_fail_msg "whitebind CIDR InitError" "Error: Cannot resolve -whitebind address" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -whitebind=noban@127.0.0.1/10
assert_fail_msg "whitebind missing port InitError" "Error: Need to specify a port with -whitebind" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -whitebind=noban@127.0.0.1
assert_fail_msg "listen=0 with bind InitError" "Error: Cannot set -bind or -whitebind together with -listen=0" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -whitebind=noban@127.0.0.1 -bind=127.0.0.1 -listen=0

# whitebind is a listen + bind grant (not a synthesized CIDR whitelist).
OUT_WB="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -whitebind=noban@127.0.0.1:18558 2>/dev/null)" || OUT_WB=""
if printf '%s' "$OUT_WB" | grep -q -- "--listen 127.0.0.1:18558" \
  && ! printf '%s' "$OUT_WB" | grep -q -- "--net-permission=noban@127.0.0.1" \
  && printf '%s' "$OUT_WB" | grep -q -- "--net-permission-bind=noban@127.0.0.1:18558"; then
  echo "ok - whitebind maps to listen+net-permission-bind"
  PASS=$((PASS + 1))
else
  echo "not ok - whitebind maps to listen+net-permission-bind (got: $OUT_WB)"
  FAIL=$((FAIL + 1))
fi

# Conf `whitebind=` (TestNode replace_in_config) must listen even when the
# leftover bind is onion-only (`p2p_permissions.py`).
WB_CONF="$WORKDIR/wb-conf"
mkdir -p "$WB_CONF"
cat >"$WB_CONF/bitcoin.conf" <<'EOF'
regtest=1
[regtest]
port=11001
rpcport=16001
whitebind=bloomfilter,forcerelay@127.0.0.1:11001
bind=127.0.0.1:21001=onion
EOF
OUT_WBC="$("$SHIM" --print-cmd -datadir="$WB_CONF" -regtest 2>/dev/null)" || OUT_WBC=""
if printf '%s' "$OUT_WBC" | grep -q -- "--listen 127.0.0.1:11001" \
  && printf '%s' "$OUT_WBC" | grep -q -- "--listen 127.0.0.1:21001" \
  && printf '%s' "$OUT_WBC" | grep -q -- "--net-permission-bind=bloomfilter,forcerelay@127.0.0.1:11001"; then
  echo "ok - conf whitebind+onion bind both listen"
  PASS=$((PASS + 1))
else
  echo "not ok - conf whitebind+onion bind both listen (got: $OUT_WBC)"
  FAIL=$((FAIL + 1))
fi

OUT_WR="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest \
  -whitelist=127.0.0.1 -whitelistrelay=0 2>/dev/null)" || OUT_WR=""
if printf '%s' "$OUT_WR" | grep -q -- "--net-permission=127.0.0.1" \
  && printf '%s' "$OUT_WR" | grep -q -- "--net-permission-relay=0"; then
  echo "ok - whitelistrelay maps to --net-permission-relay"
  PASS=$((PASS + 1))
else
  echo "not ok - whitelistrelay maps to --net-permission-relay (got: $OUT_WR)"
  FAIL=$((FAIL + 1))
fi

CONF_PORT="$WORKDIR/conf-port-bad"
mkdir -p "$CONF_PORT"
printf 'regtest=1\nport=nope\n' >"$CONF_PORT/bitcoin.conf"
assert_fail_msg "conf port garbage" "Error: Invalid port specified in -port: 'nope'" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$CONF_PORT" -regtest
printf 'regtest=1\nport=+18444\n' >"$CONF_PORT/bitcoin.conf"
assert_fail_msg "conf port +18444" "Error: Invalid port specified in -port: '+18444'" \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$CONF_PORT" -regtest

# InitError FULL_TEXT: production prints `Error: …` (`NodeError::Init`).
# the shim must emit Core's peertimeout needle. Fake node, no cargo.
FAKE_INIT="$WORKDIR/rbitcoin-node-initerr"
printf '%s\n' '#!/bin/sh' \
  'echo "Error: peer-timeout must be a positive integer."' \
  'exit 1' >"$FAKE_INIT"
chmod +x "$FAKE_INIT"
INIT_DD="$WORKDIR/initerr-peertimeout"
mkdir -p "$INIT_DD"
printf 'regtest=1\n' >"$INIT_DD/bitcoin.conf"
INIT_OUT=""
if INIT_OUT="$(RBITCOIN_NODE="$FAKE_INIT" "$SHIM" -datadir="$INIT_DD" -regtest 2>&1)"; then
  echo "not ok - peertimeout InitError maps to Core (expected failure)"
  FAIL=$((FAIL + 1))
elif printf '%s' "$INIT_OUT" | grep -q -- "Error: peertimeout must be a positive integer." \
  && ! printf '%s' "$INIT_OUT" | grep -q -- "configuration error"; then
  echo "ok - peertimeout InitError maps to Core"
  PASS=$((PASS + 1))
else
  echo "not ok - peertimeout InitError maps to Core (got: $INIT_OUT)"
  FAIL=$((FAIL + 1))
fi

# feature_filelock.py starts a second node with the live node's -datadir (same
# rpcport in bitcoin.conf, leftover .cookie). InitError must win over proxy bind.
FAKE_LOCK="$WORKDIR/rbitcoin-node-locked"
printf '%s\n' '#!/bin/sh' \
  'echo "Error: Cannot obtain a lock on directory /tmp/dd. rbitcoin is probably already running."' \
  'exit 1' >"$FAKE_LOCK"
chmod +x "$FAKE_LOCK"
LOCK_DD="$WORKDIR/filelock-rpcport"
mkdir -p "$LOCK_DD/regtest"
printf 'stale\n' >"$LOCK_DD/regtest/.cookie"
HOLD_PORT_FILE="$WORKDIR/hold.port"
python3 - "$HOLD_PORT_FILE" <<'PY' &
import socket, sys, time
path = sys.argv[1]
s = socket.socket()
s.bind(("127.0.0.1", 0))
open(path, "w").write(str(s.getsockname()[1]))
time.sleep(60)
PY
HOLD_PY=$!
HOLD_PORT=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if [ -s "$HOLD_PORT_FILE" ]; then
    HOLD_PORT="$(cat "$HOLD_PORT_FILE")"
    break
  fi
  sleep 0.05
done
if [ -z "$HOLD_PORT" ]; then
  echo "not ok - lock InitError before proxy bind (no hold port)"
  FAIL=$((FAIL + 1))
  kill "$HOLD_PY" 2>/dev/null || true
else
  printf 'regtest=1\nrpcport=%s\n' "$HOLD_PORT" >"$LOCK_DD/bitcoin.conf"
  LOCK_OUT=""
  if LOCK_OUT="$(RBITCOIN_NODE="$FAKE_LOCK" "$SHIM" -datadir="$LOCK_DD" -regtest -noserver 2>&1)"; then
    echo "not ok - lock InitError before proxy bind (expected failure)"
    FAIL=$((FAIL + 1))
  elif printf '%s' "$LOCK_OUT" | grep -q -- "Error: Cannot obtain a lock on directory /tmp/dd. Bitcoin Core is probably already running." \
    && ! printf '%s' "$LOCK_OUT" | grep -q -- "Address already in use"; then
    echo "ok - lock InitError before proxy bind"
    PASS=$((PASS + 1))
  else
    echo "not ok - lock InitError before proxy bind (got: $LOCK_OUT)"
    FAIL=$((FAIL + 1))
  fi
  kill "$HOLD_PY" 2>/dev/null || true
  wait "$HOLD_PY" 2>/dev/null || true
fi

WALLET_DD="$WORKDIR/filelock-wallet"
mkdir -p "$WALLET_DD"
printf 'regtest=1\n' >"$WALLET_DD/bitcoin.conf"
WALLET_OUT=""
if WALLET_OUT="$(RBITCOIN_NODE="$FAKE" "$SHIM" -datadir="$WALLET_DD" -regtest -noserver -wallet=abc 2>&1)"; then
  echo "not ok - wallet argv refused (expected failure)"
  FAIL=$((FAIL + 1))
elif printf '%s' "$WALLET_OUT" | grep -q -- "Error parsing command line arguments" \
  && ! printf '%s' "$WALLET_OUT" | grep -q -- "SQLiteDatabase"; then
  echo "ok - wallet argv is unknown (no SQLite lock lie)"
  PASS=$((PASS + 1))
else
  echo "not ok - wallet argv refused (got: $WALLET_OUT)"
  FAIL=$((FAIL + 1))
fi

ENV_DD="$WORKDIR/rpc-wait-idle"
mkdir -p "$ENV_DD"
printf 'regtest=1\n' >"$ENV_DD/bitcoin.conf"
ENV_FAKE="$WORKDIR/env-node"
ENV_OUT="$WORKDIR/child-env"
cat >"$ENV_FAKE" <<EOF
#!/bin/sh
env | grep -E 'RBITCOIN_RPC_WAIT_TIP_IDLE|RBITCOIN_RPC_PACKAGE_DIALECT' >"$ENV_OUT" || true
exit 0
EOF
chmod +x "$ENV_FAKE"
RBITCOIN_NODE="$ENV_FAKE" "$SHIM" -datadir="$ENV_DD" -regtest -noserver >/dev/null 2>&1 || true
if grep -q '^RBITCOIN_RPC_WAIT_TIP_IDLE=1$' "$ENV_OUT" 2>/dev/null; then
  echo "ok - shim sets RBITCOIN_RPC_WAIT_TIP_IDLE on the node"
  PASS=$((PASS + 1))
else
  echo "not ok - shim sets RBITCOIN_RPC_WAIT_TIP_IDLE (got: $([[ -f $ENV_OUT ]] && cat "$ENV_OUT" || echo missing))"
  FAIL=$((FAIL + 1))
fi
if grep -q '^RBITCOIN_RPC_PACKAGE_DIALECT=1$' "$ENV_OUT" 2>/dev/null; then
  echo "ok - shim sets RBITCOIN_RPC_PACKAGE_DIALECT on the node"
  PASS=$((PASS + 1))
else
  echo "not ok - shim sets RBITCOIN_RPC_PACKAGE_DIALECT (got: $([[ -f $ENV_OUT ]] && cat "$ENV_OUT" || echo missing))"
  FAIL=$((FAIL + 1))
fi

FAKE_MCW="$WORKDIR/rbitcoin-node-minchainwork"
printf '%s\n' '#!/bin/sh' \
  'echo "Error: Invalid minimum work specified (test), must be up to 64 hex digits"' \
  'exit 1' >"$FAKE_MCW"
chmod +x "$FAKE_MCW"
MCW_DD="$WORKDIR/initerr-minchainwork"
mkdir -p "$MCW_DD"
printf 'regtest=1\n' >"$MCW_DD/bitcoin.conf"
MCW_OUT=""
if MCW_OUT="$(RBITCOIN_NODE="$FAKE_MCW" "$SHIM" -datadir="$MCW_DD" -regtest 2>&1)"; then
  echo "not ok - minchainwork InitError maps to Core (expected failure)"
  FAIL=$((FAIL + 1))
elif printf '%s' "$MCW_OUT" | grep -q -- "Error: Invalid minimum work specified (test), must be up to 64 hex digits" \
  && ! printf '%s' "$MCW_OUT" | grep -q -- "configuration error"; then
  echo "ok - minchainwork InitError maps to Core"
  PASS=$((PASS + 1))
else
  echo "not ok - minchainwork InitError maps to Core (got: $MCW_OUT)"
  FAIL=$((FAIL + 1))
fi

# feature_port.py: Core-shaped Bound to lines in debug.log for -listen/-port.
PORT_DD="$WORKDIR/port-bound"
mkdir -p "$PORT_DD"
# FAKE exits immediately; Bound to is written before Popen.
if RBITCOIN_NODE="$FAKE" "$SHIM" -datadir="$PORT_DD" -regtest -listen -port=18666 >/dev/null 2>&1 \
  || true; then
  :
fi
LOG_BOUND="$PORT_DD/regtest/debug.log"
if [[ -f "$LOG_BOUND" ]] \
  && grep -q 'Bound to 0.0.0.0:18666' "$LOG_BOUND" \
  && grep -q 'Bound to 127.0.0.1:18667' "$LOG_BOUND"; then
  echo "ok - -listen -port emits Core Bound to dual-bind lines"
  PASS=$((PASS + 1))
else
  echo "not ok - -listen -port Bound to dual-bind (log: $([[ -f $LOG_BOUND ]] && cat "$LOG_BOUND" || echo missing))"
  FAIL=$((FAIL + 1))
fi

PORT_DD2="$WORKDIR/port-bind"
mkdir -p "$PORT_DD2"
RBITCOIN_NODE="$FAKE" "$SHIM" -datadir="$PORT_DD2" -regtest -listen -port=18666 -bind=0.0.0.0:18777 >/dev/null 2>&1 || true
LOG_BOUND2="$PORT_DD2/regtest/debug.log"
if [[ -f "$LOG_BOUND2" ]] \
  && grep -q 'Bound to 0.0.0.0:18777' "$LOG_BOUND2" \
  && ! grep -q 'Bound to 0.0.0.0:18666' "$LOG_BOUND2"; then
  echo "ok - -bind port wins Bound to over -port"
  PASS=$((PASS + 1))
else
  echo "not ok - -bind port wins Bound to (log: $([[ -f $LOG_BOUND2 ]] && cat "$LOG_BOUND2" || echo missing))"
  FAIL=$((FAIL + 1))
fi

SIGNET_DD="$WORKDIR/signet-magic"
mkdir -p "$SIGNET_DD"
printf 'signet=1\n' >"$SIGNET_DD/bitcoin.conf"
# --print-cmd returns before the shim writes debug.log. Start the fake node
# so the signet phrase is appended, then print the argv.
RBITCOIN_NODE="$FAKE" "$SHIM" -datadir="$SIGNET_DD" >/dev/null 2>&1 || true
OUT_SIGNET="$("$SHIM" --print-cmd -datadir="$SIGNET_DD" 2>/dev/null)"
LOG_SIGNET="$SIGNET_DD/signet/debug.log"
if printf '%s' "$OUT_SIGNET" | grep -q -- '--network signet' \
  && [[ -f "$LOG_SIGNET" ]] \
  && grep -q 'Signet derived magic (message start)' "$LOG_SIGNET"; then
  echo "ok - signet conf selects signet and logs derived magic"
  PASS=$((PASS + 1))
else
  echo "not ok - signet conf selects signet and logs derived magic (cmd: $OUT_SIGNET log: $([[ -f $LOG_SIGNET ]] && cat "$LOG_SIGNET" || echo missing))"
  FAIL=$((FAIL + 1))
fi

OUT_CHAL="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -signetchallenge=51 2>/dev/null)"
if printf '%s' "$OUT_CHAL" | grep -q -- '--signet-challenge=51'; then
  echo "ok - -signetchallenge=51 forwards"
  PASS=$((PASS + 1))
else
  echo "not ok - -signetchallenge=51 forwards (got: $OUT_CHAL)"
  FAIL=$((FAIL + 1))
fi

assert_fail_msg "-signetchallenge rejects non-hex" "Error: -signetchallenge must be hex, not 'abc'." \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -signetchallenge=abc
assert_fail_msg "-signetchallenge rejects duplicates" "Error: -signetchallenge cannot be multiple values." \
  env RBITCOIN_NODE="$FAKE" "$SHIM" --print-cmd -datadir="$DATADIR" -regtest -signetchallenge=51 -signetchallenge=51

OUT_BF="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -blockfilterindex 2>/dev/null)"
OUT_BF0="$("$SHIM" --print-cmd -datadir="$DATADIR" -regtest -blockfilterindex=0 2>/dev/null)"
if printf '%s' "$OUT_BF" | grep -q -- '--block-filter-index' \
  && printf '%s' "$OUT_BF0" | grep -q -- '--block-filter-index=0'; then
  echo "ok - -blockfilterindex maps to --block-filter-index"
  PASS=$((PASS + 1))
else
  echo "not ok - -blockfilterindex maps (bare: $OUT_BF zero: $OUT_BF0)"
  FAIL=$((FAIL + 1))
fi

# Concurrent readers must never observe a cookie line without ':'.
# Path.write_text truncates first; Core get_auth_cookie then IndexErrors.
COOKIE_RACE="$WORKDIR/cookie-race"
mkdir -p "$COOKIE_RACE"
if python3 - "$SHIM" "$COOKIE_RACE/.cookie" <<'PY'
import importlib.machinery
import importlib.util
import sys
import threading
from pathlib import Path

shim, dest = sys.argv[1], Path(sys.argv[2])
sys.path.insert(0, str(Path(shim).resolve().parent))
loader = importlib.machinery.SourceFileLoader("cf_bitcoind", shim)
spec = importlib.util.spec_from_loader("cf_bitcoind", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
bad = []
stop = False

def reader():
    while not stop:
        try:
            text = dest.read_text()
        except OSError:
            continue
        if ":" not in text:
            bad.append(repr(text))
            return

threads = [threading.Thread(target=reader) for _ in range(4)]
for t in threads:
    t.start()
for i in range(2000):
    mod.publish_cookie_file(dest, f"__cookie__:tok{i}\n")
stop = True
for t in threads:
    t.join()
if bad:
    print("torn", bad[:3])
    sys.exit(1)
text = dest.read_text()
if text != "__cookie__:tok1999\n":
    print("final", repr(text))
    sys.exit(1)
PY
then
  echo "ok - cookie publish is never a torn line"
  PASS=$((PASS + 1))
else
  echo "not ok - cookie publish is never a torn line"
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
