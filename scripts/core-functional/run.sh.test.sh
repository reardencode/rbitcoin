#!/usr/bin/env bash
# Contract pin for run.sh (no node, no cargo). Skip names cannot run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="$ROOT/scripts/core-functional/run.sh"
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

assert_stdout() {
  local name="$1"
  local needle="$2"
  shift 2
  local out
  if ! out="$("$@" 2>/dev/null)"; then
    echo "not ok - $name (unexpected failure)"
    FAIL=$((FAIL + 1))
    return
  fi
  if printf '%s' "$out" | grep -q -- "$needle"; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name (missing '$needle' in stdout: $out)"
    FAIL=$((FAIL + 1))
  fi
}

assert_stdout_empty_names() {
  local name="$1"
  shift
  local out
  if ! out="$("$@" 2>/dev/null)"; then
    echo "not ok - $name (unexpected failure)"
    FAIL=$((FAIL + 1))
    return
  fi
  if [[ -z "${out//$'\n'/}" ]]; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name (expected empty --list, got: $out)"
    FAIL=$((FAIL + 1))
  fi
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-cf-run.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

TESTS="$WORKDIR/tests"
mkdir -p "$TESTS"
printf '# fake\n' >"$TESTS/feature_help.py"
printf '# fake\n' >"$TESTS/wallet_basic.py"
printf '# fake\n' >"$TESTS/p2p_ping.py"

INV="$WORKDIR/inv.toml"
cat >"$INV" <<'EOF'
pin = "v31.1"
core_commit = "9be056a8a72b624dae9623b2f7bded92c2a21c91"

[[test]]
name = "feature_help.py"
status = "run"

[[test]]
name = "wallet_basic.py"
status = "skip"
reason = "no-wallet"

[[test]]
name = "p2p_ping.py"
status = "skip"
reason = "rpc-missing"
analog = "none"
EOF

# --- skip cannot be invoked ---
assert_fail_msg "skip name refused" "not in run set: wallet_basic.py" \
  "$RUN" --inventory "$INV" --tests-dir "$TESTS" wallet_basic.py

# --- unknown file ---
assert_fail_msg "unknown name refused" "unknown test: rpc_ghost.py" \
  "$RUN" --inventory "$INV" --tests-dir "$TESTS" rpc_ghost.py

# --- --list is run names only ---
assert_stdout "list includes run" "feature_help.py" \
  "$RUN" --list --inventory "$INV" --tests-dir "$TESTS"
LIST_OUT="$("$RUN" --list --inventory "$INV" --tests-dir "$TESTS" 2>/dev/null || true)"
if printf '%s' "$LIST_OUT" | grep -q 'wallet_basic.py'; then
  echo "not ok - list excludes skip (found wallet_basic.py)"
  FAIL=$((FAIL + 1))
else
  echo "ok - list excludes skip"
  PASS=$((PASS + 1))
fi

# --- p2p_timeouts has v1+v2 ALL_SCRIPTS twins; pass v2 only ---
TESTS2="$WORKDIR/tests2"
mkdir -p "$TESTS2"
printf '# fake\n' >"$TESTS2/p2p_timeouts.py"
INV2="$WORKDIR/inv2.toml"
cat >"$INV2" <<'EOF'
pin = "v31.1"
core_commit = "9be056a8a72b624dae9623b2f7bded92c2a21c91"

[[test]]
name = "p2p_timeouts.py"
status = "run"
EOF
DRY_TWIN="$("$RUN" --dry-run --inventory "$INV2" --tests-dir "$TESTS2" \
  --config-out "$WORKDIR/config-twin.ini" p2p_timeouts.py 2>/dev/null || true)"
if [[ "$DRY_TWIN" == *p2p_timeouts.py*v2transport* && "$DRY_TWIN" != *v1transport* ]]; then
  echo "ok - p2p_timeouts dry-run is v2 twin only"
  PASS=$((PASS + 1))
else
  echo "not ok - p2p_timeouts dry-run is v2 twin only (got: $DRY_TWIN)"
  FAIL=$((FAIL + 1))
fi

# --- dry-run of a run name: v2transport + name ---
DRY_OUT="$("$RUN" --dry-run --inventory "$INV" --tests-dir "$TESTS" \
  --config-out "$WORKDIR/config.ini" feature_help.py 2>/dev/null || true)"
if printf '%s' "$DRY_OUT" | grep -q -- '--v2transport' \
  && printf '%s' "$DRY_OUT" | grep -q -- '--jobs' \
  && printf '%s' "$DRY_OUT" | grep -q -- '--keepcache' \
  && printf '%s' "$DRY_OUT" | grep -q 'feature_help.py'; then
  echo "ok - dry-run run name"
  PASS=$((PASS + 1))
else
  echo "not ok - dry-run run name (got: $DRY_OUT)"
  FAIL=$((FAIL + 1))
fi

# --- dry-run writes config.ini with wallet on (shim) / bitcoind on ---
if [[ -f "$WORKDIR/config.ini" ]] \
  && grep -q 'ENABLE_WALLET=true' "$WORKDIR/config.ini" \
  && grep -q 'ENABLE_BITCOIND=true' "$WORKDIR/config.ini" \
  && grep -q 'ENABLE_ZMQ=false' "$WORKDIR/config.ini" \
  && grep -q 'ENABLE_IPC=false' "$WORKDIR/config.ini"; then
  echo "ok - config.ini template fields"
  PASS=$((PASS + 1))
else
  echo "not ok - config.ini template fields"
  FAIL=$((FAIL + 1))
fi

# --- dry-run of a run name does not pass skip names to the runner ---
if printf '%s' "$DRY_OUT" | grep -q 'wallet_basic.py'; then
  echo "not ok - dry-run leaked skip name (got: $DRY_OUT)"
  FAIL=$((FAIL + 1))
else
  echo "ok - dry-run does not leak skip names"
  PASS=$((PASS + 1))
fi

# --- real inventory: first-green run set ---
assert_stdout "real inventory --list includes feature_help" "feature_help.py" \
  "$RUN" --list
assert_stdout "real inventory --list includes feature_uacomment" "feature_uacomment.py" \
  "$RUN" --list
assert_stdout "real inventory --list includes rpc_uptime" "rpc_uptime.py" \
  "$RUN" --list
assert_stdout "real inventory --list includes rpc_named_arguments" "rpc_named_arguments.py" \
  "$RUN" --list
assert_stdout "real inventory --list includes mempool_spend_coinbase" "mempool_spend_coinbase.py" \
  "$RUN" --list
assert_stdout "real inventory --list includes mempool_resurrect" "mempool_resurrect.py" \
  "$RUN" --list
assert_stdout "real inventory --list includes p2p_block_sync" "p2p_block_sync.py" \
  "$RUN" --list
assert_stdout "real inventory --list includes feature_framework_miniwallet" "feature_framework_miniwallet.py" \
  "$RUN" --list
assert_stdout "real inventory --list includes feature_dirsymlinks" "feature_dirsymlinks.py" \
  "$RUN" --list
assert_fail_msg "real inventory skip refused" "not in run set: wallet_basic.py" \
  "$RUN" --dry-run wallet_basic.py
DRY_REAL="$("$RUN" --dry-run 2>/dev/null || true)"
if printf '%s' "$DRY_REAL" | grep -q 'feature_help.py' \
  && printf '%s' "$DRY_REAL" | grep -q 'feature_uacomment.py' \
  && printf '%s' "$DRY_REAL" | grep -q 'rpc_uptime.py' \
  && printf '%s' "$DRY_REAL" | grep -q 'rpc_named_arguments.py' \
  && printf '%s' "$DRY_REAL" | grep -q 'mempool_spend_coinbase.py' \
  && printf '%s' "$DRY_REAL" | grep -q 'p2p_block_sync.py' \
  && printf '%s' "$DRY_REAL" | grep -q -- '--v2transport' \
  && printf '%s' "$DRY_REAL" | grep -q -- '--keepcache'; then
  echo "ok - real inventory dry-run first-green set"
  PASS=$((PASS + 1))
else
  echo "not ok - real inventory dry-run first-green set (got: $DRY_REAL)"
  FAIL=$((FAIL + 1))
fi

echo
echo "$PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
