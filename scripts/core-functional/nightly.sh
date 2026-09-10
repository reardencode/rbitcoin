#!/usr/bin/env bash
# Nightly / labeled-PR Core functional gate.
#
# Warns (does not fail) when a newer Bitcoin Core *release* exists than the
# inventory pin — bump the submodule, fixtures, and inventory when that fires.
# Default cargo test never calls this.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

./scripts/core-functional/init-submodule.sh
"$HERE/bitcoind.test.sh"
"$HERE/map_debuglog_test.sh"
"$HERE/rpc_util_validateaddress.test.sh"
"$HERE/check_inventory_test.sh"
python3 "$HERE/check_inventory.py" \
  --tests-dir "$ROOT/third_party/bitcoin/test/functional"
# Warn-only: a newer Core release must not red the job.
python3 "$HERE/check_core_release.py"
# Inventory `run` set (help / uacomment / uptime / named_arguments). Needs a node.
abs_node() {
  local p="$1"
  if [[ "$p" = /* ]]; then
    printf '%s' "$p"
  else
    printf '%s' "$ROOT/$p"
  fi
}

if [[ -n "${RBITCOIN_NODE:-}" && -x "$(abs_node "$RBITCOIN_NODE")" ]]; then
  export RBITCOIN_NODE="$(abs_node "$RBITCOIN_NODE")"
elif command -v cargo >/dev/null 2>&1; then
  cargo build -p rbitcoin-node
  CAND=""
  if [[ -n "${CARGO_TARGET_DIR:-}" && -x "${CARGO_TARGET_DIR}/debug/rbitcoin-node" ]]; then
    CAND="${CARGO_TARGET_DIR}/debug/rbitcoin-node"
  elif [[ -x "$ROOT/target/debug/rbitcoin-node" ]]; then
    CAND="$ROOT/target/debug/rbitcoin-node"
  elif [[ -x "$ROOT/target/dev/debug/rbitcoin-node" ]]; then
    CAND="$ROOT/target/dev/debug/rbitcoin-node"
  fi
  if [[ -n "$CAND" ]]; then
    export RBITCOIN_NODE="$(abs_node "$CAND")"
  fi
fi
if [[ -n "${RBITCOIN_NODE:-}" && -x "${RBITCOIN_NODE}" ]]; then
  "$HERE/run.sh"
else
  echo "core-functional nightly: no rbitcoin-node; --list only" >&2
  "$HERE/run.sh" --list
fi
echo "core-functional nightly: inventory + release-pin check done"
