#!/usr/bin/env bash
# Run inventory `run` tests via Core test_runner.py. Skip names cannot be invoked
# (select_tests.py --require-run). We pass an explicit name list — do not
# --exclude every skip; Core fail_on_warn exits if an exclude is not in the
# current test list.
#
# Default cargo test never calls this. No node for --list / --dry-run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
INVENTORY="$HERE/inventory.toml"
TESTS_DIR="${ROOT}/third_party/bitcoin/test/functional"
CONFIG_OUT=""
LIST=0
DRY=0
NAMES=()

usage() {
  echo "usage: $0 [--list] [--dry-run] [--inventory FILE] [--tests-dir DIR] [--config-out FILE] [test.py…]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) LIST=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --inventory)
      [[ $# -ge 2 ]] || usage
      INVENTORY="$2"
      shift 2
      ;;
    --tests-dir)
      [[ $# -ge 2 ]] || usage
      TESTS_DIR="$2"
      shift 2
      ;;
    --config-out)
      [[ $# -ge 2 ]] || usage
      CONFIG_OUT="$2"
      shift 2
      ;;
    -h | --help) usage ;;
    --) shift; NAMES+=("$@"); break ;;
    -*) usage ;;
    *) NAMES+=("$1"); shift ;;
  esac
done

CHECK=(python3 "$HERE/check_inventory.py" --inventory "$INVENTORY")
if [[ -d "$TESTS_DIR" ]]; then
  CHECK+=(--tests-dir "$TESTS_DIR")
fi
# Diagnostics on stderr so --list stdout is names only.
"${CHECK[@]}" >&2

mapfile -t RUN_NAMES < <(python3 "$HERE/select_tests.py" --inventory "$INVENTORY" --print-run)

if [[ "$LIST" -eq 1 ]]; then
  if [[ ${#RUN_NAMES[@]} -gt 0 ]]; then
    printf '%s\n' "${RUN_NAMES[@]}"
  fi
  exit 0
fi

if [[ ${#NAMES[@]} -gt 0 ]]; then
  python3 "$HERE/select_tests.py" --inventory "$INVENTORY" --require-run "${NAMES[@]}"
  SELECTED=("${NAMES[@]}")
else
  SELECTED=("${RUN_NAMES[@]+"${RUN_NAMES[@]}"}")
fi

# Normalize to basenames with .py for the runner.
# Core ALL_SCRIPTS lists some names as `foo.py --v1transport` and
# `foo.py --v2transport`. test_runner startswith-matches `foo.py` to both.
# We are BIP324 v2-only: pass the v2 token when the basename is one of those.
V2_ONLY_TWIN=(p2p_timeouts.py)
NORM=()
for n in "${SELECTED[@]+"${SELECTED[@]}"}"; do
  base="$(basename "$n")"
  if [[ "$base" != *.py ]]; then
    base="${base}.py"
  fi
  twin=0
  for t in "${V2_ONLY_TWIN[@]}"; do
    if [[ "$base" == "$t" ]]; then
      NORM+=("$base --v2transport")
      twin=1
      break
    fi
  done
  if [[ "$twin" -eq 0 ]]; then
    NORM+=("$base")
  fi
done

if [[ ${#NORM[@]} -eq 0 ]]; then
  echo "0 run tests"
  exit 0
fi

# test_runner joins BUILDDIR/test/functional. Both dirs are the Core tree.
if [[ -d "$TESTS_DIR/../.." ]]; then
  CORE_SRC="$(cd "$TESTS_DIR/../.." && pwd)"
else
  CORE_SRC="$(dirname "$(dirname "$TESTS_DIR")")"
fi
if [[ -z "$CONFIG_OUT" ]]; then
  CONFIG_OUT="${TESTS_DIR}/../config.ini"
fi

mkdir -p "$(dirname "$CONFIG_OUT")"
sed \
  -e "s|@SRCDIR@|${CORE_SRC}|g" \
  -e "s|@BUILDDIR@|${CORE_SRC}|g" \
  -e "s|@RPCAUTH@|${HERE}/rpcauth.py|g" \
  "$HERE/config.ini.template" >"$CONFIG_OUT"

SHIM="${HERE}/bitcoind"
# Dummy Core cache dirs so `_initialize_chain` does not remine 199 then
# delete our store. Real blocks live in RBITCOIN_CACHE (our store/).
# --keepcache: test_runner would otherwise rmtree BUILDDIR/test/cache.
# --jobs 1: Core create_cache.py only runs when jobs>1; we still skip it.
export RBITCOIN_CACHE="${RBITCOIN_CACHE:-$HERE/cache}"
if [[ -f "${TESTS_DIR}/test_runner.py" ]]; then
  python3 "$HERE/create_cache.py" --preseed-core "$CORE_SRC"
fi
CMD=(
  python3 "${TESTS_DIR}/test_runner.py"
  --v2transport
  --jobs
  1
  --keepcache
  "${NORM[@]}"
)

if [[ "$DRY" -eq 1 ]]; then
  printf '%q ' "${CMD[@]}"
  printf '\n'
  exit 0
fi

if [[ ! -f "${TESTS_DIR}/test_runner.py" ]]; then
  echo "missing ${TESTS_DIR}/test_runner.py (run ./scripts/core-functional/init-submodule.sh)" >&2
  exit 1
fi

if [[ ! -d "${RBITCOIN_CACHE}/store" ]]; then
  python3 "$HERE/create_cache.py" --cache "$RBITCOIN_CACHE" --ensure
fi

export BITCOIND="$SHIM"
export BITCOINCLI="${HERE}/bitcoin-cli"
exec "${CMD[@]}"
