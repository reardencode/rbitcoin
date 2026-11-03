#!/usr/bin/env bash
# Shallow, sparse checkout of bitcoin/bitcoin @ the inventory pin (v32.1).
# cargo test stages script_tests.json / tx_*.json from src/test/data each run.
#
# A git checkout already at PIN_SHA, with the corpus files and the functional
# runner, is reused. That path does not fetch. CI caches this directory; the
# cache key is a hash of this file, so a pin bump misses and clones once.
#
# Optional dest is the self-test. Callers use the default submodule path.
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [dest]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="${1:-${ROOT}/third_party/bitcoin}"
PIN_SHA="f0de87f040621468b956f01f526a43a010310501"
URL="https://github.com/bitcoin/bitcoin.git"

# Corpus names stage_core_json reads, plus the functional runner core-functional
# and warnet invoke. A tree missing one of these is not "already the pin".
need_files=(
  src/test/data/script_tests.json
  src/test/data/tx_valid.json
  src/test/data/tx_invalid.json
  src/test/data/sighash.json
  src/test/data/bip341_wallet_vectors.json
  test/functional/test_runner.py
  test/functional/test_framework/__init__.py
)

have_files() {
  local rel
  for rel in "${need_files[@]}"; do
    [[ -f "${DEST}/${rel}" ]] || return 1
  done
}

# cargo test may stage fixtures from several processes at once.
mkdir -p "$(dirname "$DEST")"
exec 9>"$(dirname "$DEST")/.init-bitcoin.lock"
flock 9

# Local object only. A missing pin falls through to fetch or clone.
# checkout resets a dirty fixture file without sparsifying a full tree.
if [[ -e "${DEST}/.git" || -f "${DEST}/.git" ]]; then
  if git -C "$DEST" checkout -f -q "$PIN_SHA" 2>/dev/null && have_files; then
    got="$(git -C "$DEST" rev-parse HEAD)"
    if [[ "$got" == "$PIN_SHA" ]]; then
      echo "init-submodule: ok $got (v32.1) at $DEST"
      exit 0
    fi
  fi
fi

if [[ ! -e "${DEST}/.git" && ! -f "${DEST}/.git" ]]; then
  git clone --filter=blob:none --sparse --depth 1 --no-checkout "$URL" "$DEST"
  git -C "$DEST" fetch --depth 1 origin tag v32.1
  git -C "$DEST" sparse-checkout set src/test/data test
  git -C "$DEST" checkout "$PIN_SHA"
else
  git -C "$DEST" fetch --depth 1 origin tag v32.1
  git -C "$DEST" sparse-checkout set src/test/data test 2>/dev/null || true
  git -C "$DEST" checkout "$PIN_SHA"
fi

got="$(git -C "$DEST" rev-parse HEAD)"
if [[ "$got" != "$PIN_SHA" ]]; then
  echo "init-submodule: expected $PIN_SHA got $got" >&2
  exit 1
fi
echo "init-submodule: ok $got (v32.1) at $DEST"
