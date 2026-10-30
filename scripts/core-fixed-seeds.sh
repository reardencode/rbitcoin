#!/usr/bin/env bash
# Refresh crates/rbitcoin-net/seeds/nodes_{main,test,signet}.txt from Bitcoin
# Core's contrib/seeds at COMMIT. Core's generate-seeds.py builds
# src/chainparamsseeds.h from these same files. rbitcoin has no testnet4.
# The DNS seed list is hand-copied from src/kernel/chainparams.cpp into
# dns_seeds() in crates/rbitcoin-net/src/seeds.rs.
# Usage: scripts/core-fixed-seeds.sh COMMIT   (40-hex bitcoin/bitcoin commit)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/crates/rbitcoin-net/seeds"
commit="${1:-}"
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 COMMIT  (full 40-hex bitcoin/bitcoin commit)" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$OUT"
for net in main test signet; do
  src="contrib/seeds/nodes_$net.txt"
  curl -fsSL --proto '=https' \
    "https://raw.githubusercontent.com/bitcoin/bitcoin/$commit/$src" -o "$tmp/nodes_$net.txt"
  {
    printf '# bitcoin/bitcoin %s %s\n' "$commit" "$src"
    cat "$tmp/nodes_$net.txt"
  } >"$OUT/nodes_$net.txt"
  echo "$OUT/nodes_$net.txt: $(grep -cv '^#' "$OUT/nodes_$net.txt") lines"
done
