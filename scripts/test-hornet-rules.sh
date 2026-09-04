#!/usr/bin/env bash
# Run the consensus pins that cover Hornet spec.h / spec.html H01–S09.
# The tests themselves live in the existing structure / header / connect
# suites — this is only a selector.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found; enter nix-shell first" >&2
  exit 1
fi

echo "== structure, header, finality, sigops =="
cargo test -p rbitcoin-consensus --lib -- \
  structure_rule_tests \
  sigop_cost_tests \
  finality_tests \
  median_time_past_tests \
  assemble_second_block_rejects_stale_nversion

echo "== connect / header journey =="
cargo test -p rbitcoin-test --test consensus_rules

echo "hornet-mapped pins OK"
