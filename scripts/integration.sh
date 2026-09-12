#!/usr/bin/env bash
# Periodic multi-node P2P integration suite (heavier than default unit scenarios).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo >/dev/null; then
  echo "enter nix-shell first" >&2
  exit 1
fi

echo "== multi-node (default + ignored IBD topology) =="
cargo test -p rbitcoin-test --test integration_multinode -- --nocapture
cargo test -p rbitcoin-test --test integration_multinode -- --ignored --nocapture

echo "== IBD smoke (cancel / follow_from / unreachable) =="
cargo test -p rbitcoin-net --test ibd_smoke -- --nocapture

echo "integration suite OK"
