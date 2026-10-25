#!/usr/bin/env bash
# Model-checked concurrency for rbitcoin-store (`--test model`). loom explores
# every interleaving of small ArrayTable scenarios; shuttle runs seeded PCT
# and random schedules on larger ones. The engine is a `--cfg`, not a feature,
# so each engine builds in its own target dir (TESTING.md Artifact silos).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

engine="${1:-}"
case "$engine" in
  loom | shuttle) shift ;;
  *)
    echo "usage: $0 <loom|shuttle> [extra cargo test args...]" >&2
    exit 2
    ;;
esac

RUSTFLAGS="${RUSTFLAGS:-} --cfg $engine"
export RUSTFLAGS="${RUSTFLAGS# }"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR_MODEL:-$ROOT/target/model-$engine}"
cmd=(cargo test -p rbitcoin-store --test model "$@")

exec "${cmd[@]}"
