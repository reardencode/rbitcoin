#!/usr/bin/env bash
# The checker must accept a consistent fixture and reject a drifted line.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$ROOT/scripts/btc-lean-census.py" --self-test
