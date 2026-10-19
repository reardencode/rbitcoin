#!/usr/bin/env bash
# Fail when a mapped btc-lean census id, its // btc-lean: comment, or the
# cited line disagree. Does not need the third_party/btc-lean checkout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/scripts/btc-lean-census.py" --root "$ROOT"
