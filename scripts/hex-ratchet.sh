#!/usr/bin/env bash
# Production hex-literal ceiling. See lint/hex-baseline.txt.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/hex-ratchet.py" "$@"
