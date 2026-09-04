#!/usr/bin/env bash
# Contract pin for release_pin.py (no network).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PIN="$ROOT/scripts/core-functional/release_pin.py"
PASS=0
FAIL=0

assert_ok_msg() {
  local name="$1"
  local needle="$2"
  shift 2
  local out
  if ! out="$("$@" 2>&1)"; then
    echo "not ok - $name (unexpected failure: $out)"
    FAIL=$((FAIL + 1))
    return
  fi
  if printf '%s' "$out" | grep -Fq -- "$needle"; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name (missing '$needle' in: $out)"
    FAIL=$((FAIL + 1))
  fi
}

assert_fail_msg() {
  local name="$1"
  local needle="$2"
  shift 2
  local out
  if out="$("$@" 2>&1)"; then
    echo "not ok - $name (expected failure: $out)"
    FAIL=$((FAIL + 1))
    return
  fi
  if printf '%s' "$out" | grep -Fq -- "$needle"; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name (missing '$needle' in: $out)"
    FAIL=$((FAIL + 1))
  fi
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-rel-pin.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

INV="$WORKDIR/inv.toml"
cat >"$INV" <<'EOF'
pin = "v31.1"
core_commit = "9be056a8a72b624dae9623b2f7bded92c2a21c91"

[release]
base_url = "https://bitcoincore.org/bin/bitcoin-core-31.1"

[[release.linux]]
arch = "x86_64-linux-gnu"
tarball = "bitcoin-31.1-x86_64-linux-gnu.tar.gz"
sha256 = "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"

[[release.linux]]
arch = "aarch64-linux-gnu"
tarball = "bitcoin-31.1-aarch64-linux-gnu.tar.gz"
sha256 = "dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004"
EOF

assert_ok_msg "x86_64 sha256" "sha256=b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e" \
  python3 "$PIN" --inventory "$INV" --arch x86_64-linux-gnu
assert_ok_msg "x86_64 url" "url=https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz" \
  python3 "$PIN" --inventory "$INV" --arch x86_64-linux-gnu
assert_ok_msg "x86_64 inner" "inner=bitcoin-31.1/bin/bitcoind" \
  python3 "$PIN" --inventory "$INV" --arch x86_64-linux-gnu

assert_ok_msg "aarch64 sha256" "sha256=dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004" \
  python3 "$PIN" --inventory "$INV" --arch aarch64-linux-gnu

assert_fail_msg "darwin refuse" "unsupported arch" \
  python3 "$PIN" --inventory "$INV" --arch darwin-aarch64

cat >"$WORKDIR/empty.toml" <<'EOF'
pin = "v31.1"
EOF
assert_fail_msg "missing table" "missing [release]" \
  python3 "$PIN" --inventory "$WORKDIR/empty.toml"

REAL="$ROOT/scripts/core-functional/inventory.toml"
assert_ok_msg "real inventory x86_64" "sha256=b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e" \
  python3 "$PIN" --inventory "$REAL" --arch x86_64-linux-gnu

if [[ "$FAIL" -ne 0 ]]; then
  echo "release_pin.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "release_pin.test.sh: $PASS passed"
