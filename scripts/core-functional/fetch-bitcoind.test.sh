#!/usr/bin/env bash
# Contract: fetch-bitcoind.sh verifies sha256, extracts only bin/bitcoind, cache-hits.
# No network: file:// fixture tarball.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FETCH="$ROOT/scripts/core-functional/fetch-bitcoind.sh"
PASS=0
FAIL=0

assert_ok() {
  local name="$1"
  shift
  if "$@"; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name"
    FAIL=$((FAIL + 1))
  fi
}

assert_fail() {
  local name="$1"
  shift
  if "$@"; then
    echo "not ok - $name (expected failure)"
    FAIL=$((FAIL + 1))
  else
    echo "ok - $name"
    PASS=$((PASS + 1))
  fi
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-fetch-bitcoind.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

mkdir -p "$WORKDIR/tree/bitcoin-31.1/bin"
printf '#!/bin/sh\necho stub-bitcoind\n' >"$WORKDIR/tree/bitcoin-31.1/bin/bitcoind"
chmod +x "$WORKDIR/tree/bitcoin-31.1/bin/bitcoind"
tar -C "$WORKDIR/tree" -czf "$WORKDIR/bitcoin-31.1-x86_64-linux-gnu.tar.gz" bitcoin-31.1/bin/bitcoind
good_sha="$(sha256sum "$WORKDIR/bitcoin-31.1-x86_64-linux-gnu.tar.gz" | awk '{print $1}')"

cat >"$WORKDIR/inv.toml" <<EOF
pin = "v31.1"
core_commit = "9be056a8a72b624dae9623b2f7bded92c2a21c91"

[release]
base_url = "file://$WORKDIR"

[[release.linux]]
arch = "x86_64-linux-gnu"
tarball = "bitcoin-31.1-x86_64-linux-gnu.tar.gz"
sha256 = "$good_sha"
EOF

export FETCH_BITCOIND_INVENTORY="$WORKDIR/inv.toml"
export FETCH_BITCOIND_ARCH="x86_64-linux-gnu"
export FETCH_BITCOIND_CACHE="$WORKDIR/cache"
export FETCH_BITCOIND_BASE_URL="file://$WORKDIR"

got="$("$FETCH")"
assert_ok "stdout is extracted bitcoind" test -x "$got"
assert_ok "path under cache" grep -q "/v31.1/x86_64-linux-gnu/bin/bitcoind" <<<"$got"
assert_ok "stub content" grep -q stub-bitcoind "$got"
# Only bitcoind, not a full tree dump
assert_ok "only bin/bitcoind extracted" test ! -e "$WORKDIR/cache/v31.1/x86_64-linux-gnu/bitcoin-31.1"

got2="$("$FETCH")"
assert_ok "cache hit same path" test "$got2" = "$got"

# Wrong sha256: no leftover binary.
export FETCH_BITCOIND_CACHE="$WORKDIR/cache-bad"
cat >"$WORKDIR/inv-bad.toml" <<EOF
pin = "v31.1"
core_commit = "9be056a8a72b624dae9623b2f7bded92c2a21c91"

[release]
base_url = "file://$WORKDIR"

[[release.linux]]
arch = "x86_64-linux-gnu"
tarball = "bitcoin-31.1-x86_64-linux-gnu.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
EOF
export FETCH_BITCOIND_INVENTORY="$WORKDIR/inv-bad.toml"
assert_fail "mismatch exits non-zero" "$FETCH"
assert_ok "mismatch leaves no bitcoind" test ! -e "$WORKDIR/cache-bad/v31.1/x86_64-linux-gnu/bin/bitcoind"

export FETCH_BITCOIND_INVENTORY="$WORKDIR/inv.toml"
export FETCH_BITCOIND_ARCH="darwin-aarch64"
assert_fail "non-linux refused" "$FETCH"

if [[ "$FAIL" -ne 0 ]]; then
  echo "fetch-bitcoind.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "fetch-bitcoind.test.sh: $PASS passed"
