#!/usr/bin/env bash
# Re-vendor libsecp256k1 with the batch verification module (upstream PR
# bitcoin-core/secp256k1#1134, not yet merged) into depend/secp256k1.
#
# Usage: ./vendor-libsecp.sh [REV]
#
# Every exported symbol is renamed from `secp256k1_` to `rbtc_secp256k1_` so
# this copy links next to rust-bitcoin's secp256k1-sys (which uses its own
# `rustsecp256k1_v*_` prefix) without clashes.
set -euo pipefail

REPO=https://github.com/siv2r/secp256k1
REV=${1:-0696ea8084015e7d5420d7f1feb37d2b2e5993de}
HERE=$(cd "$(dirname "$0")" && pwd)
DEST="$HERE/depend/secp256k1"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL "$REPO/archive/$REV.tar.gz" | tar -xz -C "$work"
src="$work/secp256k1-$REV"

rm -rf "$DEST"
mkdir -p "$DEST/src/modules"
cp "$src/COPYING" "$DEST/"
cp -r "$src/include" "$DEST/"
cp "$src"/src/*.h "$DEST/src/"
cp "$src/src/secp256k1.c" "$src/src/precomputed_ecmult.c" \
  "$src/src/precomputed_ecmult_gen.c" "$DEST/src/"
for m in batch extrakeys schnorrsig; do
  mkdir -p "$DEST/src/modules/$m"
  cp "$src/src/modules/$m"/main_impl.h "$DEST/src/modules/$m/"
  if [ -f "$src/src/modules/$m/batch_add_impl.h" ]; then
    cp "$src/src/modules/$m/batch_add_impl.h" "$DEST/src/modules/$m/"
  fi
done
# Test, bench, and table-generator headers are not part of the library.
rm -f "$DEST"/src/{bench,testrand,testrand_impl,testutil,tests_common,unit_test}.h
rm -f "$DEST"/src/{ecmult_compute_table,ecmult_compute_table_impl}.h
rm -f "$DEST"/src/{ecmult_gen_compute_table,ecmult_gen_compute_table_impl}.h
# Headers of modules this build does not enable.
rm -f "$DEST"/include/secp256k1_{ecdh,ellswift,musig,recovery}.h

find "$DEST" \( -name '*.c' -o -name '*.h' \) -print0 |
  xargs -0 sed -i '/^#include/! s/secp256k1_/rbtc_secp256k1_/g'

echo "$REV" >"$DEST/../secp256k1-HEAD-revision.txt"
