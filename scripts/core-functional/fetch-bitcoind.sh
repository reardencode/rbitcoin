#!/usr/bin/env bash
# Download official bitcoind for the inventory [release] pin. SHA256 fail-closed.
# stdout: absolute path to bitcoind. stderr: progress / errors.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PIN_PY="$ROOT/scripts/core-functional/release_pin.py"
INV="${FETCH_BITCOIND_INVENTORY:-$ROOT/scripts/core-functional/inventory.toml}"

arch_args=()
if [[ -n "${FETCH_BITCOIND_ARCH:-}" ]]; then
  arch_args=(--arch "$FETCH_BITCOIND_ARCH")
fi

mapfile -t lines < <(python3 "$PIN_PY" --inventory "$INV" "${arch_args[@]}")
version=""
arch=""
url=""
tarball=""
sha256=""
inner=""
for line in "${lines[@]}"; do
  case "$line" in
    version=*) version="${line#version=}" ;;
    arch=*) arch="${line#arch=}" ;;
    url=*) url="${line#url=}" ;;
    tarball=*) tarball="${line#tarball=}" ;;
    sha256=*) sha256="${line#sha256=}" ;;
    inner=*) inner="${line#inner=}" ;;
  esac
done
if [[ -z "$version" || -z "$arch" || -z "$url" || -z "$tarball" || -z "$sha256" || -z "$inner" ]]; then
  echo "fetch-bitcoind: incomplete release_pin output" >&2
  exit 1
fi

if [[ -n "${FETCH_BITCOIND_BASE_URL:-}" ]]; then
  url="${FETCH_BITCOIND_BASE_URL%/}/$tarball"
fi

cache="${FETCH_BITCOIND_CACHE:-${HOME}/.cache/rbitcoin/core-bitcoind}"
dest="$cache/$version/$arch"
bin="$dest/bin/bitcoind"
stamp="$dest/sha256"
tarpath="$dest/$tarball"

if [[ "${FETCH_BITCOIND_DRY_RUN:-}" == "1" ]]; then
  echo "arch=$arch" >&2
  echo "url=$url" >&2
  echo "cache=$dest" >&2
  echo "dest=$bin" >&2
  echo "$bin"
  exit 0
fi

if [[ -x "$bin" && -f "$stamp" && "$(cat "$stamp")" == "$sha256" ]]; then
  echo "fetch-bitcoind: cache hit $bin" >&2
  echo "$bin"
  exit 0
fi

mkdir -p "$dest/bin"
part="$tarpath.part"
rm -f "$part"
echo "fetch-bitcoind: downloading $url" >&2
curl -fsSL --retry 3 --max-time 300 "$url" -o "$part"
got="$(sha256sum "$part" | awk '{print $1}')"
if [[ "$got" != "$sha256" ]]; then
  echo "fetch-bitcoind: sha256 mismatch got=$got want=$sha256" >&2
  rm -f "$part" "$tarpath" "$bin"
  exit 1
fi
mv "$part" "$tarpath"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/rbtc-bitcoind-extract.XXXXXX")"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT
tar -xzf "$tarpath" -C "$tmpdir" "$inner"
install -m 0755 "$tmpdir/$inner" "$bin"
printf '%s\n' "$sha256" >"$stamp"
echo "fetch-bitcoind: extracted $bin" >&2
echo "$bin"
