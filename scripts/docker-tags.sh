#!/usr/bin/env bash
# Image tags for a ship tag, one per line: X.Y.Z, then X.Y when it is the
# newest patch on its line, then latest when it is the newest ship tag. A
# patch on an older line, or a rerun of an old tag, moves neither. Reads
# v*.*.* tags from --root (default: this repo), so CI must fetch tags.
#
# Usage: ./scripts/docker-tags.sh vX.Y.Z [--root DIR]
set -euo pipefail

ROOT=""
TAG=""
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() {
  echo "usage: $0 vX.Y.Z [--root DIR]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 ]] || usage
      ROOT="$2"
      shift
      ;;
    -h|--help) usage ;;
    *)
      [[ -z "$TAG" ]] || usage
      TAG="$1"
      ;;
  esac
  shift
done

if [[ -z "$ROOT" ]]; then
  ROOT="$(cd "$HERE/.." && pwd)"
fi
# shellcheck source=release-lib.sh
source "$HERE/release-lib.sh"

[[ "$TAG" == v* ]] || release_die "tag is not vX.Y.Z: ${TAG:-empty}"
VER="${TAG#v}"
release_parse_semver "$VER" || release_die "tag is not vX.Y.Z: $TAG"
release_is_ship || release_die "$TAG is not a ship version (patch 99 is in-tree only)"

# Ship versions in numeric order, including this one if not fetched yet.
ship_versions() {
  {
    git -C "$ROOT" tag -l 'v*' | sed -n 's/^v\([0-9]*\.[0-9]*\.[0-9]*\)$/\1/p'
    printf '%s\n' "$VER"
  } | awk -F. '$3 != 99' | sort -u -t. -k1,1n -k2,2n -k3,3n
}

versions="$(ship_versions)"
newest="$(tail -n 1 <<<"$versions")"
newest_on_line="$(awk -F. -v x="$REL_MAJOR" -v y="$REL_MINOR" \
  '$1 == x && $2 == y' <<<"$versions" | tail -n 1)"

echo "$VER"
if [[ "$newest_on_line" == "$VER" ]]; then
  echo "$REL_MAJOR.$REL_MINOR"
fi
if [[ "$newest" == "$VER" ]]; then
  echo latest
fi
