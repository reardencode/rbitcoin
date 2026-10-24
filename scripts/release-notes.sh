#!/usr/bin/env bash
# Brief GitHub Release notes: platform blurb + CHANGELOG ### Highlights.
# Thanks live in that section. A committer not already named there is
# thanked in the same block. Full Keep a Changelog body stays in CHANGELOG.md.
set -euo pipefail

ROOT=""
VER=""
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() {
  echo "usage: $0 [X.Y.Z] [--root DIR]" >&2
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
      [[ -z "$VER" ]] || usage
      VER="$1"
      ;;
  esac
  shift
done

if [[ -z "$ROOT" ]]; then
  ROOT="$(cd "$HERE/.." && pwd)"
fi
cd "$ROOT"
# shellcheck source=release-lib.sh
source "$HERE/release-lib.sh"

if [[ -z "$VER" ]]; then
  VER="$(release_cargo_workspace_version)"
fi
release_parse_semver "$VER" || release_die "version is not X.Y.Z: ${VER:-empty}"
release_is_ship || release_die "workspace $VER is not a ship version (patch 99 is in-tree only)"
release_require_highlights "$VER"

# GitHub login for a commit email, or empty when the author is the
# maintainer, the bot, dependabot, or not a noreply login.
release_login_from_email() {
  local email="$1"
  case "$email" in
    *rearden-grok*|*reardencode*|*dependabot*)
      return 0
      ;;
  esac
  case "$email" in
    Hero-Gamer@users.noreply.github.com) printf '%s\n' Hero-Gamer ;;
    xstoicunicornx@users.noreply.github.com) printf '%s\n' xstoicunicornx ;;
    *@users.noreply.github.com)
      local localpart="${email%%@*}"
      localpart="${localpart##*+}"
      case "$localpart" in
        ''|*[!A-Za-z0-9-]*) ;;
        *) printf '%s\n' "$localpart" ;;
      esac
      ;;
  esac
}

release_thanks_sentence() {
  local skip="${1:-}"
  local prev range line email login
  prev="$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n 1 || true)"
  if [[ -n "$prev" ]]; then
    range="${prev}..HEAD"
  else
    range="HEAD"
  fi
  local -a others=()
  release_keep_login() {
    local login="$1"
    [[ -n "$login" ]] || return 0
    case "$login" in
      reardencode|rearden-grok|rearden-grok\[bot\]|dependabot|dependabot\[bot\])
        return 0
        ;;
    esac
    if [[ -n "$skip" ]] && printf '%s' "$skip" | grep -q "@${login}"; then
      return 0
    fi
    local seen=0 o
    for o in "${others[@]+"${others[@]}"}"; do
      [[ "$o" == "$login" ]] && seen=1
    done
    [[ "$seen" -eq 0 ]] && others+=("$login")
  }
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^Merge\ pull\ request\ \#[0-9]+\ from\ ([A-Za-z0-9-]+)/ ]]; then
      release_keep_login "${BASH_REMATCH[1]}"
      continue
    fi
    if [[ "$line" == Co-authored-by:* ]]; then
      email="${line##*<}"
      email="${email%>}"
    else
      email="$line"
    fi
    login="$(release_login_from_email "$email" || true)"
    release_keep_login "$login"
  done < <(git log "$range" --format='%ae%n%s%n%b')
  local rest=""
  if ((${#others[@]})); then
    local joined=""
    for o in "${others[@]}"; do
      if [[ -z "$joined" ]]; then
        joined="@${o}"
      else
        joined="${joined}, @${o}"
      fi
    done
    rest="Thanks to ${joined} for changes in this release."
  fi
  printf '%s\n' "$rest"
}

hl="$(release_changelog_highlights "$VER" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')"
authors="$(release_thanks_sentence "$hl" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')"
note="rbitcoin v${VER}

Linux **musl x86_64 and aarch64** are the operator binaries (statically
linked). Windows is CRT-static PE (no IoRing). Darwin aarch64 is ad-hoc
codesigned, **not notarized** (\`xattr -d com.apple.quarantine\`).
Image (linux/amd64, linux/arm64): \`docker pull ghcr.io/reardencode/rbitcoin:${VER}\`.

### Highlights

${hl}
"
if [[ -n "$authors" ]]; then
  note="${note}
${authors}
"
fi
note="${note}
Full notes: CHANGELOG.md \`## [${VER}]\`."
printf '%s\n' "$note"
