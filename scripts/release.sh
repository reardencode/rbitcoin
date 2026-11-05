#!/usr/bin/env bash
# Tag and push vX.Y.Z so GitHub Actions release.yml builds operator snapshots.
#
# Typical (agent / docs/releases.md): merge the version-bump PR, checkout the
# merge commit, then:
#   ./scripts/release-post.sh         # tag, push tag, create vX.Y.x when X.Y.0
#   ./scripts/release.sh              # tag only (also pushes the branch)
#   ./scripts/release.sh --tag-only   # push the tag, not the branch
#   ./scripts/release.sh --dry-run
#
# Version is workspace.package.version (Cargo.toml). Files that must match:
# Cargo.toml, nix/rbitcoin.nix, CHANGELOG.md ## [X.Y.Z]. Tag is vX.Y.Z.
# Patch 99 is the in-tree sentinel and is never tagged.
# Allowed branches: master, main, vX.Y.x. Does not force-push or rewrite remotes.
set -euo pipefail

ROOT=""
DRY=0
PUSH=1
TAG_ONLY=0
ALLOW_BRANCH=""
ALLOW_DIVERGED=0
REMOTE="origin"
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() {
  echo "usage: $0 [--dry-run] [--no-push] [--tag-only] [--allow-branch NAME] [--allow-diverged] [--remote NAME] [--root DIR]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --no-push) PUSH=0 ;;
    --tag-only) TAG_ONLY=1 ;;
    --allow-branch)
      [[ $# -ge 2 ]] || usage
      ALLOW_BRANCH="$2"
      shift
      ;;
    --allow-diverged) ALLOW_DIVERGED=1 ;;
    --remote)
      [[ $# -ge 2 ]] || usage
      REMOTE="$2"
      shift
      ;;
    --root)
      [[ $# -ge 2 ]] || usage
      ROOT="$2"
      shift
      ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
  shift
done

if [[ -z "$ROOT" ]]; then
  ROOT="$(cd "$HERE/.." && pwd)"
fi
cd "$ROOT"
# shellcheck source=release-lib.sh
source "$HERE/release-lib.sh"

ver="$(release_cargo_workspace_version)"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || release_die "Cargo.toml workspace version is not X.Y.Z: ${ver:-empty}"
release_parse_semver "$ver" || release_die "Cargo.toml workspace version is not X.Y.Z: ${ver:-empty}"
release_is_ship || release_die "workspace $ver is not a ship version (patch 99 is in-tree only)"
tag="v${ver}"

nix_ver="$(release_nix_package_version)"
[[ "$nix_ver" == "$ver" ]] || release_die "nix/rbitcoin.nix version=$nix_ver != Cargo.toml $ver"

release_changelog_has_heading "$ver" || release_die "CHANGELOG.md has no ## [$ver] heading"

notes="$(release_changelog_notes "$ver")"
[[ -n "$(printf '%s\n' "$notes" | grep -v '^[[:space:]]*$')" ]] || release_die "CHANGELOG.md ## [$ver] section is empty"
release_require_highlights "$ver"
notes="$(bash "$HERE/release-notes.sh" --root "$ROOT")"

if [[ -n "$(git status --porcelain)" ]]; then
  release_die "working tree is not clean"
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ -n "$ALLOW_BRANCH" ]]; then
  [[ "$branch" == "$ALLOW_BRANCH" ]] || release_die "on $branch, expected --allow-branch $ALLOW_BRANCH"
elif [[ "$branch" != "master" && "$branch" != "main" ]] && ! release_is_maint_branch "$branch"; then
  release_die "on $branch; merge first or pass --allow-branch $branch"
fi

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  release_die "local tag $tag already exists"
fi
if git remote get-url "$REMOTE" >/dev/null 2>&1; then
  ls_rc=0
  git ls-remote --exit-code "$REMOTE" "refs/tags/${tag}" >/dev/null 2>&1 || ls_rc=$?
  if [[ "$ls_rc" -eq 0 ]]; then
    release_die "remote $REMOTE already has $tag"
  elif [[ "$ls_rc" -ne 2 ]]; then
    release_die "git ls-remote $REMOTE refs/tags/${tag} failed (exit $ls_rc)"
  fi
elif [[ "$DRY" -eq 0 && "$PUSH" -eq 1 ]]; then
  release_die "no git remote $REMOTE"
fi

if [[ "$PUSH" -eq 1 ]]; then
  git fetch "$REMOTE" "+refs/heads/${branch}:refs/remotes/${REMOTE}/${branch}" \
    || release_die "git fetch $REMOTE $branch failed"
  remote_head="$(git rev-parse "refs/remotes/${REMOTE}/${branch}")"
  head="$(git rev-parse HEAD)"
  if [[ "$head" != "$remote_head" && "$ALLOW_DIVERGED" -ne 1 ]]; then
    release_die "HEAD is not ${REMOTE}/${branch} ($head vs $remote_head); pass --allow-diverged"
  fi
fi

echo "release: version=$ver tag=$tag branch=$branch dry=$DRY push=$PUSH tag_only=$TAG_ONLY"
echo "---- CHANGELOG $ver ----"
echo "$notes"
echo "------------------------"

if [[ "$DRY" -eq 1 ]]; then
  echo "release: dry-run ok (no tag)"
  exit 0
fi

msg="rbitcoin ${tag}

${notes}"
git tag -a "$tag" -m "$msg"
echo "release: created annotated $tag at $(git rev-parse --short HEAD)"

if [[ "$PUSH" -eq 0 ]]; then
  echo "release: not pushed (--no-push). Push with:"
  if [[ "$TAG_ONLY" -eq 1 ]]; then
    echo "  git push ${REMOTE} refs/tags/${tag}"
  else
    echo "  git push ${REMOTE} refs/heads/${branch} refs/tags/${tag}"
  fi
  exit 0
fi

if [[ "$TAG_ONLY" -eq 1 ]]; then
  git push "$REMOTE" "refs/tags/${tag}"
  echo "release: pushed ${tag} → $REMOTE"
else
  git push "$REMOTE" "refs/heads/${branch}" "refs/tags/${tag}"
  echo "release: pushed ${branch} + ${tag} → $REMOTE"
fi
echo "release: GitHub Actions .github/workflows/release.yml builds musl/Windows/Darwin"
echo "release: https://github.com/rbitcoin-org/rbitcoin/releases/tag/${tag}"
