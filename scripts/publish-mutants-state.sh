#!/usr/bin/env bash
# Push the mutants cursor and append MISSED lines to the long-lived
# `mutants-state` branch. Does not touch master. A failed push fails
# the caller. MISSED text itself is not a failure.
# Owner: TESTING.md (Mutation testing).
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-rbitcoin-org/rbitcoin}"
BRANCH="${MUTANTS_STATE_BRANCH:-mutants-state}"
CURSOR_SRC="${1:-cursor.json}"
MISSED_SRC="${2:-missed.txt}"

case "$BRANCH" in
  master|main)
    echo "publish-mutants-state: refuse ${BRANCH}" >&2
    exit 1
    ;;
esac

if [[ "${MUTANTS_STATE_DRY_RUN:-}" == "1" ]]; then
  echo "publish-mutants-state: ${REPO} ${BRANCH}/cursor.json + missed.txt"
  echo "publish-mutants-state: miss-list append from ${MISSED_SRC}"
  echo "publish-mutants-state: dry-run (no push, no checkout)"
  exit 0
fi

if [[ "${MUTANTS_STATE_PUBLISH:-}" != "1" ]]; then
  echo "publish-mutants-state: skip (MUTANTS_STATE_PUBLISH!=1)"
  exit 0
fi

if [[ ! -f "$CURSOR_SRC" ]]; then
  echo "publish-mutants-state: missing cursor ${CURSOR_SRC}" >&2
  exit 1
fi

if [[ -n "${MUTANTS_STATE_PUSH_URL:-}" ]]; then
  url="${MUTANTS_STATE_PUSH_URL}"
elif [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "publish-mutants-state: no GITHUB_TOKEN" >&2
  exit 1
else
  url="https://x-access-token:${GITHUB_TOKEN}@github.com/${REPO}.git"
fi

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

if git clone --depth 1 --branch "$BRANCH" "$url" "$work" 2>/dev/null; then
  :
elif git ls-remote --exit-code "$url" "refs/heads/${BRANCH}" >/dev/null 2>&1; then
  echo "publish-mutants-state: clone failed but ${BRANCH} exists" >&2
  exit 1
else
  git init --initial-branch="$BRANCH" "$work"
  git -C "$work" remote add origin "$url"
fi

cp "$CURSOR_SRC" "$work/cursor.json"
python3 - "$MISSED_SRC" "$work/missed.txt" "${MUTANTS_RUN_ID:-}" "${MUTANTS_PHASE:-}" "${GITHUB_SHA:-}" <<'PY'
import sys
from pathlib import Path

src, dest, run_id, phase, sha = sys.argv[1:]
hist_path = Path(dest)
hist = hist_path.read_text(encoding="utf-8") if hist_path.exists() else ""
incoming = ""
miss_path = Path(src)
if miss_path.is_file():
    incoming = miss_path.read_text(encoding="utf-8").strip()
if incoming:
    header = f"# {run_id} {phase} {sha}\n"
    block = header + incoming + "\n"
    if block not in hist:
        if hist and not hist.endswith("\n"):
            hist += "\n"
        hist += block
hist_path.write_text(hist, encoding="utf-8")
PY

git -C "$work" add cursor.json missed.txt
if git -C "$work" diff --cached --quiet; then
  echo "publish-mutants-state: unchanged"
  exit 0
fi

sha="${GITHUB_SHA:-unknown}"
git -C "$work" \
  -c user.name="github-actions[bot]" \
  -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit -m "mutants: cursor ${MUTANTS_RUN_ID:-local} phase ${MUTANTS_PHASE:-0} (${sha:0:12})"
git -C "$work" push origin "HEAD:${BRANCH}"
echo "publish-mutants-state: pushed cursor and miss list to ${BRANCH}"
