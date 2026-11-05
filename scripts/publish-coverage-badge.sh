#!/usr/bin/env bash
# Push coverage/badge.json to the orphan-style `badges` branch as coverage.json
# and append coverage-history.jsonl (sha, lh, lf, date). Does not touch master.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:-$ROOT/coverage/badge.json}"
REPO="${GITHUB_REPOSITORY:-rbitcoin-org/rbitcoin}"
BRANCH="badges"

if [[ "${BADGE_DRY_RUN:-}" == "1" ]]; then
  echo "publish-coverage-badge: $SRC -> $REPO $BRANCH/coverage.json + coverage-history.jsonl"
  exit 0
fi

if [[ ! -f "$SRC" ]]; then
  echo "publish-coverage-badge: skip (missing $SRC)"
  exit 0
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "publish-coverage-badge: skip (no GITHUB_TOKEN)"
  exit 0
fi

if [[ "${PUBLISH_COVERAGE_BADGE:-}" != "1" ]]; then
  echo "publish-coverage-badge: skip (PUBLISH_COVERAGE_BADGE!=1)"
  exit 0
fi

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

url="https://x-access-token:${GITHUB_TOKEN}@github.com/${REPO}.git"
if git clone --depth 1 --branch "$BRANCH" "$url" "$work" 2>/dev/null; then
  :
elif git ls-remote --exit-code "$url" "refs/heads/${BRANCH}" >/dev/null 2>&1; then
  echo "publish-coverage-badge: clone failed but ${BRANCH} exists" >&2
  exit 1
else
  git init --initial-branch="$BRANCH" "$work"
  git -C "$work" remote add origin "$url"
fi

cp "$SRC" "$work/coverage.json"
python3 - "$SRC" "$work/coverage-history.jsonl" <<'PY'
import json, sys
from pathlib import Path
src = json.loads(Path(sys.argv[1]).read_text())
hist_path = Path(sys.argv[2])
rows = []
if hist_path.exists():
    for line in hist_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
sha = str(src.get("sha") or "")
if sha:
    rows = [r for r in rows if str(r.get("sha")) != sha]
    rows.append(
        {
            "sha": sha,
            "lh": int(src["lh"]),
            "lf": int(src["lf"]),
            "date": str(src.get("date") or ""),
        }
    )
    rows = rows[-500:]
    hist_path.write_text(
        "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows),
        encoding="utf-8",
    )
PY
git -C "$work" add coverage.json coverage-history.jsonl
if git -C "$work" diff --cached --quiet; then
  echo "publish-coverage-badge: unchanged"
  exit 0
fi

msg="$(python3 -c "import json; print(json.load(open('$SRC'))['message'])")"
sha="${GITHUB_SHA:-unknown}"
git -C "$work" \
  -c user.name="github-actions[bot]" \
  -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit -m "coverage: ${msg} (${sha:0:12})"
git -C "$work" push origin "HEAD:${BRANCH}"
echo "publish-coverage-badge: pushed ${msg} to ${BRANCH}"
