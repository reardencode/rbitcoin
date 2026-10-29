#!/usr/bin/env bash
# A scheduled workflow must not share a cancelling concurrency group with
# push or workflow_dispatch on the same ref. mutants is the exception:
# cancel-in-progress is false, so a second night queues behind the writer
# of mutants-state.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"

set +e
pin="$(python3 - "$ROOT/.github/workflows" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
bad = []
seen = []
for path in sorted(root.glob("*.yml")):
    lines = path.read_text().splitlines()
    if not any(line.strip().startswith("- cron:") or line.strip().startswith("cron:") for line in lines):
        continue
    start = next((i for i, line in enumerate(lines) if line.startswith("concurrency:")), None)
    if start is None:
        bad.append(path.name + ":no-concurrency")
        continue
    block = []
    for line in lines[start + 1:]:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        block.append(line)
    text = "\n".join(block)
    seen.append(path.name)
    queues = "cancel-in-progress: false" in text
    own_group = "github.event_name == 'schedule'" in text
    if not (queues or own_group):
        bad.append(path.name)
print("scheduled=" + ",".join(seen))
print("bad=" + ",".join(bad))
sys.exit(1 if bad else 0)
PY
)"
pin_rc=$?
set -e

assert_ok "every cron workflow queues or isolates schedule" test "$pin_rc" -eq 0
assert_ok "the pin lists model among the scheduled workflows" grep -q "model.yml" <<<"$pin"
assert_ok "mutants queues instead of cancelling" grep -q "cancel-in-progress: false" "$ROOT/.github/workflows/mutants.yml"

if [[ "$FAIL" -ne 0 ]]; then
  printf '%s\n' "$pin"
  echo "$FAIL failed, $PASS passed"
  exit 1
fi
echo "$PASS passed"
