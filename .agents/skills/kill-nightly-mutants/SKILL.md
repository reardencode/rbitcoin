---
name: kill-nightly-mutants
description: >-
  Kill every nightly cargo-mutants MISSED line since the last kill, and
  report cursor health before editing. Use when the user says kill nightly
  mutants, kill the overnight misses, kill the latest missed mutants, or
  runs /kill-nightly-mutants.
---

# Kill missed mutants since the last kill

Proof and the delete-then-journey order:
[`TESTING.md`](../../../TESTING.md) (What a mutant kill looks like).
The cargo-mutants row there owns the night schedule, the backlog
reset, and the cursor fields. Red / Green, and cargo log redirect:
[`docs/how-we-plan.md`](../../../docs/how-we-plan.md#agent-contract).
Worktree, push, and poll:
[ship-pr](../ship-pr/SKILL.md).
`rearden-grok[bot]` also follows
[`rearden-vm-HOST.md`](../../../rearden-vm-HOST.md).

One gap, one branch, one PR. Do not merge unless asked.

## Which lines

`missed.txt` on `mutants-state` is an append-only log. A block starts
with `# <run_id> <phase> <sha>`. Fetch that branch. Do not check it out
over the session worktree.

```bash
git fetch https://github.com/rbitcoin-org/rbitcoin.git mutants-state
git show FETCH_HEAD:missed.txt
git show FETCH_HEAD:cursor.json
git log -n 14 --format='%H%x09%cI' FETCH_HEAD -- cursor.json
```

```bash
gh pr list --repo rbitcoin-org/rbitcoin --state merged --search 'head:mutants/' --limit 30 \
  --json number,headRefName,mergedAt
```

The floor is the greatest Actions run id among those heads
`mutants/run-<id>`, `mutants/overnight-<id>`, and
`mutants/through-<id>`. The batch is every `missed.txt` block with a
greater run id, both phases of every such run. A runner shutdown (exit
143) does not publish; do not invent those lines from a partial job
log. If the user names a floor, use that. If no merged kill names a run
id, stop and say so.

Read the lines against current `origin/master`.

## Cursor health

Print this before editing. Put the same report in the PR body. The
command owns the catch rate, the net, the backlog pace, and the days
left. Field names live in `TESTING.md`.

```bash
git fetch https://github.com/rbitcoin-org/rbitcoin.git mutants-state
git log -n 14 --format='%H%x09%cI' FETCH_HEAD -- cursor.json > /tmp/mutants-cursors.list
: > /tmp/mutants-health.jsonl
while IFS=$'\t' read -r sha at; do
  git show "$sha:cursor.json" | python3 -c 'import json,sys; c=json.load(sys.stdin); print(json.dumps({"date":sys.argv[1][:10],"at":sys.argv[1],"cursor":c}))' "$at"
done < /tmp/mutants-cursors.list >> /tmp/mutants-health.jsonl
python3 scripts/mutants_queue.py health --jsonl /tmp/mutants-health.jsonl
base=$(git show FETCH_HEAD:cursor.json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("new_base",""))')
git fetch https://github.com/rbitcoin-org/rbitcoin.git master
git rev-list --count "${base}..FETCH_HEAD"
```

The `rev-list` count is how many commits `origin/master` is ahead of
`new_base`. Do not check `mutants-state` out over the session worktree.

## Disposition

Walk each `MISSED` line in the batch on the current tree. The kill order and the hand-edit proof are in `TESTING.md`. Two batch rules sit on top of that:

- **Already gone.** The operator text is not in the file. Record it. No edit.
- A compile error is not a kill. Never `#[mutants::skip]`.

Group operators one journey kills into one slice. Prove each operator.

## Ship

Branch `mutants/through-<newest-run-id>`. One
`changelog.d/overnight-through-<newest-run-id>.md`.
Do not edit `CHANGELOG.md`.

The PR body accounts for every line of the batch in one of three lists:

- Already gone
- Deleted (path and operator)
- Pinned by test (test name, then the `MISSED` line)

Do not label `core-functional`. Follow ship-pr for the worktree, the push, and `./scripts/pr-checks-watch.sh`.
