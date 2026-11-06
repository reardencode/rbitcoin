#!/usr/bin/env bash
# Cursor math for the nightly mutants queue. Does not run cargo-mutants.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/scripts/mutants_queue.py"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"


tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/list.txt" <<'EOF'
crates/a/src/lib.rs:2:1: replace a in old
crates/b/src/lib.rs:4:1: replace b in new
crates/a/src/lib.rs:9:1: replace c in old
not a mutant
EOF

cat >"$tmp/diff.txt" <<'EOF'
diff --git a/crates/b/src/lib.rs b/crates/b/src/lib.rs
--- a/crates/b/src/lib.rs
+++ b/crates/b/src/lib.rs
@@ -3,0 +4 @@
+fn new_line() {}
EOF

order="$(python3 "$PY" order --list "$tmp/list.txt" --diff "$tmp/diff.txt" --old-index 1 --new-skip 0)"
first="$(printf '%s\n' "$order" | head -n 1)"
second="$(printf '%s\n' "$order" | sed -n '2p')"
assert_ok "new mutant is first" test "$first" = "crates/b/src/lib.rs:4:1: replace b in new"
assert_ok "old rotation starts at index 1" test "$second" = "crates/a/src/lib.rs:9:1: replace c in old"

skipped="$(python3 "$PY" order --list "$tmp/list.txt" --diff "$tmp/diff.txt" --old-index 0 --new-skip 1 | head -n 1)"
assert_ok "new-skip drops the new prefix" test "$skipped" = "crates/a/src/lib.rs:2:1: replace a in old"

printf '%s\n' '{"new_base":"abc","new_skip":0,"old_index":1}' >"$tmp/cursor.json"
python3 "$PY" advance --cursor "$tmp/cursor.json" --n-new 2 --n-old 2 --completed 1 --head abc
assert_ok "partial new keeps the base" grep -q '"new_base": "abc"' "$tmp/cursor.json"
assert_ok "partial new records skip" grep -q '"new_skip": 1' "$tmp/cursor.json"

python3 "$PY" advance --cursor "$tmp/cursor.json" --n-new 2 --n-old 2 --completed 2 --head def
assert_ok "finished new moves the base" grep -q '"new_base": "def"' "$tmp/cursor.json"
assert_ok "finished new clears skip" grep -q '"new_skip": 0' "$tmp/cursor.json"
# old_index was 1; the extra completed mutant walks one old slot -> 0 (mod 2)
assert_ok "old index wraps" grep -q '"old_index": 0' "$tmp/cursor.json"

angled='crates/rbitcoin-esplora/src/handlers.rs:1504:5: replace sat_vb -> Option<f64> with None'
re_out="$(python3 "$PY" re "$angled")"
assert_ok "regex is anchored" bash -c '[[ "$1" == ^* && "$1" == *\$ ]]' _ "$re_out"
assert_ok "angle brackets stay literal" bash -c 'printf "%s\n" "$1" | grep -F -q "Option<f64>"' _ "$re_out"
assert_ok "hyphen and dot are escaped" bash -c 'printf "%s\n" "$1" | grep -F -q "rbitcoin\\-esplora" && printf "%s\n" "$1" | grep -F -q "handlers\\.rs"' _ "$re_out"

pipes='crates/a.rs:1:1: replace && with || in f'
pipe_re="$(python3 "$PY" re "$pipes")"
assert_ok "pipes are escaped" bash -c '[[ "$1" == *\\\|\\\|* ]]' _ "$pipe_re"

cat >"$tmp/batch.log" <<'EOF'
Found 22 mutants to test
22 mutants tested in 11m: 10 caught, 12 unviable
EOF
finished="$(python3 "$PY" finished --log "$tmp/batch.log")"
assert_ok "summary counts caught and unviable" test "$finished" = 22

cat >"$tmp/partial.log" <<'EOF'
MISSED   crates/a.rs:1:1: replace == with != in f
caught   crates/a.rs:2:1: replace x with y in f
EOF
partial="$(python3 "$PY" finished --log "$tmp/partial.log")"
assert_ok "killed batch counts outcome lines" test "$partial" = 2

cat >"$tmp/queue.txt" <<'EOF'
crates/a/src/lib.rs:1:1: replace a in f
crates/a/src/lib.rs:2:1: replace b in f
crates/b/src/lib.rs:3:1: replace c in f
EOF
batch="$(python3 "$PY" file-batch --queue "$tmp/queue.txt" --offset 0 --cap 10)"
assert_ok "file batch stays on the first path" test "$batch" = "$(printf '%s\n' \
  'crates/a/src/lib.rs:1:1: replace a in f' \
  'crates/a/src/lib.rs:2:1: replace b in f')"
capped="$(python3 "$PY" file-batch --queue "$tmp/queue.txt" --offset 0 --cap 1)"
assert_ok "file batch honors the cap" test "$capped" = "crates/a/src/lib.rs:1:1: replace a in f"
next_file="$(python3 "$PY" file-batch --queue "$tmp/queue.txt" --offset 2 --cap 10)"
assert_ok "file batch offset reaches the next path" test "$next_file" = "crates/b/src/lib.rs:3:1: replace c in f"

cat >"$tmp/slice.txt" <<'EOF'
crates/a/src/lib.rs:2:1: replace b in f
crates/a/src/lib.rs:4:1: replace d in f
EOF
cat >"$tmp/killed.log" <<'EOF'
unviable crates/a/src/lib.rs:1:1: delete field x from struct S expression in f in 1s build
caught   crates/a/src/lib.rs:2:1: replace b in f in 10s build + 4s test
caught   crates/a/src/lib.rs:9:1: replace z in f in 10s build + 4s test
EOF
prog="$(python3 "$PY" progress --log "$tmp/killed.log" --slice "$tmp/slice.txt")"
assert_ok "progress ignores unfiltered deletes and stops at a hole" test "$prog" = 1

# Half the job budget is the new-mutant window. A batch already started
# may finish after that mark; the next batch is backlog. Names below are
# one file each so a cap of 1 is one cargo invocation.
cat >"$tmp/new-q.txt" <<'EOF'
crates/new/a.rs:1:1: replace a with b in n1
crates/new/b.rs:2:1: replace a with b in n2
crates/new/c.rs:3:1: replace a with b in n3
crates/new/d.rs:4:1: replace a with b in n4
EOF
cat >"$tmp/old-q.txt" <<'EOF'
crates/old/a.rs:1:1: replace a with b in o1
crates/old/b.rs:2:1: replace a with b in o2
crates/old/c.rs:3:1: replace a with b in o3
crates/old/d.rs:4:1: replace a with b in o4
crates/old/e.rs:5:1: replace a with b in o5
crates/old/f.rs:6:1: replace a with b in o6
EOF

sched="$(python3 "$PY" schedule --new "$tmp/new-q.txt" --old "$tmp/old-q.txt" \
  --budget 1000 --batch-sec 200 --cap 1)"
assert_ok "both sides: after half the budget the names are backlog" \
  python3 -c '
import sys
rows = [line.split("\t", 2) for line in sys.argv[1].splitlines()]
half = 500
after = [r for r in rows if int(r[1]) >= half]
before = [r for r in rows if int(r[1]) < half]
assert after and all(r[0] == "old" for r in after), after
assert before and all(r[0] == "new" for r in before), before
assert any(r[0] == "new" and int(r[1]) + 200 > half for r in before), before
' "$sched"

cross="$(python3 "$PY" schedule --new "$tmp/new-q.txt" --old "$tmp/old-q.txt" \
  --budget 1000 --batch-sec 400 --cap 1)"
assert_ok "a batch that started before half stays new" \
  python3 -c '
import sys
rows = [line.split("\t", 2) for line in sys.argv[1].splitlines()]
by = {int(r[1]): r[0] for r in rows}
assert by[0] == "new" and by[400] == "new" and by[800] == "old", rows
' "$cross"

cat >"$tmp/one-new.txt" <<'EOF'
crates/new/a.rs:1:1: replace a with b in n1
EOF
early="$(python3 "$PY" schedule --new "$tmp/one-new.txt" --old "$tmp/old-q.txt" \
  --budget 1000 --batch-sec 200 --cap 1)"
assert_ok "unused new time goes to the backlog immediately" \
  python3 -c '
import sys
rows = [line.split("\t", 2) for line in sys.argv[1].splitlines()]
assert rows[0][0] == "new" and int(rows[0][1]) == 0, rows
assert rows[1][0] == "old" and int(rows[1][1]) == 200, rows
' "$early"

: >"$tmp/empty-q.txt"
empty_new="$(python3 "$PY" schedule --new "$tmp/empty-q.txt" --old "$tmp/old-q.txt" \
  --budget 1000 --batch-sec 200 --cap 1)"
assert_ok "empty new schedules backlog immediately" \
  python3 -c '
import sys
rows = [line.split("\t", 2) for line in sys.argv[1].splitlines()]
assert rows and rows[0][0] == "old" and int(rows[0][1]) == 0, rows
assert all(r[0] == "old" for r in rows), rows
' "$empty_new"

empty_old="$(python3 "$PY" schedule --new "$tmp/new-q.txt" --old "$tmp/empty-q.txt" \
  --budget 1000 --batch-sec 200 --cap 1)"
assert_ok "empty backlog keeps scheduling new past half" \
  python3 -c '
import sys
rows = [line.split("\t", 2) for line in sys.argv[1].splitlines()]
assert rows and all(r[0] == "new" for r in rows), rows
assert any(int(r[1]) >= 500 for r in rows), rows
' "$empty_old"

capped="$(python3 "$PY" schedule --new "$tmp/new-q.txt" --old "$tmp/old-q.txt" \
  --budget 1000 --batch-sec 200 --cap 1 --new-cap-used 1)"
assert_ok "a used new cap does not schedule more new while backlog remains" \
  python3 -c '
import sys
rows = [line.split("\t", 2) for line in sys.argv[1].splitlines()]
assert rows and all(r[0] == "old" for r in rows), rows
assert not any(r[0] == "new" for r in rows), rows
' "$capped"

kept="$(python3 "$PY" resume-old --list "$tmp/old-q.txt" --index 0 \
  --name "crates/old/c.rs:3:1: replace a with b in o3")"
assert_ok "a persisted backlog name that still exists is the resume point" \
  test "$(printf '%s\n' "$kept" | head -n 1)" = "crates/old/c.rs:3:1: replace a with b in o3"

missing="$(python3 "$PY" resume-old --list "$tmp/old-q.txt" --index 5 \
  --name "crates/gone.rs:1:1: replace a with b in gone")"
assert_ok "a missing backlog name resumes at the saved index modulo length" \
  test "$(printf '%s\n' "$missing" | head -n 1)" = "crates/old/f.rs:6:1: replace a with b in o6"
assert_ok "a missing backlog name does not resume at zero" \
  test "$(printf '%s\n' "$missing" | head -n 1)" != "crates/old/a.rs:1:1: replace a with b in o1"

printf '%s\n' '{"new_base":"abc","new_skip":0,"old_index":0,"old_name":"","new_cap_used":true,"run_id":"42"}' >"$tmp/night.json"
python3 "$PY" night --cursor "$tmp/night.json" --run-id 42
assert_ok "the same night keeps a consumed new cap" \
  grep -q '"new_cap_used": true' "$tmp/night.json"
python3 "$PY" night --cursor "$tmp/night.json" --run-id 99
assert_ok "a new night clears the new cap" \
  grep -q '"new_cap_used": false' "$tmp/night.json"
assert_ok "a new night records its run id" \
  grep -q '"run_id": "99"' "$tmp/night.json"

printf '%s\n' '{"new_base":"","new_skip":0,"old_index":1,"old_name":"crates/old/c.rs:3:1: replace a with b in o3","new_cap_used":false,"run_id":""}' >"$tmp/split-cursor.json"
cat >"$tmp/split-list.txt" <<'EOF'
crates/new/a.rs:1:1: replace a with b in n1
crates/old/a.rs:1:1: replace a with b in o1
crates/old/b.rs:2:1: replace a with b in o2
crates/old/c.rs:3:1: replace a with b in o3
EOF
cat >"$tmp/split-diff.txt" <<'EOF'
diff --git a/crates/new/a.rs b/crates/new/a.rs
--- a/crates/new/a.rs
+++ b/crates/new/a.rs
@@ -0,0 +1 @@
+fn new_line() {}
EOF
python3 "$PY" split --list "$tmp/split-list.txt" --diff "$tmp/split-diff.txt" \
  --cursor "$tmp/split-cursor.json" --head feedface \
  --out-new "$tmp/split-new.txt" --out-old "$tmp/split-old.txt" >/dev/null
assert_ok "split resumes the old queue at the saved name" \
  test "$(head -n 1 "$tmp/split-old.txt")" = "crates/old/c.rs:3:1: replace a with b in o3"
assert_ok "split keeps the new mutant on the new side" \
  test "$(cat "$tmp/split-new.txt")" = "crates/new/a.rs:1:1: replace a with b in n1"

python3 "$PY" advance-side --cursor "$tmp/split-cursor.json" --side old \
  --completed 1 --n-new 1 --n-old 3 --head def \
  --old-queue "$tmp/split-old.txt" --old-offset 1 \
  --elapsed 0 --budget 1000 --new-left 1 --old-left 2
assert_ok "advancing the backlog stores the next mutant name" \
  grep -q '"old_name": "crates/old/a.rs:1:1: replace a with b in o1"' "$tmp/split-cursor.json"

# new_skip already covers the one new mutant. Those names are not walked,
# and the new phase finishes so the next diff starts at HEAD.
printf '%s\n' '{"new_base":"abc","new_skip":2,"old_index":0,"old_name":"","new_cap_used":false,"run_id":""}' >"$tmp/stuck.json"
python3 "$PY" split --list "$tmp/split-list.txt" --diff "$tmp/split-diff.txt" \
  --cursor "$tmp/stuck.json" --head feedface \
  --out-new "$tmp/stuck-new.txt" --out-old "$tmp/stuck-old.txt" >/dev/null
stuck_sched="$(python3 "$PY" schedule --new "$tmp/stuck-new.txt" --old "$tmp/stuck-old.txt" \
  --budget 1000 --batch-sec 200 --cap 1)"
assert_ok "a covered new_skip schedules none of the sliced-off new name" \
  bash -c '! printf "%s\n" "$1" | grep -q "crates/new/a.rs:1:1: replace a with b in n1"' _ "$stuck_sched"
assert_ok "a covered new_skip still schedules the backlog" \
  grep -q "crates/old/" <<<"$stuck_sched"
assert_ok "a covered new_skip moves new_base to HEAD" \
  grep -q '"new_base": "feedface"' "$tmp/stuck.json"
assert_ok "a covered new_skip clears the skip" \
  grep -q '"new_skip": 0' "$tmp/stuck.json"

# A finished backlog generation drops both cursors and rebuilds the
# backlog as every listed mutant at HEAD. The night cap stays.
printf '%s\n' '{"new_base":"abc","new_skip":4,"old_index":9,"old_name":"crates/old/c.rs:3:1: replace a with b in o3","new_cap_used":true,"run_id":"42","new_len":4,"old_len":9}' >"$tmp/roll.json"
python3 "$PY" rollover --cursor "$tmp/roll.json" --list "$tmp/split-list.txt" \
  --head deadbeef --out-new "$tmp/roll-new.txt" --out-old "$tmp/roll-old.txt" >/dev/null
assert_ok "a finished backlog sets new_base to HEAD" \
  grep -q '"new_base": "deadbeef"' "$tmp/roll.json"
assert_ok "a finished backlog clears new_skip" \
  grep -q '"new_skip": 0' "$tmp/roll.json"
assert_ok "a finished backlog clears old_index" \
  grep -q '"old_index": 0' "$tmp/roll.json"
assert_ok "a finished backlog keeps the night cap" \
  grep -q '"new_cap_used": true' "$tmp/roll.json"
assert_ok "a finished backlog keeps the run id" \
  grep -q '"run_id": "42"' "$tmp/roll.json"
assert_ok "a fresh backlog has no new file" \
  test ! -s "$tmp/roll-new.txt"
assert_ok "a fresh backlog is the full list in order" \
  cmp -s "$tmp/split-list.txt" "$tmp/roll-old.txt"
assert_ok "a fresh backlog starts at the first listed mutant" \
  test "$(head -n 1 "$tmp/roll-old.txt")" = "crates/new/a.rs:1:1: replace a with b in n1"
assert_ok "a fresh backlog records its length" \
  grep -q '"old_len": 4' "$tmp/roll.json"
assert_ok "a fresh backlog records no new mutants" \
  grep -q '"new_len": 0' "$tmp/roll.json"

python3 "$PY" remember --cursor "$tmp/roll.json" \
  --new-len 0 --old-len 4 --new-remaining 0 --old-remaining 2 \
  --completed-new 4 --completed-old 9
assert_ok "remember stores this job's old progress" \
  grep -q '"completed_old": 9' "$tmp/roll.json"
assert_ok "remember stores mutants still in the fresh backlog" \
  grep -q '"old_remaining": 2' "$tmp/roll.json"

printf '%s\n' '{"new_base":"abc","new_skip":0,"old_index":0,"old_name":"","new_cap_used":false,"run_id":"1"}' >"$tmp/neg.json"
set +e
python3 "$PY" remember --cursor "$tmp/neg.json" \
  --new-len 0 --old-len 1 --new-remaining 0 --old-remaining 1 \
  --completed-new -1 --completed-old 0 >/dev/null 2>&1
neg_ec=$?
set -e
assert_ok "remember rejects a negative count" test "$neg_ec" -ne 0

# Oldest first is not required: health sorts by at.
cat >"$tmp/health-up.jsonl" <<'EOF'
{"date":"2026-10-02","at":"2026-10-02T08:00:00Z","cursor":{"new_base":"aaa","new_remaining":4,"old_remaining":80,"completed_new":3,"completed_old":10,"old_index":4}}
{"date":"2026-10-01","at":"2026-10-01T08:00:00Z","cursor":{"new_base":"aaa","new_remaining":10,"old_remaining":100,"completed_new":3,"completed_old":10,"old_index":2}}
EOF
health_up="$(python3 "$PY" health --jsonl "$tmp/health-up.jsonl")"
assert_ok "new queue catching up names the catch rate" \
  grep -q 'catch rate 3.0 mutants/night over 2 nights' <<<"$health_up"
assert_ok "new queue catching up names outstanding" \
  grep -q 'Outstanding 4.' <<<"$health_up"
assert_ok "a shrinking new queue is catching up" \
  grep -q 'catching up' <<<"$health_up"
assert_ok "backlog days left uses the pace" \
  grep -q 'about 8.0 days left' <<<"$health_up"

cat >"$tmp/health-behind.jsonl" <<'EOF'
{"date":"2026-10-01","at":"2026-10-01T08:00:00Z","cursor":{"new_base":"aaa","new_remaining":4,"old_remaining":50,"completed_new":2,"completed_old":0}}
{"date":"2026-10-02","at":"2026-10-02T08:00:00Z","cursor":{"new_base":"aaa","new_remaining":20,"old_remaining":50,"completed_new":2,"completed_old":0}}
EOF
health_behind="$(python3 "$PY" health --jsonl "$tmp/health-behind.jsonl")"
assert_ok "a growing new queue is falling behind" \
  grep -q 'falling behind' <<<"$health_behind"
assert_ok "zero backlog pace is not a day count" \
  grep -q 'no recent backlog progress' <<<"$health_behind"

cat >"$tmp/health-one.jsonl" <<'EOF'
{"date":"2026-10-01","at":"2026-10-01T04:00:00Z","cursor":{"new_base":"aaa","new_remaining":9,"old_remaining":40,"completed_new":4,"completed_old":6}}
{"date":"2026-10-01","at":"2026-10-01T12:00:00Z","cursor":{"new_base":"aaa","new_remaining":5,"old_remaining":30,"completed_new":6,"completed_old":4}}
EOF
health_one="$(python3 "$PY" health --jsonl "$tmp/health-one.jsonl")"
assert_ok "two jobs in one night add their catches" \
  grep -q 'catch rate 10.0 mutants/night over 1 night' <<<"$health_one"
assert_ok "one night does not invent a trend" \
  grep -q 'Trend needs another night.' <<<"$health_one"
assert_ok "two jobs in one night add their backlog pace" \
  grep -q 'pace 10.0 mutants/night over 1 night' <<<"$health_one"

cat >"$tmp/health-reset.jsonl" <<'EOF'
{"date":"2026-10-01","at":"2026-10-01T08:00:00Z","cursor":{"new_base":"aaa","new_remaining":8,"old_remaining":20,"completed_new":1,"completed_old":5,"old_index":3}}
{"date":"2026-10-02","at":"2026-10-02T08:00:00Z","cursor":{"new_base":"bbb","new_remaining":0,"old_remaining":200,"completed_new":2,"completed_old":15,"old_index":0}}
EOF
health_reset="$(python3 "$PY" health --jsonl "$tmp/health-reset.jsonl")"
assert_ok "a moved new_base is not catch-up" \
  grep -q 'not comparable' <<<"$health_reset"
assert_ok "a moved new_base is a generation restart" \
  grep -q 'Generation restarted' <<<"$health_reset"

cat >"$tmp/health-base.jsonl" <<'EOF'
{"date":"2026-10-01","at":"2026-10-01T08:00:00Z","cursor":{"new_base":"aaa","new_remaining":6,"old_remaining":40,"completed_new":1,"completed_old":4,"old_index":3,"old_len":40}}
{"date":"2026-10-02","at":"2026-10-02T08:00:00Z","cursor":{"new_base":"bbb","new_remaining":0,"old_remaining":30,"completed_new":2,"completed_old":4,"old_index":8,"old_len":40}}
EOF
health_base="$(python3 "$PY" health --jsonl "$tmp/health-base.jsonl")"
assert_ok "finishing the new queue is not a backlog restart" \
  bash -c '! printf "%s\n" "$1" | grep -q "Generation restarted"' _ "$health_base"
assert_ok "finishing the new queue still refuses a catch-up claim" \
  grep -q 'not comparable' <<<"$health_base"

cat >"$tmp/health-old.jsonl" <<'EOF'
{"date":"2026-10-01","at":"2026-10-01T08:00:00Z","cursor":{"new_base":"aaa","old_remaining":10}}
EOF
health_old="$(python3 "$PY" health --jsonl "$tmp/health-old.jsonl")"
assert_ok "a cursor without completed_new is unknown" \
  grep -q 'no measured catch rate' <<<"$health_old"

printf '%s\n' '{"new_base":"abc","new_skip":0,"old_index":0,"old_name":"","new_cap_used":false,"run_id":"7"}' >"$tmp/cap.json"
python3 "$PY" mark-cap --cursor "$tmp/cap.json" --elapsed 500 --budget 1000 --new-left 2 --old-left 2
assert_ok "half the budget with both sides left consumes the new cap" \
  grep -q '"new_cap_used": true' "$tmp/cap.json"
python3 "$PY" mark-cap --cursor "$tmp/cap.json" --elapsed 0 --budget 1000 --new-left 2 --old-left 2
assert_ok "a consumed new cap stays consumed for the rest of the night" \
  grep -q '"new_cap_used": true' "$tmp/cap.json"

cat >"$tmp/meta.json" <<'EOF'
{
  "packages": [
    {
      "name": "rbitcoin-primitives",
      "manifest_path": "/work/crates/rbitcoin-primitives/Cargo.toml",
      "dependencies": []
    },
    {
      "name": "rbitcoin-query",
      "manifest_path": "/work/crates/rbitcoin-query/Cargo.toml",
      "dependencies": [
        {"name": "rbitcoin-primitives", "kind": null}
      ]
    },
    {
      "name": "rbitcoin-mempool",
      "manifest_path": "/work/crates/rbitcoin-mempool/Cargo.toml",
      "dependencies": [
        {"name": "rbitcoin-primitives", "kind": "normal"}
      ]
    },
    {
      "name": "rbitcoin-net",
      "manifest_path": "/work/crates/rbitcoin-net/Cargo.toml",
      "dependencies": [
        {"name": "rbitcoin-primitives", "kind": "normal"},
        {"name": "rbitcoin-mempool", "kind": "normal"},
        {"name": "build-only", "kind": "build"}
      ]
    },
    {
      "name": "rbitcoin-node",
      "manifest_path": "/work/crates/rbitcoin-node/Cargo.toml",
      "dependencies": [
        {"name": "rbitcoin-net", "kind": "dev"}
      ]
    },
    {
      "name": "rbitcoin-bench",
      "manifest_path": "/work/crates/rbitcoin-bench/Cargo.toml",
      "dependencies": [
        {"name": "rbitcoin-net", "kind": "normal"}
      ]
    },
    {
      "name": "build-only",
      "manifest_path": "/work/crates/build-only/Cargo.toml",
      "dependencies": []
    }
  ]
}
EOF
pkg="$(python3 "$PY" package-for --metadata "$tmp/meta.json" --path crates/rbitcoin-net/src/a.rs)"
assert_ok "a source path maps to the package that owns the manifest" \
  test "$pkg" = "rbitcoin-net"
cone="$(python3 "$PY" dependents --metadata "$tmp/meta.json" --package rbitcoin-primitives)"
assert_ok "the reverse cone is transitive through normal and dev deps" \
  test "$cone" = "$(printf '%s\n' rbitcoin-mempool rbitcoin-net rbitcoin-node rbitcoin-query)"
assert_ok "bench is not a dependent" \
  bash -c '! printf "%s\n" "$1" | grep -q rbitcoin-bench' _ "$cone"
assert_ok "a build-dependency does not put the depender in the cone" \
  bash -c '! printf "%s\n" "$1" | grep -q "^build-only$" && ! printf "%s\n" "$1" | grep -q rbitcoin-net' _ \
  "$(python3 "$PY" dependents --metadata "$tmp/meta.json" --package build-only)"
assert_ok "a crate with no reverse deps has an empty cone" \
  test -z "$(python3 "$PY" dependents --metadata "$tmp/meta.json" --package rbitcoin-node)"
assert_ok "dependent timeout is five times the measured suite" \
  test "$(python3 "$PY" dependent-timeout --seconds 16)" = 80
assert_ok "dependent timeout floors at 60 seconds" \
  test "$(python3 "$PY" dependent-timeout --seconds 4)" = 60
assert_ok "dependent timeout ceilings at 1200 seconds" \
  test "$(python3 "$PY" dependent-timeout --seconds 1000)" = 1200
assert_fail "a non-positive measurement is not a timeout" \
  python3 "$PY" dependent-timeout --seconds 0

req='crates/rbitcoin-net/src/a.rs:1:1: replace == with != in f'
extra='crates/rbitcoin-net/src/a.rs:9:1: delete field x in Foo'
caught_extra='crates/rbitcoin-net/src/a.rs:8:1: delete field y in Foo'
kept='crates/rbitcoin-net/src/a.rs:2:1: replace > with == in g'
caught_name='crates/rbitcoin-net/src/a.rs:3:1: replace || with && in h'
timed='crates/rbitcoin-net/src/a.rs:4:1: replace wait with () in i'
unviable_name='crates/rbitcoin-net/src/a.rs:6:1: replace arm with () in k'
printf '%s\n' "$req" "$kept" "$caught_name" "$timed" "$unviable_name" >"$tmp/requested.txt"
cat >"$tmp/phase1.log" <<EOF
MISSED   $extra in 4s build + 8s test
MISSED   $caught_extra in 4s build + 8s test
MISSED   $req in 6s build + 12s test
MISSED   $kept in 6s build + 12s test
MISSED   $caught_name in 6s build + 12s test
MISSED   $timed in 6s build + 12s test
MISSED   $unviable_name in 6s build + 12s test
caught   crates/rbitcoin-net/src/a.rs:5:1: replace x with y in j in 6s build + 12s test
TIMEOUT  crates/rbitcoin-net/src/a.rs:7:1: delete field z in Foo in 6s build + 1200s test
EOF
cat >"$tmp/phase2.log" <<EOF
caught   $caught_name in 9s build + 40s test
caught   $caught_extra in 9s build + 40s test
TIMEOUT  $timed in 9s build + 400s test
unviable $unviable_name in 9s build + 1s test
MISSED   $req in 9s build + 40s test
EOF
python3 "$PY" reconcile-missed --phase1 "$tmp/phase1.log" --phase2 "$tmp/phase2.log" \
  --slice "$tmp/requested.txt" >"$tmp/reconciled.txt"
assert_ok "an unrequested struct-field miss is kept when phase 2 did not catch it" \
  grep -q "$extra" "$tmp/reconciled.txt"
assert_ok "a phase-2 catch of an unrequested delete is not a miss" \
  bash -c '! grep -q "$1" "$2"' _ "$caught_extra" "$tmp/reconciled.txt"
assert_ok "a phase-2 miss is kept" \
  grep -q "$req" "$tmp/reconciled.txt"
assert_ok "a requested miss that phase 2 did not run is kept" \
  grep -q "$kept" "$tmp/reconciled.txt"
assert_ok "a phase-2 catch is not a miss" \
  bash -c '! grep -q "$1" "$2"' _ "$caught_name" "$tmp/reconciled.txt"
assert_ok "a phase-2 timeout keeps the crate miss" \
  grep -q "$timed" "$tmp/reconciled.txt"
assert_ok "a phase-2 unviable keeps the crate miss" \
  grep -q "$unviable_name" "$tmp/reconciled.txt"
python3 "$PY" reconcile-missed --phase1 "$tmp/phase1.log" --slice "$tmp/requested.txt" \
  >"$tmp/reconciled-open.txt"
assert_ok "with no phase-2 log every phase-1 miss is kept" \
  test "$(grep -c . "$tmp/reconciled-open.txt")" = 7
rerun="$(python3 "$PY" requested-misses --phase1 "$tmp/phase1.log" --slice "$tmp/requested.txt")"
assert_ok "only requested misses are rerun, in slice order" \
  test "$rerun" = "$(printf '%s\n' "$req" "$kept" "$caught_name" "$timed" "$unviable_name")"
printf '%s\n' 'already-caught' >"$tmp/caught.txt"
python3 "$PY" hide-unrequested --phase1 "$tmp/phase1.log" --slice "$tmp/requested.txt" \
  --caught "$tmp/caught.txt"
assert_ok "hide keeps names already in caught.txt" \
  grep -qx 'already-caught' "$tmp/caught.txt"
assert_ok "hide adds the unrequested miss so iterate will skip it" \
  grep -qx "$extra" "$tmp/caught.txt"
assert_ok "hide adds the unrequested timeout so iterate will skip it" \
  grep -qx 'crates/rbitcoin-net/src/a.rs:7:1: delete field z in Foo' "$tmp/caught.txt"
assert_ok "hide does not add a requested miss" \
  bash -c '! grep -qx "$1" "$2"' _ "$req" "$tmp/caught.txt"
python3 "$PY" hide-unrequested --phase1 "$tmp/phase1.log" --slice "$tmp/requested.txt" \
  --caught "$tmp/no-such-caught.txt"
assert_ok "hide does not create a caught.txt the crate run never wrote" \
  test ! -f "$tmp/no-such-caught.txt"
assert_ok "outcome-count is the number of result lines" \
  test "$(python3 "$PY" outcome-count --log "$tmp/phase2.log")" = 5

NIGHTLY="$ROOT/scripts/mutants-nightly.sh"
TOML="$ROOT/.cargo/mutants.toml"
assert_ok "nightly list excludes rbitcoin-bench" \
  bash -c 'grep -q -- "--exclude '"'"'crates/rbitcoin-bench/\*\*/\*.rs'"'"' --list" "$1"' _ "$NIGHTLY"
assert_ok "nightly run excludes rbitcoin-bench" \
  bash -c 'grep -q -- "--exclude '"'"'crates/rbitcoin-bench/\*\*/\*.rs'"'"'" "$1"' _ "$NIGHTLY"
assert_ok "mutants.toml excludes rbitcoin-bench" \
  grep -q 'crates/rbitcoin-bench/\*\*/\*.rs' "$TOML"
WF="$ROOT/.github/workflows/mutants.yml"
CI="$ROOT/.github/workflows/ci.yml"
assert_ok "nightly cron is 00:47 UTC" \
  grep -q 'cron: "47 0 \* \* \*"' "$WF"
assert_ok "workflow_dispatch remains" \
  grep -q 'workflow_dispatch:' "$WF"
assert_ok "ci does not run the nightly mutants script" \
  bash -c '! grep -q mutants-nightly.sh "$1"' _ "$CI"
assert_ok "nightly uses the queue regex helper" \
  grep -q 'mutants_queue.py" re' "$NIGHTLY"
assert_ok "nightly examines one file" \
  grep -q -- '--file' "$NIGHTLY"
assert_ok "nightly batches by file" \
  grep -q 'mutants_queue.py" file-batch' "$NIGHTLY"
assert_ok "nightly asks which side the next batch is" \
  grep -q 'mutants_queue.py" next-side' "$NIGHTLY"
assert_ok "nightly persists the new cap" \
  grep -q 'mutants_queue.py" mark-cap' "$NIGHTLY"
assert_ok "nightly advances one side" \
  grep -q 'mutants_queue.py" advance-side' "$NIGHTLY"
assert_ok "a finished backlog starts a fresh one at HEAD" \
  grep -q 'mutants_queue.py" rollover' "$NIGHTLY"
assert_ok "rollover runs only after the backlog file is consumed" \
  grep -q 'old_len > 0 && old_off >= old_len' "$NIGHTLY"
assert_ok "a finished backlog rolls over before a timeout stops the job" \
  awk '/mutants_queue.py" rollover/{r=NR} /ec == 124/{t=NR} END{exit !(r && t && r<t)}' "$NIGHTLY"
assert_ok "nightly records queue progress on the cursor" \
  grep -q 'mutants_queue.py" remember' "$NIGHTLY"
assert_ok "nightly progress ignores extra outcomes" \
  grep -q 'mutants_queue.py" progress' "$NIGHTLY"
assert_ok "same-file cursor copy is skipped" \
  grep -q -- '-ef' "$NIGHTLY"
assert_ok "crate run and dependent run are separate cargo mutants commands" \
  python3 -c '
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
cmds = []
buf = []
for line in text.splitlines():
    if buf:
        buf.append(line)
        if not line.rstrip().endswith("\\"):
            cmds.append(" ".join(part.strip().strip("\\") for part in buf))
            buf = []
        continue
    if "cargo mutants" in line and "--list" not in line:
        if line.rstrip().endswith("\\"):
            buf = [line]
        else:
            cmds.append(line.strip())
runs = [c for c in cmds if "cargo mutants" in c and "--list" not in c]
assert len(runs) == 2, runs
phase1, phase2 = runs
assert "--test-package" in phase1, phase1
assert "--baseline=skip" not in phase1, phase1
assert "--test-workspace" not in phase1, phase1
assert "--timeout" not in phase1, phase1
assert "--baseline=skip" in phase2, phase2
assert "--timeout" in phase2, phase2
assert "--iterate" in phase2, phase2
assert "--iterate" not in phase1, phase1
assert "--output" in phase1 and "--output" in phase2, (phase1, phase2)
assert "--test-workspace" not in phase2, phase2
assert "${dep_args[@]}" in phase2, phase2
assert "dep_args+=(--test-package" in text
for needle in ("package-for", "dependents", "dependent-timeout", "reconcile-missed", "requested-misses", "hide-unrequested", "outcome-count"):
    assert needle in text, needle
no_prog = text.find("dependents made no progress")
advance = text.find("advance-side")
assert 0 < no_prog < advance, (no_prog, advance)
phase2 = text.find("reconcile-missed --phase1 \"$log\" --phase2")
assert no_prog < phase2 < advance, (no_prog, phase2, advance)
between = text[text.find("deps_started=0"):phase2]
assert "deps_started == 1" in between
assert "[[ -f \"$deps_log\" ]]" not in text
assert "--test-workspace" not in text
assert "workspace-baseline.log" in text
' "$NIGHTLY"
assert_ok "one job budget is 4 hours" \
  grep -q 'MUTANTS_BUDGET_SEC:-14400' "$NIGHTLY"
assert_ok "missed mutants do not fail the nightly script" \
  grep -q 'MISSED (not a failure' "$NIGHTLY"
assert_ok "queued nights are not cancelled" \
  grep -q 'cancel-in-progress: false' "$WF"

assert_ok "two jobs sum to 8 hours and each timeout has 30 minutes of slack under 6 hours" \
  python3 -c '
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
budgets = text.count("MUTANTS_BUDGET_SEC: \"14400\"")
timeouts = text.count("timeout-minutes: 270")
assert budgets == 2, budgets
assert timeouts == 2, timeouts
assert 14400 * 2 == 8 * 3600
assert 270 <= 360
assert 270 >= 14400 // 60 + 30
' "$WF"

assert_ok "each mutant job restores the state branch before the queue and publishes it after" \
  python3 -c '
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
starts = [i for i, line in enumerate(lines) if line.startswith("  mutants-")]
assert len(starts) == 2, starts
starts.append(len(lines))
for a, b in zip(starts, starts[1:]):
    block = lines[a:b]
    def at(needle):
        for i, line in enumerate(block):
            if needle in line:
                return i
        return -1
    restore, run, publish = at("restore-mutants-state.sh"), at("mutants-nightly.sh"), at("publish-mutants-state.sh")
    assert 0 <= restore < run < publish, (restore, run, publish)
' "$WF"

assert_ok "artifact download is not the only cursor restore" \
  grep -q 'git fetch' "$ROOT/scripts/restore-mutants-state.sh"
assert_ok "state branch is mutants-state" \
  grep -q 'mutants-state' "$ROOT/scripts/publish-mutants-state.sh"
assert_ok "publisher refuses master" \
  grep -q 'master|main' "$ROOT/scripts/publish-mutants-state.sh"
assert_ok "publisher pushes only the state branch ref" \
  grep -q 'HEAD:${BRANCH}' "$ROOT/scripts/publish-mutants-state.sh"
assert_ok "workflow names the state branch" \
  grep -q 'MUTANTS_STATE_BRANCH: mutants-state' "$WF"
assert_ok "both jobs share one run id" \
  bash -c 'test "$(grep -c "github.run_id" "$1")" -ge 2' _ "$WF"
assert_ok "state publish has contents write" \
  grep -q 'contents: write' "$WF"

dry="$(MUTANTS_STATE_DRY_RUN=1 "$ROOT/scripts/publish-mutants-state.sh")"
assert_ok "dry-run names the state branch and the cursor" \
  grep -q 'mutants-state/cursor.json' <<<"$dry"
assert_ok "dry-run names the miss-list update" \
  grep -q 'missed.txt' <<<"$dry"
assert_ok "dry-run does not push" \
  grep -q 'no push' <<<"$dry"
assert_ok "dry-run does not check out or push master" \
  bash -c '! printf "%s\n" "$1" | grep -E -q "checkout master|HEAD:master|push origin master"' _ "$dry"

set +e
MUTANTS_STATE_DRY_RUN=1 MUTANTS_STATE_BRANCH=master \
  "$ROOT/scripts/publish-mutants-state.sh" >/dev/null 2>"$tmp/refuse.err"
refuse_ec=$?
set -e
assert_ok "dry-run refuses to publish master" test "$refuse_ec" -ne 0

bare="$(mktemp -d)"
git init --bare -q "$bare"
printf '%s\n' '{"new_base":"abc","new_skip":1,"old_index":2,"old_name":"crates/old/a.rs:1:1: replace a with b in o1","new_cap_used":true,"run_id":"42"}' >"$tmp/pub-cursor.json"
printf '%s\n' 'MISSED crates/old/a.rs:1:1: replace a with b in o1' >"$tmp/pub-missed.txt"
MUTANTS_STATE_PUBLISH=1 MUTANTS_STATE_PUSH_URL="$bare" MUTANTS_STATE_BRANCH=mutants-state \
  MUTANTS_RUN_ID=42 MUTANTS_PHASE=1 \
  "$ROOT/scripts/publish-mutants-state.sh" "$tmp/pub-cursor.json" "$tmp/pub-missed.txt" \
  >"$tmp/pub1.out"
printf '%s\n' 'MISSED crates/old/b.rs:2:1: replace a with b in o2' >"$tmp/pub-missed-2.txt"
printf '%s\n' '{"new_base":"abc","new_skip":1,"old_index":3,"old_name":"crates/old/b.rs:2:1: replace a with b in o2","new_cap_used":true,"run_id":"42"}' >"$tmp/pub-cursor-2.json"
MUTANTS_STATE_PUBLISH=1 MUTANTS_STATE_PUSH_URL="$bare" MUTANTS_STATE_BRANCH=mutants-state \
  MUTANTS_RUN_ID=42 MUTANTS_PHASE=2 \
  "$ROOT/scripts/publish-mutants-state.sh" "$tmp/pub-cursor-2.json" "$tmp/pub-missed-2.txt" \
  >"$tmp/pub2.out"
pub_clone="$(mktemp -d)"
git clone -q --branch mutants-state "$bare" "$pub_clone"
assert_ok "published cursor is the second job cursor" \
  grep -E -q '"old_index": ?3' "$pub_clone/cursor.json"
assert_ok "miss lines from both jobs are on the branch" \
  bash -c 'grep -q "o1" "$1/missed.txt" && grep -q "o2" "$1/missed.txt"' _ "$pub_clone"
assert_ok "publish did not create master" \
  bash -c '! git --git-dir="$1" show-ref --verify --quiet refs/heads/master' _ "$bare"
assert_ok "publish created mutants-state" \
  bash -c 'git --git-dir="$1" show-ref --verify --quiet refs/heads/mutants-state' _ "$bare"

set +e
MUTANTS_STATE_PUBLISH=1 MUTANTS_STATE_PUSH_URL="$tmp/not-a-remote" MUTANTS_STATE_BRANCH=mutants-state \
  "$ROOT/scripts/publish-mutants-state.sh" "$tmp/pub-cursor.json" "$tmp/pub-missed.txt" \
  >"$tmp/bad-push.out" 2>"$tmp/bad-push.err"
bad_ec=$?
set -e
assert_ok "a failed state publish exits non-zero" test "$bad_ec" -ne 0

# Branch cursor wins over a disagreeing artifact. Local origin remote, no network.
src="$(mktemp -d)"
git init -q -b master "$src"
git -C "$src" config user.email "mutants-test@example.com"
git -C "$src" config user.name "mutants-test"
echo seed >"$src/README"
git -C "$src" add README
git -C "$src" commit -q -m seed
git -C "$src" remote add origin "$bare"
# The bare repo already has mutants-state from the publisher. Point a fresh
# branch cursor at a different name than the artifact by cloning that history
# and replacing the file is unnecessary: fetch the published branch.
printf '%s\n' '{"old_index":1,"old_name":"from-artifact"}' >"$tmp/artifact-cursor.json"
(
  cd "$src"
  MUTANTS_ARTIFACT_CURSOR="$tmp/artifact-cursor.json" \
    "$ROOT/scripts/restore-mutants-state.sh" "$tmp/restored.json"
)
assert_ok "restore prefers the state branch over the artifact" \
  grep -E -q '"old_index": ?3' "$tmp/restored.json"
assert_ok "restore does not keep the disagreeing artifact cursor" \
  bash -c '! grep -q from-artifact "$1"' _ "$tmp/restored.json"

git --git-dir="$bare" update-ref -d refs/heads/mutants-state
(
  cd "$src"
  MUTANTS_ARTIFACT_CURSOR="$tmp/artifact-cursor.json" \
    "$ROOT/scripts/restore-mutants-state.sh" "$tmp/restored-art.json"
)
assert_ok "missing state branch falls back to the artifact" \
  grep -q 'from-artifact' "$tmp/restored-art.json"
(
  cd "$src"
  MUTANTS_ARTIFACT_CURSOR="$tmp/no-artifact.json" \
    "$ROOT/scripts/restore-mutants-state.sh" "$tmp/restored-empty.json"
)
assert_ok "missing branch and artifact start from an empty cursor" \
  grep -E -q '"old_index": ?0' "$tmp/restored-empty.json"

assert_ok "consensus mutants dependency is optional" \
  grep -q 'mutants = { version = "0.0.4", optional = true }' "$ROOT/crates/rbitcoin-consensus/Cargo.toml"
assert_ok "query mutants dependency is optional" \
  grep -q 'mutants = { version = "0.0.4", optional = true }' "$ROOT/crates/rbitcoin-query/Cargo.toml"
assert_ok "consensus mutants feature is the optional dep" \
  grep -q 'mutants = \["dep:mutants"\]' "$ROOT/crates/rbitcoin-consensus/Cargo.toml"
assert_ok "query mutants feature is the optional dep" \
  grep -q 'mutants = \["dep:mutants"\]' "$ROOT/crates/rbitcoin-query/Cargo.toml"
assert_ok "csv mask skip is behind the mutants feature" \
  grep -q 'cfg_attr(feature = "mutants", mutants::skip)' \
  "$ROOT/crates/rbitcoin-consensus/src/script/interpreter.rs"
assert_ok "parent stamp skip is behind the mutants feature" \
  grep -q 'cfg_attr(feature = "mutants", mutants::skip)' \
  "$ROOT/crates/rbitcoin-query/src/stamp.rs"
assert_ok "nightly list builds the mutants feature" \
  grep -q -- '--features mutants --workspace' "$NIGHTLY"
assert_ok "mutants.toml enables the mutants feature" \
  grep -q 'features = \["mutants"\]' "$TOML"
for toml in "$ROOT"/crates/*/Cargo.toml; do
  assert_ok "mutants feature in $(basename "$(dirname "$toml")")" \
    grep -q '^mutants = ' "$toml"
done
set +e
cargo tree -p rbitcoin-consensus -i mutants --prefix none >"$tmp/mutants-tree.txt" 2>&1
tree_ec=$?
set -e
assert_ok "default consensus build does not link mutants" test "$tree_ec" -ne 0
set +e
cargo tree -p rbitcoin-consensus --features mutants -i mutants --prefix none >"$tmp/mutants-on.txt" 2>&1
tree_on=$?
set -e
assert_ok "mutants feature links the attribute crate" test "$tree_on" -eq 0
assert_ok "mutants feature tree names the crate" grep -q '^mutants ' "$tmp/mutants-on.txt"

echo "$PASS passed, $FAIL failed"
test "$FAIL" -eq 0
