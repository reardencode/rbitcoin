#!/usr/bin/env bash
# Time-boxed workspace mutants. New lines since the cursor first, then a
# rotating backlog. One job spends the first half of its budget on new
# mutants when both queues still have work, then the backlog. A later job
# in the same night does not open another new window. When the backlog
# walk finishes, both cursors reset at HEAD and the full list is the next
# backlog; the job keeps walking that list for whatever budget remains.
# MISSED is written for humans; it does not fail the run.
# Owner: TESTING.md (Mutation testing).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# One cargo-mutants output directory per batch, outside the artifact tree.
# Removed when the next batch starts, and again when this script exits.
cm_parent=""
cleanup_cm() {
  if [[ -n "$cm_parent" ]]; then
    rm -rf "$cm_parent"
    cm_parent=""
  fi
}
trap cleanup_cm EXIT

# 4 hours for this job. The nightly workflow runs two of these, 8 hours
# total. One crate suite is the unit of work, and two of them in parallel
# do not fit a hosted runner, so this is -j 1. The job timeout is 30
# minutes longer so the script can stop itself and the workflow can
# publish the state branch. GitHub-hosted jobs cannot run longer than 6 hours.
BUDGET_SEC="${MUTANTS_BUDGET_SEC:-14400}"
# One cargo-mutants process per source file. 27.1.0 emits `..` struct
# field deletes without applying --re, so a workspace-wide --re batch
# retests every such delete. --file keeps that repeat inside this file.
# The cap is how many queued names from that file one process may take.
BATCH="${MUTANTS_BATCH:-200}"
CURSOR="${MUTANTS_CURSOR:-mutants-nightly/cursor.json}"
OUT="${MUTANTS_OUT:-mutants-nightly}"

mkdir -p "$OUT"
if [[ ! -f "$CURSOR" ]]; then
  printf '%s\n' '{"new_base":"","new_skip":0,"old_index":0,"old_name":"","new_cap_used":false,"run_id":""}' >"$CURSOR"
fi
python3 "$ROOT/scripts/mutants_queue.py" night --cursor "$CURSOR" --run-id "${MUTANTS_RUN_ID:-}"

new_base="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("new_base",""))' "$CURSOR")"
new_skip="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1])).get("new_skip",0)))' "$CURSOR")"
old_index="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1])).get("old_index",0)))' "$CURSOR")"

if [[ -z "$new_base" ]] || ! git rev-parse --verify "${new_base}^{commit}" >/dev/null 2>&1; then
  new_base="$(git rev-list -n 1 --before="24 hours ago" HEAD || true)"
  if [[ -z "$new_base" ]]; then
    new_base="$(git rev-parse HEAD)"
  fi
  new_skip=0
  python3 - "$CURSOR" "$new_base" <<'PY'
import json, sys
path, base = sys.argv[1], sys.argv[2]
cur = json.load(open(path))
cur["new_base"] = base
cur["new_skip"] = 0
json.dump(cur, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY
fi

head_sha="$(git rev-parse HEAD)"
git diff "$new_base"..HEAD --unified=0 -- crates >"$OUT/new.diff" || true

echo "mutants-nightly: listing workspace mutants"
# rbitcoin-bench is an optional host client, not a mutants gate.
# CLI --exclude replaces exclude_globs in .cargo/mutants.toml (same glob).
cargo mutants --features mutants --workspace --exclude 'crates/rbitcoin-bench/**/*.rs' --list >"$OUT/all.txt"

read -r n_new n_old < <(python3 "$ROOT/scripts/mutants_queue.py" split \
  --list "$OUT/all.txt" --diff "$OUT/new.diff" \
  --cursor "$CURSOR" --head "$head_sha" \
  --out-new "$OUT/new.txt" --out-old "$OUT/old.txt")
new_skip="$(python3 "$ROOT/scripts/mutants_queue.py" show --cursor "$CURSOR" --key new_skip)"
old_index="$(python3 "$ROOT/scripts/mutants_queue.py" show --cursor "$CURSOR" --key old_index)"
new_cap="$(python3 "$ROOT/scripts/mutants_queue.py" show --cursor "$CURSOR" --key new_cap_used)"

echo "mutants-nightly: new=$n_new skip=$new_skip old=$n_old index=$old_index budget=${BUDGET_SEC}s new_cap=$new_cap"

: >"$OUT/missed.txt"
: >"$OUT/ran.txt"
completed_total=0
completed_new=0
completed_old=0

new_len="$(grep -c . "$OUT/new.txt" || true)"
old_len="$(grep -c . "$OUT/old.txt" || true)"
new_off=0
old_off=0
start=$SECONDS
deadline=$((start + BUDGET_SEC))

# One green workspace run per job. It does not warm the mutants scratch
# tree. Phase 2's timeout is five times the test half of this run.
echo "mutants-nightly: workspace baseline"
set +e
cargo test --no-run --features mutants --workspace --exclude rbitcoin-bench \
  >"$OUT/workspace-baseline.log" 2>&1
build_ec=$?
set -e
if ((build_ec != 0)); then
  echo "mutants-nightly: workspace baseline did not build (exit $build_ec)"
  exit "$build_ec"
fi
test_start=$SECONDS
set +e
cargo test --features mutants --workspace --exclude rbitcoin-bench \
  >>"$OUT/workspace-baseline.log" 2>&1
test_ec=$?
set -e
measured=$((SECONDS - test_start))
if ((test_ec != 0)); then
  echo "mutants-nightly: workspace baseline failed (exit $test_ec)"
  exit "$test_ec"
fi
if ((measured < 1)); then
  measured=1
fi
DEP_TIMEOUT="$(python3 "$ROOT/scripts/mutants_queue.py" dependent-timeout --seconds "$measured")"
echo "mutants-nightly: workspace tests took ${measured}s; dependent timeout ${DEP_TIMEOUT}s"
cargo metadata --format-version 1 >"$OUT/metadata.json"
while ((SECONDS < deadline)); do
  remain=$((deadline - SECONDS))
  if ((remain < 60)); then
    break
  fi
  elapsed=$((SECONDS - start))
  new_left=$((new_len - new_off))
  old_left=$((old_len - old_off))
  python3 "$ROOT/scripts/mutants_queue.py" mark-cap \
    --cursor "$CURSOR" --elapsed "$elapsed" --budget "$BUDGET_SEC" \
    --new-left "$new_left" --old-left "$old_left"
  new_cap="$(python3 "$ROOT/scripts/mutants_queue.py" show --cursor "$CURSOR" --key new_cap_used)"
  side="$(python3 "$ROOT/scripts/mutants_queue.py" next-side \
    --elapsed "$elapsed" --budget "$BUDGET_SEC" \
    --new-left "$new_left" --old-left "$old_left" \
    --new-cap-used "$new_cap")"
  if [[ -z "$side" ]]; then
    break
  fi
  if [[ "$side" == "new" ]]; then
    queue="$OUT/new.txt"
    offset=$new_off
  else
    queue="$OUT/old.txt"
    offset=$old_off
  fi
  slice="$OUT/batch-$side-$offset.names"
  python3 "$ROOT/scripts/mutants_queue.py" file-batch \
    --queue "$queue" --offset "$offset" --cap "$BATCH" >"$slice"
  requested="$(grep -c . "$slice" || true)"
  if ((requested == 0)); then
    break
  fi
  file="$(head -n 1 "$slice" | cut -d: -f1)"
  cleanup_cm
  cm_parent="$(mktemp -d)"
  RE_ARGS=(--file "$file")
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    escaped="$(python3 "$ROOT/scripts/mutants_queue.py" re "$line")"
    RE_ARGS+=(--re "$escaped")
  done <"$slice"
  pkg="$(python3 "$ROOT/scripts/mutants_queue.py" package-for --metadata "$OUT/metadata.json" --path "$file")"
  log="$OUT/batch-$side-$offset.log"
  echo "mutants-nightly: batch side=$side at $offset ($requested mutants in $file, package $pkg, ${remain}s left)"
  # This crate only. cargo-mutants runs the unmutated suite once and times out at 5× that.
  set +e
  timeout --signal=TERM --kill-after=60s "$remain" \
    cargo mutants --features mutants --workspace --exclude 'crates/rbitcoin-bench/**/*.rs' \
      --test-package "$pkg" --caught --unviable \
      --output "$cm_parent" \
      -j 1 \
      "${RE_ARGS[@]}" \
      >"$log" 2>&1
  ec=$?
  set -e
  # A clean exit consumed the slice. A killed process counts only the
  # requested names that printed an outcome, in order. Unfiltered
  # struct-field deletes in this file do not advance the cursor.
  if ((ec == 0)); then
    step=$requested
  else
    step="$(python3 "$ROOT/scripts/mutants_queue.py" progress --log "$log" --slice "$slice")"
    if ((step > requested)); then
      step=$requested
    fi
    if ((step == 0)); then
      python3 "$ROOT/scripts/mutants_queue.py" reconcile-missed --phase1 "$log" --slice "$slice" \
        >>"$OUT/missed.txt"
      echo "mutants-nightly: batch made no progress (exit $ec); same queue next night"
      break
    fi
  fi
  deps_ec=0
  deps_started=0
  deps_log="$OUT/batch-$side-$offset-deps.log"
  if ((ec != 124)); then
    remain=$((deadline - SECONDS))
    python3 "$ROOT/scripts/mutants_queue.py" requested-misses --phase1 "$log" --slice "$slice" \
      >"$OUT/batch-$side-$offset.misses"
    python3 "$ROOT/scripts/mutants_queue.py" dependents --metadata "$OUT/metadata.json" --package "$pkg" \
      >"$OUT/batch-$side-$offset.deps"
    if ((remain >= 60)) && [[ -s "$OUT/batch-$side-$offset.misses" && -s "$OUT/batch-$side-$offset.deps" ]]; then
      dep_args=()
      while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue
        dep_args+=(--test-package "$dep")
      done <"$OUT/batch-$side-$offset.deps"
      miss_re=(--file "$file")
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        escaped="$(python3 "$ROOT/scripts/mutants_queue.py" re "$line")"
        miss_re+=(--re "$escaped")
      done <"$OUT/batch-$side-$offset.misses"
      if ((${#dep_args[@]} > 0)); then
        # 27.1.0 still runs `..` struct-field deletes under --file. --iterate
        # skips names in caught.txt. Add every phase-1 name that is not a
        # requested miss so those deletes are not run again.
        python3 "$ROOT/scripts/mutants_queue.py" hide-unrequested \
          --phase1 "$log" --slice "$slice" \
          --caught "$cm_parent/mutants.out/caught.txt"
        echo "mutants-nightly: dependents for $pkg ($(wc -l <"$OUT/batch-$side-$offset.misses") misses, ${remain}s left)"
        set +e
        timeout --signal=TERM --kill-after=60s "$remain" \
          cargo mutants --features mutants --workspace --exclude 'crates/rbitcoin-bench/**/*.rs' \
            --baseline=skip --timeout "$DEP_TIMEOUT" --caught --unviable \
            --output "$cm_parent" --iterate \
            -j 1 "${dep_args[@]}" \
            "${miss_re[@]}" \
            >"$deps_log" 2>&1
        deps_ec=$?
        deps_started=1
        set -e
      fi
    fi
  fi
  if ((deps_started == 1)); then
    deps_outcomes="$(python3 "$ROOT/scripts/mutants_queue.py" outcome-count --log "$deps_log")"
    if ((deps_outcomes == 0)); then
      echo "mutants-nightly: dependents made no progress (exit $deps_ec); same queue next night"
      break
    fi
    python3 "$ROOT/scripts/mutants_queue.py" reconcile-missed --phase1 "$log" --phase2 "$deps_log" \
      --slice "$slice" >>"$OUT/missed.txt"
  else
    python3 "$ROOT/scripts/mutants_queue.py" reconcile-missed --phase1 "$log" --slice "$slice" \
      >>"$OUT/missed.txt"
  fi
  if [[ "$side" == "new" ]]; then
    new_off=$((new_off + step))
    completed_new=$((completed_new + step))
  else
    old_off=$((old_off + step))
    completed_old=$((completed_old + step))
  fi
  now=$((SECONDS - start))
  python3 "$ROOT/scripts/mutants_queue.py" advance-side \
    --cursor "$CURSOR" --side "$side" --completed "$step" \
    --n-new "$n_new" --n-old "$n_old" --head "$head_sha" \
    --old-queue "$OUT/old.txt" --old-offset "$old_off" \
    --elapsed "$now" --budget "$BUDGET_SEC" \
    --new-left "$((new_len - new_off))" --old-left "$((old_len - old_off))"
  completed_total=$((completed_total + step))
  if ((old_len > 0 && old_off >= old_len)); then
    echo "mutants-nightly: backlog finished; fresh backlog at ${head_sha}"
    read -r n_new n_old < <(python3 "$ROOT/scripts/mutants_queue.py" rollover \
      --cursor "$CURSOR" --list "$OUT/all.txt" --head "$head_sha" \
      --out-new "$OUT/new.txt" --out-old "$OUT/old.txt")
    new_len="$(grep -c . "$OUT/new.txt" || true)"
    old_len="$(grep -c . "$OUT/old.txt" || true)"
    new_off=0
    old_off=0
    if ((new_len == 0 && old_len == 0)); then
      break
    fi
  fi
  if ((ec == 124 || deps_ec == 124)); then
    echo "mutants-nightly: budget exhausted after $completed_total mutants"
    break
  fi
done

python3 "$ROOT/scripts/mutants_queue.py" mark-cap \
  --cursor "$CURSOR" --elapsed "$((SECONDS - start))" --budget "$BUDGET_SEC" \
  --new-left "$((new_len - new_off))" --old-left "$((old_len - old_off))"
python3 "$ROOT/scripts/mutants_queue.py" remember \
  --cursor "$CURSOR" \
  --new-len "$n_new" --old-len "$n_old" \
  --new-remaining "$((new_len - new_off))" \
  --old-remaining "$((old_len - old_off))" \
  --completed-new "$completed_new" --completed-old "$completed_old"

# The default cursor path already lives in the artifact directory.
if [[ ! "$CURSOR" -ef "$OUT/cursor.json" ]]; then
  cp "$CURSOR" "$OUT/cursor.json"
fi
echo "mutants-nightly: completed=$completed_total missed=$(grep -c . "$OUT/missed.txt" || true)"
if [[ -s "$OUT/missed.txt" ]]; then
  echo "mutants-nightly: MISSED (not a failure; extend a journey or delete the expression)"
  cat "$OUT/missed.txt"
fi
