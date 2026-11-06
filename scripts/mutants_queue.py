#!/usr/bin/env python3
"""Order cargo-mutants names: changed lines first, then a rotating backlog.

The nightly job runs a time budget of these names. A file batch runs that
crate's tests. A miss is run again against the packages that link the crate.
A cursor remembers how far the new-code prefix and the old rotation got.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
# Rust regex meta. `<` and `>` are not in this set: `\<` and `\>` are
# word-boundary assertions in the regex crate, not literals.
RUST_META = set(r"\.+*?()|[]{}^$#&-~")
FINISHED = re.compile(r"(?m)^(\d+) mutants tested\b")
OUTCOME = re.compile(r"^(caught|MISSED|TIMEOUT|unviable)\b")


def parse_mutant(line: str) -> tuple[str, int, str] | None:
    parts = line.split(":", 3)
    if len(parts) < 4:
        return None
    path, line_no, _col, _rest = parts
    try:
        return path, int(line_no), line
    except ValueError:
        return None


def changed_lines(diff_text: str) -> set[tuple[str, int]]:
    """New-file line numbers touched by a ``git diff -U0``."""
    path = ""
    new_line = 0
    touched: set[tuple[str, int]] = set()
    for raw in diff_text.splitlines():
        if raw.startswith("+++ b/"):
            path = raw[6:]
            continue
        if raw.startswith("+++ /dev/null"):
            path = ""
            continue
        match = HUNK.match(raw)
        if match:
            new_line = int(match.group(1))
            continue
        if not path or raw.startswith(("diff ", "index ", "--- ")):
            continue
        if raw.startswith("+"):
            touched.add((path, new_line))
            new_line += 1
        elif raw.startswith("-"):
            continue
        elif raw.startswith("\\"):
            continue
        else:
            new_line += 1
    return touched


def load_mutants(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if parse_mutant(line):
            out.append(line)
    return out


def partition(mutants: list[str], changed: set[tuple[str, int]]) -> tuple[list[str], list[str]]:
    new: list[str] = []
    old: list[str] = []
    for line in mutants:
        parsed = parse_mutant(line)
        if parsed and (parsed[0], parsed[1]) in changed:
            new.append(line)
        else:
            old.append(line)
    return new, old


def resume_old(old: list[str], old_index: int, old_name: str) -> tuple[list[str], int]:
    """Rotate ``old`` so the walk starts at ``old_name``, else at ``old_index``.

    A name that is still in the regenerated list wins over the integer. A
    name that is gone uses ``old_index`` modulo the current length, not zero.
    """
    if not old:
        return [], 0
    if old_name:
        for i, line in enumerate(old):
            if line == old_name:
                return old[i:] + old[:i], i
    start = old_index % len(old)
    return old[start:] + old[:start], start


def order(mutants: list[str], changed: set[tuple[str, int]], old_index: int) -> tuple[list[str], list[str]]:
    new, old = partition(mutants, changed)
    rotated, _start = resume_old(old, old_index, "")
    return new, rotated


def next_side(
    elapsed: int,
    budget: int,
    new_remaining: bool,
    old_remaining: bool,
    new_cap_used: bool,
) -> str:
    """Which queue the next file-batch comes from.

    New work goes first until half of this job's budget has elapsed, or
    until this night already used that half. An empty side does not block
    the other. A batch already started is not cancelled here; the caller
    asks again after it finishes, and that next batch is the other side.
    """
    if budget < 1 or elapsed < 0:
        raise ValueError("budget")
    if not new_remaining and not old_remaining:
        return ""
    if new_remaining and not old_remaining:
        return "new"
    if old_remaining and not new_remaining:
        return "old"
    if new_cap_used or elapsed >= budget // 2:
        return "old"
    return "new"


def cap_consumed(elapsed: int, budget: int, new_left: int, old_left: int, already: bool) -> bool:
    """True once this night's new window is spent and backlog work remains.

    An empty side does not burn the window: the other side may use the
    whole job. ``already`` stays set for a later job in the same night so
    that job does not open a second new window.
    """
    if already:
        return True
    if new_left <= 0 or old_left <= 0:
        return False
    if budget < 1 or elapsed < 0:
        raise ValueError("budget")
    return elapsed >= budget // 2


def schedule(
    new: list[str],
    old: list[str],
    budget: int,
    batch_sec: int,
    cap: int,
    new_cap_used: bool,
) -> list[tuple[str, int, str]]:
    """Fake-clock walk used by the queue self-test and the same side rule as the job.

    Each file-batch starts at the current elapsed second and then advances
    the clock by ``batch_sec``. Names in a batch that started before half
    the budget stay on that side.
    """
    if batch_sec < 1:
        raise ValueError("batch-sec")
    new_q = [line.strip() for line in new if parse_mutant(line.strip())]
    old_q = [line.strip() for line in old if parse_mutant(line.strip())]
    elapsed = 0
    used = new_cap_used
    rows: list[tuple[str, int, str]] = []
    while elapsed < budget and (new_q or old_q):
        used = cap_consumed(elapsed, budget, len(new_q), len(old_q), used)
        side = next_side(elapsed, budget, bool(new_q), bool(old_q), used)
        if not side:
            break
        src = new_q if side == "new" else old_q
        batch = file_batch(src, 0, cap)
        if not batch:
            break
        for name in batch:
            rows.append((side, elapsed, name))
        del src[: len(batch)]
        elapsed += batch_sec
    return rows


def begin_night(cursor: dict, run_id: str) -> None:
    """Clear the new-mutant cap when ``run_id`` is a different night.

    An empty ``run_id`` is a local run: the cap starts unused. The same
    id across two jobs keeps a cap the earlier job already consumed.
    """
    if run_id:
        if str(cursor.get("run_id", "")) != run_id:
            cursor["new_cap_used"] = False
            cursor["run_id"] = run_id
    else:
        cursor["new_cap_used"] = False


def read_cursor(path: Path) -> dict:
    return json.loads(path.read_text())


def write_cursor(path: Path, cursor: dict) -> None:
    path.write_text(json.dumps(cursor, indent=2) + "\n")


def rust_re_exact(line: str) -> str:
    """One cargo-mutants ``--list`` line, anchored for ``--re``.

    ``re.escape`` is the wrong escaper: it emits ``\\<`` and ``\\>``, and the
    Rust regex crate treats those as word boundaries.
    """
    body = "".join("\\" + c if c in RUST_META else c for c in line)
    return f"^{body}$"


def file_batch(lines: list[str], offset: int, cap: int) -> list[str]:
    """Queue lines from ``offset`` that share one path, at most ``cap``.

    cargo-mutants 27.1.0 emits ``..`` struct field deletes without applying
    ``--re``. One source file per invocation keeps that repeat inside the
    file under test.
    """
    if offset < 0 or cap < 1:
        raise ValueError("file batch")
    queued = [line.strip() for line in lines if parse_mutant(line.strip())]
    if offset >= len(queued):
        return []
    path = parse_mutant(queued[offset])[0]
    out: list[str] = []
    for line in queued[offset:]:
        if parse_mutant(line)[0] != path or len(out) >= cap:
            break
        out.append(line)
    return out


_OUTCOME_NAME = re.compile(
    r"^(?:caught|MISSED|TIMEOUT|unviable)\s+(.*?)\s+in \d"
)


def prefix_progress(log: str, requested: list[str]) -> int:
    """How far into ``requested`` the log got, in order.

    Outcome lines for other mutants (the unfiltered struct-field deletes)
    do not count, and a later hit does not skip a hole.
    """
    done: set[str] = set()
    for raw in log.splitlines():
        match = _OUTCOME_NAME.match(raw.strip())
        if match:
            done.add(match.group(1))
    count = 0
    for line in requested:
        name = line.strip()
        if not name:
            continue
        if name not in done:
            break
        count += 1
    return count


def _norm_path(path: str) -> str:
    return path.replace("\\", "/").rstrip("/")


def package_for(metadata: dict, source_path: str) -> str:
    """Package whose manifest directory contains ``source_path``.

    Manifest paths in cargo metadata are absolute. Mutant names use a path
    relative to the workspace, so a relative source matches the suffix of
    the manifest directory. The longest match wins.
    """
    src = _norm_path(source_path)
    best_name = ""
    best_len = -1
    for pkg in metadata.get("packages", []):
        manifest = _norm_path(str(pkg.get("manifest_path", "")))
        if not manifest.endswith("/Cargo.toml"):
            continue
        man_dir = manifest[: -len("/Cargo.toml")]
        score = -1
        if src == man_dir or src.startswith(man_dir + "/"):
            score = len(man_dir)
        else:
            parts = man_dir.split("/")
            for i in range(len(parts)):
                tail = "/".join(parts[i:])
                if tail and (src == tail or src.startswith(tail + "/")):
                    score = len(tail)
                    break
        if score > best_len:
            best_len = score
            best_name = str(pkg.get("name", ""))
    if best_len < 0 or not best_name:
        raise ValueError(f"no package for {source_path}")
    return best_name


def _dep_names(pkg: dict) -> set[str]:
    """Normal and dev dependency package names. Build-dependencies are not linked by tests."""
    names: set[str] = set()
    for dep in pkg.get("dependencies", []):
        kind = dep.get("kind")
        if kind not in (None, "normal", "dev"):
            continue
        name = dep.get("name")
        if name:
            names.add(str(name))
    return names


def dependents(metadata: dict, package: str) -> list[str]:
    """Packages that link ``package``, transitively, through normal or dev deps.

    The package itself is not included. ``rbitcoin-bench`` is not included
    and is not walked through.
    """
    rev: dict[str, set[str]] = {}
    for pkg in metadata.get("packages", []):
        name = str(pkg.get("name", ""))
        if not name:
            continue
        rev.setdefault(name, set())
        if name == "rbitcoin-bench":
            continue
        for dep_name in _dep_names(pkg):
            rev.setdefault(dep_name, set()).add(name)
    seen: set[str] = set()
    stack = list(rev.get(package, ()))
    out: list[str] = []
    while stack:
        name = stack.pop()
        if name in seen or name == package or name == "rbitcoin-bench":
            continue
        seen.add(name)
        out.append(name)
        stack.extend(rev.get(name, ()))
    return sorted(out)


def dependent_timeout(measured_test_seconds: int) -> int:
    """Five times a green workspace test run, floored at 60s and capped at 20 minutes."""
    if measured_test_seconds <= 0:
        raise ValueError("measured test seconds")
    return min(1200, max(60, 5 * measured_test_seconds))


def _outcomes(log: str) -> list[tuple[str, str, str]]:
    found = []
    for raw in log.splitlines():
        match = _OUTCOME_NAME.match(raw.strip())
        if not match:
            continue
        kind = raw.strip().split(None, 1)[0]
        found.append((kind, match.group(1), raw.strip()))
    return found


def requested_misses(phase1: str, requested: list[str]) -> list[str]:
    """Requested names phase 1 logged as MISSED, in slice order."""
    missed = {name for kind, name, _raw in _outcomes(phase1) if kind == "MISSED"}
    return [line.strip() for line in requested if line.strip() and line.strip() in missed]


def reconcile_missed(phase1: str, phase2: str, requested: list[str]) -> list[str]:
    """Miss lines after the crate run and, when present, the dependent run.

    A phase-2 catch drops the name, including an unrequested struct-field
    delete that the dependent run happened to catch. A timeout, an unviable
    result, a phase-2 miss, or no phase-2 line keeps the crate miss. A
    phase-2 miss uses the phase-2 line.
    """
    wanted = {line.strip() for line in requested if line.strip()}
    phase2_kind = {name: kind for kind, name, _raw in _outcomes(phase2)}
    phase2_miss = {
        name: raw for kind, name, raw in _outcomes(phase2) if kind == "MISSED"
    }
    kept: list[str] = []
    for kind, name, raw in _outcomes(phase1):
        if kind != "MISSED":
            continue
        later = phase2_kind.get(name)
        if later == "caught":
            continue
        if name in wanted and later == "MISSED":
            kept.append(phase2_miss[name])
            continue
        kept.append(raw)
    return kept


def outcome_count(log: str) -> int:
    """How many caught, missed, timeout, or unviable lines a log has."""
    return len(_outcomes(log))


def hide_unrequested(phase1: str, requested: list[str], caught_text: str) -> str:
    """Caught-list text that tells ``--iterate`` to skip names we will not rerun.

    Requested misses stay off the list so the dependent run still tests them.
    Every other phase-1 name is added. cargo-mutants 27.1.0 still generates
    ``..`` struct-field deletes when ``--file`` is set, and ``--re`` does not
    filter those, so the caught list is what keeps them out of the next run.
    """
    rerun = set(requested_misses(phase1, requested))
    have = [line for line in caught_text.splitlines() if line.strip()]
    seen = set(have)
    for _kind, name, _raw in _outcomes(phase1):
        if name in rerun or name in seen:
            continue
        have.append(name)
        seen.add(name)
    if not have:
        return ""
    return "\n".join(have) + "\n"


def finished_mutants(log: str) -> int:
    """How many mutants a cargo-mutants batch actually finished.

    Caught and unviable mutants are not printed as their own lines unless
    ``--caught`` / ``--unviable`` are on. The summary line counts them.
    A batch killed before that line falls back to the outcome lines that
    were printed.
    """
    found = FINISHED.findall(log)
    if found:
        return int(found[-1])
    return sum(1 for line in log.splitlines() if OUTCOME.match(line))


def rollover(cursor: dict, mutants: list[str], head: str) -> tuple[list[str], list[str]]:
    """The backlog generation is finished. Start the next one at ``head``.

    ``new_base`` becomes HEAD and ``new_skip`` is cleared, so the diff is
    empty and every listed mutant is backlog. ``old_index`` starts at the
    first name. The night cap and run id stay; they are not cursors.
    """
    names = [line.strip() for line in mutants if parse_mutant(line.strip())]
    cursor["new_base"] = head
    cursor["new_skip"] = 0
    cursor["old_index"] = 0
    cursor["old_name"] = names[0] if names else ""
    cursor["new_len"] = 0
    cursor["old_len"] = len(names)
    cursor["new_remaining"] = 0
    cursor["old_remaining"] = len(names)
    return [], names


def remember(
    cursor: dict,
    new_len: int,
    old_len: int,
    new_remaining: int,
    old_remaining: int,
    completed_new: int,
    completed_old: int,
) -> None:
    """Record this job's queue sizes and how many mutants it examined."""
    counts = (
        new_len,
        old_len,
        new_remaining,
        old_remaining,
        completed_new,
        completed_old,
    )
    if any(n < 0 for n in counts):
        raise ValueError("remember")
    cursor["new_len"] = new_len
    cursor["old_len"] = old_len
    cursor["new_remaining"] = new_remaining
    cursor["old_remaining"] = old_remaining
    cursor["completed_new"] = completed_new
    cursor["completed_old"] = completed_old


def _health_nights(entries: list[dict]) -> list[dict]:
    rows = []
    for entry in entries:
        if not isinstance(entry, dict) or "date" not in entry or "cursor" not in entry:
            raise ValueError("health")
        rows.append(entry)
    rows.sort(key=lambda entry: (str(entry.get("at") or entry["date"]), str(entry["date"])))
    nights: list[dict] = []
    for entry in rows:
        date = str(entry["date"])
        if nights and nights[-1]["date"] == date:
            nights[-1]["cursors"].append(entry["cursor"])
        else:
            nights.append({"date": date, "cursors": [entry["cursor"]]})
    return nights


def _sum_key(cursors: list[dict], key: str) -> int | None:
    total = 0
    found = False
    for cursor in cursors:
        if key in cursor and cursor[key] is not None:
            total += int(cursor[key])
            found = True
    return total if found else None


def _last_key(cursors: list[dict], key: str):
    for cursor in reversed(cursors):
        if key in cursor and cursor[key] is not None:
            return cursor[key]
    return None


def _latest(nights: list[dict], key: str):
    for night in reversed(nights):
        value = _last_key(night["cursors"], key)
        if value is not None:
            return value
    return None


def _generation_restarted(prev: dict, cur: dict) -> bool:
    """True when ``cur`` is a new backlog, not merely a finished new queue."""
    previous_base = prev.get("new_base")
    current_base = cur.get("new_base")
    if not previous_base or not current_base or previous_base == current_base:
        return False
    if int(cur.get("old_index", -1)) == 0:
        return True
    if "old_len" in cur and "old_len" in prev and int(cur["old_len"]) > int(prev["old_len"]):
        return True
    if (
        "old_remaining" in cur
        and "old_remaining" in prev
        and int(cur["old_remaining"]) > int(prev["old_remaining"])
    ):
        return True
    return False


def health_report(entries: list[dict]) -> str:
    """How the new queue and the backlog moved across published cursors.

    One UTC date is one night. Jobs that share a date add their
    ``completed_new`` and ``completed_old`` counts. The later cursor that
    night supplies the remaining work. A night that omits a completed
    count is unknown, not zero.

    Outstanding new work is comparable only while ``new_base`` stays put.
    A moved base means that queue was closed or folded into a new
    backlog. Folding the backlog (index cleared, or the backlog longer
    or larger than the night before) is a generation restart: days left
    describe the new backlog, and the refill is not lost progress.
    """
    if not entries:
        return "No cursor history."
    nights = _health_nights(entries)
    lines: list[str] = []

    measured_new = []
    for night in nights:
        done = _sum_key(night["cursors"], "completed_new")
        if done is not None:
            measured_new.append(done)
    outstanding = _latest(nights, "new_remaining")
    outstanding_text = "unknown" if outstanding is None else str(int(outstanding))
    if not measured_new:
        lines.append("New: no measured catch rate (completed_new missing).")
    else:
        rate = sum(measured_new) / len(measured_new)
        span = "1 night" if len(measured_new) == 1 else f"{len(measured_new)} nights"
        lines.append(
            f"New: catch rate {rate:.1f} mutants/night over {span}. Outstanding {outstanding_text}."
        )

    with_remaining = []
    for night in nights:
        remaining = _last_key(night["cursors"], "new_remaining")
        if remaining is None:
            continue
        base = _last_key(night["cursors"], "new_base")
        with_remaining.append((int(remaining), "" if base is None else str(base)))
    if len(with_remaining) < 2:
        lines.append("New: Trend needs another night.")
    else:
        bases = {base for _remaining, base in with_remaining if base}
        if len(bases) > 1:
            lines.append("New: new_base moved, so outstanding is not comparable.")
        else:
            net = (with_remaining[-1][0] - with_remaining[0][0]) / (len(with_remaining) - 1)
            if net < 0:
                trend = "catching up"
            elif net > 0:
                trend = "falling behind"
            else:
                trend = "even"
            lines.append(f"New: net {net:.1f} mutants/night, {trend}.")

    measured_old = []
    for night in nights:
        done = _sum_key(night["cursors"], "completed_old")
        if done is not None:
            measured_old.append(done)
    left = _latest(nights, "old_remaining")
    left_text = "unknown" if left is None else str(int(left))
    if not measured_old:
        lines.append("Old: no measured backlog pace (completed_old missing).")
    else:
        pace = sum(measured_old) / len(measured_old)
        span = "1 night" if len(measured_old) == 1 else f"{len(measured_old)} nights"
        lines.append(f"Old: pace {pace:.1f} mutants/night over {span}. Left {left_text}.")
        if pace <= 0:
            lines.append("Old: no recent backlog progress.")
        elif left is None:
            lines.append("Old: days left unknown.")
        else:
            lines.append(f"Old: about {int(left) / pace:.1f} days left.")

    restarted = False
    for prev, cur in zip(nights, nights[1:]):
        if _generation_restarted(prev["cursors"][-1], cur["cursors"][-1]):
            restarted = True
            break
    if restarted:
        lines.append(
            "Generation restarted (new_base changed). Days left is the current backlog. "
            "That refill is not lost progress."
        )
    return "\n".join(lines)


def advance_side(
    cursor: dict,
    side: str,
    completed: int,
    n_new: int,
    n_old: int,
    head: str,
    old_lines: list[str],
    old_offset: int,
    elapsed: int,
    budget: int,
    new_left: int,
    old_left: int,
) -> None:
    """Move one side's cursor and record the next backlog name."""
    if completed < 0:
        raise ValueError("completed")
    if side == "new":
        new_skip = int(cursor.get("new_skip", 0)) + completed
        if new_skip >= n_new:
            cursor["new_base"] = head
            cursor["new_skip"] = 0
        else:
            cursor["new_skip"] = new_skip
    elif side == "old":
        if n_old:
            cursor["old_index"] = (int(cursor.get("old_index", 0)) + completed) % n_old
        else:
            cursor["old_index"] = 0
        queued = [line.strip() for line in old_lines if parse_mutant(line.strip())]
        if queued:
            cursor["old_name"] = queued[old_offset % len(queued)]
        else:
            cursor["old_name"] = ""
        # Backlog work does not rewind a new phase that is already done.
        # The old combined advance() reported new_done on this same check.
        if int(cursor.get("new_skip", 0)) >= n_new:
            cursor["new_base"] = head
            cursor["new_skip"] = 0
    else:
        raise ValueError("side")
    cursor["new_cap_used"] = cap_consumed(
        elapsed,
        budget,
        new_left,
        old_left,
        bool(cursor.get("new_cap_used", False)),
    )


def mark_cap(cursor: dict, elapsed: int, budget: int, new_left: int, old_left: int) -> bool:
    cursor["new_cap_used"] = cap_consumed(
        elapsed,
        budget,
        new_left,
        old_left,
        bool(cursor.get("new_cap_used", False)),
    )
    return bool(cursor["new_cap_used"])


def advance(new_skip: int, old_index: int, n_new: int, n_old: int, completed: int) -> tuple[int, int, bool]:
    """Return (new_skip, old_index, new_done).

    ``new_done`` means every new mutant was attempted, so the caller can
    move ``new_base`` to HEAD.
    """
    if completed < 0:
        raise ValueError("completed")
    take_new = min(completed, max(n_new - new_skip, 0))
    new_skip += take_new
    rest = completed - take_new
    if n_old and rest:
        old_index = (old_index + rest) % n_old
    elif n_old == 0:
        old_index = 0
    return new_skip, old_index, new_skip >= n_new


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    order_p = sub.add_parser("order")
    order_p.add_argument("--list", type=Path, required=True)
    order_p.add_argument("--diff", type=Path, required=True)
    order_p.add_argument("--old-index", type=int, required=True)
    order_p.add_argument("--new-skip", type=int, default=0)

    adv = sub.add_parser("advance")
    adv.add_argument("--cursor", type=Path, required=True)
    adv.add_argument("--n-new", type=int, required=True)
    adv.add_argument("--n-old", type=int, required=True)
    adv.add_argument("--completed", type=int, required=True)
    adv.add_argument("--head", required=True)

    re_p = sub.add_parser("re")
    re_p.add_argument("line")

    fin = sub.add_parser("finished")
    fin.add_argument("--log", type=Path, required=True)

    batch_p = sub.add_parser("file-batch")
    batch_p.add_argument("--queue", type=Path, required=True)
    batch_p.add_argument("--offset", type=int, required=True)
    batch_p.add_argument("--cap", type=int, required=True)

    prog = sub.add_parser("progress")
    prog.add_argument("--log", type=Path, required=True)
    prog.add_argument("--slice", type=Path, required=True)

    sched = sub.add_parser("schedule")
    sched.add_argument("--new", type=Path, required=True)
    sched.add_argument("--old", type=Path, required=True)
    sched.add_argument("--budget", type=int, required=True)
    sched.add_argument("--batch-sec", type=int, required=True)
    sched.add_argument("--cap", type=int, required=True)
    sched.add_argument("--new-cap-used", type=int, default=0)

    resume_p = sub.add_parser("resume-old")
    resume_p.add_argument("--list", type=Path, required=True)
    resume_p.add_argument("--index", type=int, required=True)
    resume_p.add_argument("--name", default="")

    night_p = sub.add_parser("night")
    night_p.add_argument("--cursor", type=Path, required=True)
    night_p.add_argument("--run-id", default="")

    split_p = sub.add_parser("split")
    split_p.add_argument("--list", type=Path, required=True)
    split_p.add_argument("--diff", type=Path, required=True)
    split_p.add_argument("--cursor", type=Path, required=True)
    split_p.add_argument("--head", required=True)
    split_p.add_argument("--out-new", type=Path, required=True)
    split_p.add_argument("--out-old", type=Path, required=True)

    side_p = sub.add_parser("next-side")
    side_p.add_argument("--elapsed", type=int, required=True)
    side_p.add_argument("--budget", type=int, required=True)
    side_p.add_argument("--new-left", type=int, required=True)
    side_p.add_argument("--old-left", type=int, required=True)
    side_p.add_argument("--new-cap-used", type=int, required=True)

    cap_p = sub.add_parser("mark-cap")
    cap_p.add_argument("--cursor", type=Path, required=True)
    cap_p.add_argument("--elapsed", type=int, required=True)
    cap_p.add_argument("--budget", type=int, required=True)
    cap_p.add_argument("--new-left", type=int, required=True)
    cap_p.add_argument("--old-left", type=int, required=True)

    show_p = sub.add_parser("show")
    show_p.add_argument("--cursor", type=Path, required=True)
    show_p.add_argument("--key", required=True)

    roll_p = sub.add_parser("rollover")
    roll_p.add_argument("--cursor", type=Path, required=True)
    roll_p.add_argument("--list", type=Path, required=True)
    roll_p.add_argument("--head", required=True)
    roll_p.add_argument("--out-new", type=Path, required=True)
    roll_p.add_argument("--out-old", type=Path, required=True)

    pkg_p = sub.add_parser("package-for")
    pkg_p.add_argument("--metadata", type=Path, required=True)
    pkg_p.add_argument("--path", required=True)

    dep_p = sub.add_parser("dependents")
    dep_p.add_argument("--metadata", type=Path, required=True)
    dep_p.add_argument("--package", required=True)

    dto_p = sub.add_parser("dependent-timeout")
    dto_p.add_argument("--seconds", type=int, required=True)

    rec_p = sub.add_parser("reconcile-missed")
    rec_p.add_argument("--phase1", type=Path, required=True)
    rec_p.add_argument("--phase2", type=Path)
    rec_p.add_argument("--slice", type=Path, required=True)

    rm_p = sub.add_parser("requested-misses")
    rm_p.add_argument("--phase1", type=Path, required=True)
    rm_p.add_argument("--slice", type=Path, required=True)

    hide_p = sub.add_parser("hide-unrequested")
    hide_p.add_argument("--phase1", type=Path, required=True)
    hide_p.add_argument("--slice", type=Path, required=True)
    hide_p.add_argument("--caught", type=Path, required=True)

    count_p = sub.add_parser("outcome-count")
    count_p.add_argument("--log", type=Path, required=True)

    rem_p = sub.add_parser("remember")
    rem_p.add_argument("--cursor", type=Path, required=True)
    rem_p.add_argument("--new-len", type=int, required=True)
    rem_p.add_argument("--old-len", type=int, required=True)
    rem_p.add_argument("--new-remaining", type=int, required=True)
    rem_p.add_argument("--old-remaining", type=int, required=True)
    rem_p.add_argument("--completed-new", type=int, required=True)
    rem_p.add_argument("--completed-old", type=int, required=True)

    health_p = sub.add_parser("health")
    health_p.add_argument("--jsonl", type=Path, required=True)

    adv_side = sub.add_parser("advance-side")
    adv_side.add_argument("--cursor", type=Path, required=True)
    adv_side.add_argument("--side", required=True)
    adv_side.add_argument("--completed", type=int, required=True)
    adv_side.add_argument("--n-new", type=int, required=True)
    adv_side.add_argument("--n-old", type=int, required=True)
    adv_side.add_argument("--head", required=True)
    adv_side.add_argument("--old-queue", type=Path, required=True)
    adv_side.add_argument("--old-offset", type=int, required=True)
    adv_side.add_argument("--elapsed", type=int, required=True)
    adv_side.add_argument("--budget", type=int, required=True)
    adv_side.add_argument("--new-left", type=int, required=True)
    adv_side.add_argument("--old-left", type=int, required=True)

    args = parser.parse_args(argv)
    if args.cmd == "re":
        print(rust_re_exact(args.line))
        return 0
    if args.cmd == "finished":
        print(finished_mutants(args.log.read_text()))
        return 0
    if args.cmd == "file-batch":
        lines = file_batch(args.queue.read_text().splitlines(), args.offset, args.cap)
        for line in lines:
            print(line)
        return 0
    if args.cmd == "package-for":
        metadata = json.loads(args.metadata.read_text())
        print(package_for(metadata, args.path))
        return 0
    if args.cmd == "dependents":
        metadata = json.loads(args.metadata.read_text())
        for name in dependents(metadata, args.package):
            print(name)
        return 0
    if args.cmd == "dependent-timeout":
        print(dependent_timeout(args.seconds))
        return 0
    if args.cmd == "reconcile-missed":
        phase2 = args.phase2.read_text() if args.phase2 else ""
        for line in reconcile_missed(args.phase1.read_text(), phase2, args.slice.read_text().splitlines()):
            print(line)
        return 0
    if args.cmd == "requested-misses":
        for line in requested_misses(args.phase1.read_text(), args.slice.read_text().splitlines()):
            print(line)
        return 0
    if args.cmd == "hide-unrequested":
        if not args.caught.is_file():
            return 0
        requested = args.slice.read_text().splitlines()
        updated = hide_unrequested(args.phase1.read_text(), requested, args.caught.read_text())
        args.caught.write_text(updated)
        return 0
    if args.cmd == "outcome-count":
        print(outcome_count(args.log.read_text()))
        return 0
    if args.cmd == "progress":
        requested = args.slice.read_text().splitlines()
        print(prefix_progress(args.log.read_text(), requested))
        return 0

    if args.cmd == "order":
        mutants = load_mutants(args.list.read_text())
        changed = changed_lines(args.diff.read_text()) if args.diff.stat().st_size else set()
        new, old = order(mutants, changed, args.old_index)
        if args.new_skip:
            new = new[args.new_skip :]
        for line in new + old:
            print(line)
        return 0

    if args.cmd == "schedule":
        rows = schedule(
            args.new.read_text().splitlines(),
            args.old.read_text().splitlines(),
            args.budget,
            args.batch_sec,
            args.cap,
            bool(args.new_cap_used),
        )
        for side, start, name in rows:
            print(f"{side}\t{start}\t{name}")
        return 0

    if args.cmd == "resume-old":
        old = load_mutants(args.list.read_text())
        rotated, _start = resume_old(old, args.index, args.name)
        for line in rotated:
            print(line)
        return 0

    if args.cmd == "night":
        cursor = read_cursor(args.cursor)
        begin_night(cursor, args.run_id)
        write_cursor(args.cursor, cursor)
        return 0

    if args.cmd == "split":
        mutants = load_mutants(args.list.read_text())
        changed = changed_lines(args.diff.read_text()) if args.diff.stat().st_size else set()
        new, old = partition(mutants, changed)
        # Full counts, before new_skip slices the file the job walks.
        n_new, n_old = len(new), len(old)
        cursor = read_cursor(args.cursor)
        new_skip = int(cursor.get("new_skip", 0))
        # A skip that already covers this list finished the new phase on a
        # previous shape of the diff. Drop those names and move the base,
        # matching advance() when new_skip >= n_new. Leaving the skip in
        # place would hide every later new mutant.
        if new_skip >= n_new:
            cursor["new_base"] = args.head
            cursor["new_skip"] = 0
            new = []
        elif new_skip:
            new = new[new_skip:]
        rotated, start = resume_old(
            old, int(cursor.get("old_index", 0)), str(cursor.get("old_name", ""))
        )
        cursor["old_index"] = start
        cursor["old_name"] = rotated[0] if rotated else ""
        write_cursor(args.cursor, cursor)
        args.out_new.write_text("".join(line + "\n" for line in new))
        args.out_old.write_text("".join(line + "\n" for line in rotated))
        print(n_new, n_old)
        return 0

    if args.cmd == "next-side":
        print(
            next_side(
                args.elapsed,
                args.budget,
                args.new_left > 0,
                args.old_left > 0,
                bool(args.new_cap_used),
            )
        )
        return 0

    if args.cmd == "mark-cap":
        cursor = read_cursor(args.cursor)
        mark_cap(cursor, args.elapsed, args.budget, args.new_left, args.old_left)
        write_cursor(args.cursor, cursor)
        return 0

    if args.cmd == "show":
        cursor = read_cursor(args.cursor)
        key = args.key
        if key == "new_cap_used":
            print("1" if cursor.get("new_cap_used") else "0")
        elif key in ("new_skip", "old_index"):
            print(int(cursor.get(key, 0)))
        else:
            print(cursor.get(key, ""))
        return 0

    if args.cmd == "rollover":
        cursor = read_cursor(args.cursor)
        new, old = rollover(cursor, load_mutants(args.list.read_text()), args.head)
        write_cursor(args.cursor, cursor)
        args.out_new.write_text("".join(line + "\n" for line in new))
        args.out_old.write_text("".join(line + "\n" for line in old))
        print(len(new), len(old))
        return 0

    if args.cmd == "remember":
        cursor = read_cursor(args.cursor)
        remember(
            cursor,
            args.new_len,
            args.old_len,
            args.new_remaining,
            args.old_remaining,
            args.completed_new,
            args.completed_old,
        )
        write_cursor(args.cursor, cursor)
        return 0

    if args.cmd == "health":
        entries = []
        for raw in args.jsonl.read_text().splitlines():
            line = raw.strip()
            if line:
                entries.append(json.loads(line))
        print(health_report(entries))
        return 0

    if args.cmd == "advance-side":
        cursor = read_cursor(args.cursor)
        old_lines = args.old_queue.read_text().splitlines() if args.old_queue.exists() else []
        advance_side(
            cursor,
            args.side,
            args.completed,
            args.n_new,
            args.n_old,
            args.head,
            old_lines,
            args.old_offset,
            args.elapsed,
            args.budget,
            args.new_left,
            args.old_left,
        )
        write_cursor(args.cursor, cursor)
        return 0

    if args.cmd != "advance":
        raise SystemExit(f"unknown command {args.cmd}")

    cursor = json.loads(args.cursor.read_text())
    new_skip, old_index, done = advance(
        int(cursor.get("new_skip", 0)),
        int(cursor.get("old_index", 0)),
        args.n_new,
        args.n_old,
        args.completed,
    )
    if done:
        cursor["new_base"] = args.head
        cursor["new_skip"] = 0
    else:
        cursor["new_skip"] = new_skip
    if old_index != int(cursor.get("old_index", 0)):
        cursor.pop("old_name", None)
    cursor["old_index"] = old_index
    write_cursor(args.cursor, cursor)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
