#!/usr/bin/env python3
"""Confirm // btc-lean: comments cover the vendored consensus census.

The pin is the third_party/btc-lean gitlink. This script reads that
checkout's spec/db/rules.yaml, docs/btc-lean-gaps.md, and the comments in
this tree. It runs in the qc job after
`git submodule update --init --depth 1 third_party/btc-lean`.

A proven row is covered when some // btc-lean: comment names it, or when
docs/btc-lean-gaps.md gives a reason. status: obsolete is the reason for a
retired row, and that id must not be commented or listed as a gap. A
comment is an index of the statement under it. It is not a claim that a
Lean theorem holds of the Rust.
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

COMMENT = re.compile(r"^\s*// btc-lean:((?:\s+[A-Z]{3}-\d{3})+)\s*$")
RULE_ID = re.compile(r"^- id: ([A-Z]{3}-\d{3})\s*$")
RULE_STATUS = re.compile(r"^\s+status:\s+(\S+)\s*$")
SECTION = re.compile(r"(?m)^## .+$")
TICK_ID = re.compile(r"`([A-Z]{3}-\d{3})`")
RULES_REL = Path("third_party/btc-lean/spec/db/rules.yaml")
GAPS_REL = Path("docs/btc-lean-gaps.md")


def load_rules(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    rows: dict[str, str] = {}
    cur: str | None = None
    for n, ln in enumerate(path.read_text().splitlines(), 1):
        mid = RULE_ID.match(ln)
        if mid:
            if cur is not None:
                raise SystemExit(f"{path}:{n}: {cur} has no status")
            cur = mid.group(1)
            if cur in rows:
                raise SystemExit(f"{path}:{n}: duplicate id {cur}")
            continue
        mstatus = RULE_STATUS.match(ln)
        if mstatus and cur is not None:
            rows[cur] = mstatus.group(1)
            cur = None
    if cur is not None:
        raise SystemExit(f"{path}: {cur} has no status")
    if not rows:
        raise SystemExit(f"{path}: no rule ids")
    return rows


class GapError(Exception):
    pass


def load_gaps(path: Path) -> dict[str, str]:
    """Map each gap id to its reason. The first line of a section is ids."""
    if not path.is_file():
        raise FileNotFoundError(path)
    text = path.read_text()
    marks = list(SECTION.finditer(text))
    if not marks:
        raise GapError(f"{path}: no gap sections")
    out: dict[str, str] = {}
    for i, mark in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        lines = text[mark.end() : end].strip().splitlines()
        title = mark.group(0)
        if not lines:
            raise GapError(f"{path}: empty section {title}")
        ids = TICK_ID.findall(lines[0])
        if not ids or lines[0].replace("`", "").split() != ids:
            raise GapError(f"{path}: {title} must open with `ID` tokens")
        reason = " ".join(ln.strip() for ln in lines[1:] if ln.strip())
        if not reason:
            raise GapError(f"{path}: {ids[0]} has an empty reason")
        for rid in ids:
            if rid in out:
                raise GapError(f"{path}: duplicate gap {rid}")
            out[rid] = reason
    return out


def comment_ids(root: Path) -> tuple[set[str], list[str]]:
    found: set[str] = set()
    errs: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if rel.startswith("target/") or "/target/" in rel:
            continue
        lines = path.read_text().splitlines()
        i = 0
        while i < len(lines):
            if not COMMENT.match(lines[i]):
                i += 1
                continue
            ids: list[str] = []
            while i < len(lines) and (m := COMMENT.match(lines[i])):
                ids.extend(m.group(1).split())
                i += 1
            if i >= len(lines) or not lines[i].strip() or lines[i].lstrip().startswith("//"):
                errs.append(f"{rel}:{i}: btc-lean comment is not on the next code line")
                continue
            for rid in sorted({x for x in ids if ids.count(x) > 1}):
                errs.append(f"{rel}:{i + 1}: {rid} repeated in one comment")
            found.update(ids)
    return found, errs


def check(root: Path) -> list[str]:
    path = root / RULES_REL
    try:
        rules = load_rules(path)
    except FileNotFoundError:
        return [
            f"{RULES_REL} is not checked out; "
            "git submodule update --init --depth 1 third_party/btc-lean"
        ]
    try:
        reasons = load_gaps(root / GAPS_REL)
    except FileNotFoundError:
        return [f"{GAPS_REL} is missing"]
    except GapError as exc:
        return [str(exc)]
    commented, errs = comment_ids(root)
    for rid in sorted(commented):
        if rid not in rules:
            errs.append(f"{rid}: comment is not in {RULES_REL}")
    for rid, reason in reasons.items():
        if rid not in rules:
            errs.append(f"{rid}: gap is not in {RULES_REL}")
            continue
        if rules[rid] == "obsolete":
            errs.append(f"{rid}: obsolete row does not need a gap reason")
        if rid in commented:
            errs.append(f"{rid}: gap row also has a // btc-lean: comment")
        if not reason.strip():
            errs.append(f"{rid}: empty gap reason")
    for rid, status in rules.items():
        if status == "obsolete":
            if rid in commented:
                errs.append(f"{rid}: obsolete row must not have a // btc-lean: comment")
            continue
        if rid in reasons or rid in commented:
            continue
        errs.append(f"{rid}: status {status} has no // btc-lean: comment and no gap reason")
    return errs


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _fixture(root: Path, rust: str) -> None:
    _write(
        root / RULES_REL,
        "- id: INV-001\n  status: proven\n"
        "- id: INV-002\n  status: obsolete\n"
        "- id: INV-003\n  status: proven\n"
        "- id: INV-004\n  status: proven\n",
    )
    _write(
        root / GAPS_REL,
        "# gaps\n\n## no site\n\n`INV-003`\n\nno production site. see INV-004.\n",
    )
    _write(
        root / "src" / "a.rs",
        rust,
    )


def self_test() -> None:
    clean = (
        "// btc-lean: INV-001 INV-004\n"
        "fn prod() {}\n"
        "// btc-lean: INV-001\n"
        "fn test_it() {}\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _fixture(root, clean)
        errs = check(root)
        if errs:
            raise SystemExit("self-test clean tree failed:\n" + "\n".join(errs))

        _fixture(root, "fn prod() {}\n")
        errs = check(root)
        if not any("INV-001" in e and "no // btc-lean:" in e for e in errs):
            raise SystemExit("self-test did not notice a missing comment:\n" + "\n".join(errs))

        _fixture(root, "// btc-lean: INV-001 INV-003 INV-004\nfn prod() {}\n")
        errs = check(root)
        if not any("INV-003" in e and "gap row" in e for e in errs):
            raise SystemExit("self-test did not notice a commented gap:\n" + "\n".join(errs))

        _fixture(root, "// btc-lean: INV-001 INV-002 INV-004\nfn prod() {}\n")
        errs = check(root)
        if not any("INV-002" in e and "obsolete" in e for e in errs):
            raise SystemExit("self-test did not notice an obsolete comment:\n" + "\n".join(errs))

        _fixture(root, "// btc-lean: INV-001 INV-004 INV-999\nfn prod() {}\n")
        errs = check(root)
        if not any("INV-999" in e for e in errs):
            raise SystemExit("self-test did not notice an unknown id:\n" + "\n".join(errs))

        _fixture(root, "// btc-lean: INV-001 INV-004\n// still a comment\n")
        errs = check(root)
        if not any("not on the next code line" in e for e in errs):
            raise SystemExit("self-test did not notice a dangling comment:\n" + "\n".join(errs))

        _fixture(root, clean)
        _write(root / GAPS_REL, "# gaps\n\n## no site\n\n`INV-003`\n")
        errs = check(root)
        if not any("empty reason" in e for e in errs):
            raise SystemExit("self-test did not notice an empty reason:\n" + "\n".join(errs))

        (root / RULES_REL).unlink()
        errs = check(root)
        if not any("not checked out" in e for e in errs):
            raise SystemExit("self-test did not notice a missing submodule:\n" + "\n".join(errs))

        _fixture(root, clean)
        (root / GAPS_REL).unlink()
        errs = check(root)
        if not any(str(GAPS_REL) in e for e in errs):
            raise SystemExit("self-test did not notice a missing gaps file:\n" + "\n".join(errs))
    print("btc-lean-census self-test ok")


def main() -> None:
    if "--self-test" in sys.argv:
        self_test()
        return
    root = Path.cwd()
    if "--root" in sys.argv:
        root = Path(sys.argv[sys.argv.index("--root") + 1])
    errs = check(root)
    if errs:
        print(f"btc-lean census: {len(errs)} error(s)", file=sys.stderr)
        for e in errs[:80]:
            print(e, file=sys.stderr)
        raise SystemExit(1)
    rules = load_rules(root / RULES_REL)
    reasons = load_gaps(root / GAPS_REL)
    commented, _ = comment_ids(root)
    obsolete = sum(1 for s in rules.values() if s == "obsolete")
    print(
        "btc-lean census: "
        f"{len(rules)} rules, {len(commented)} commented, "
        f"{len(reasons)} gaps, {obsolete} obsolete"
    )


if __name__ == "__main__":
    main()
