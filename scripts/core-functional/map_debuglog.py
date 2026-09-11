#!/usr/bin/env python3
"""Apply debuglog_map.toml rules: rbitcoin line → Core debug.log lines."""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ImportError:  # py<3.11
    import tomli as tomllib  # type: ignore


def load_rules(path: Path) -> list[tuple[re.Pattern[str], list[str]]]:
    data = tomllib.loads(path.read_text())
    out: list[tuple[re.Pattern[str], list[str]]] = []
    for row in data.get("rule", []):
        out.append((re.compile(row["match"]), list(row["emit"])))
    return out


def apply_line(line: str, rules: list[tuple[re.Pattern[str], list[str]]]) -> list[str]:
    line = line.rstrip("\n")
    emitted: list[str] = []
    for pat, emits in rules:
        m = pat.search(line)
        if not m:
            continue
        for tmpl in emits:
            s = tmpl
            for i, g in enumerate(m.groups(), start=1):
                s = s.replace(f"{{{i}}}", g or "")
            emitted.append(s)
    return emitted


def map_error_stderr(
    lines: list[str], rules: list[tuple[re.Pattern[str], list[str]]]
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for ln in lines:
        mapped = [m for m in apply_line(ln, rules) if m.startswith("Error:")]
        chosen = mapped if mapped else [ln]
        for c in chosen:
            if c not in seen:
                seen.add(c)
                out.append(c)
    return out


def main() -> int:
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--map", required=True)
    p.add_argument("line")
    args = p.parse_args()
    rules = load_rules(Path(args.map))
    for out in apply_line(args.line, rules):
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
