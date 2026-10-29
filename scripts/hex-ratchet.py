#!/usr/bin/env python3
"""Per-file ceiling for production hex integer literals.

Counts each `0x` literal under crates/, not each line. Skips the same
files as the unwrap ratchet: rbitcoin-test, rbitcoin-bench, tests/,
benches/, *tests.rs, and items marked `#[cfg(test)]`. Comments, strings,
and char literals do not count. `0x207f_ffff` is one literal.

lint/hex-baseline.txt is sorted `path<TAB>count` lines for counts above
zero. A file above its line, a positive file with no line, or a line that
is now lower (or whose file is gone) fails. --write rewrites the file
from the tree.
"""

import argparse
import importlib.util
import os
import re
import sys

HEX_RE = re.compile(r"(?<![A-Za-z0-9_])0[xX][0-9a-fA-F][0-9a-fA-F_]*")


def hex_on_line(code: str, _prev: str) -> int:
    return len(HEX_RE.findall(code))


def load_unwrap():
    path = os.path.join(os.path.dirname(__file__), "unwrap-ratchet.py")
    spec = importlib.util.spec_from_file_location("unwrap_ratchet", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    root = os.path.abspath(args.root or os.path.join(os.path.dirname(__file__), ".."))
    baseline = os.path.join(root, "lint", "hex-baseline.txt")
    ratchet = load_unwrap()
    counts = ratchet.scan(root, hex_on_line)
    if args.write:
        ratchet.write_baseline(baseline, counts)
        print(f"wrote {len(counts)} lines to {baseline}")
        return 0
    errors = ratchet.check(counts, ratchet.read_baseline(baseline), "hex literals")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
