#!/usr/bin/env python3
"""Per-file ceiling for bare production unwraps.

Counts each `.unwrap(` and `.unwrap_err(` under crates/, not each line.
Skips rbitcoin-test, rbitcoin-bench, tests/, benches/, *tests.rs, and
items marked `#[cfg(test)]`. Does not count unwrap_or. A `.lock()` /
`.read()` / `.write()` / `try_into()` receiver is not counted, including
when that call sits on the previous line, including a turbofish.
A later method on that value still counts.

lint/unwrap-baseline.txt is sorted `path<TAB>count` lines for counts above zero.
A file above its line, a positive file with no line, or a line that is now
lower (or whose file is gone) fails. --write rewrites the file from the tree.
"""

import argparse
import os
import re
import sys

UNWRAP_RE = re.compile(r"\.unwrap(?:_err)?\s*\(")
# The excluded call is the tail of the receiver. The name is `try_into`,
# not a longer identifier. A turbofish may contain `;` (`[u8; 4]`).
# A later `.ok()` or `.as_ref()` is not that tail.
EXCLUDED_TAIL = re.compile(
    r"(?:(?<![A-Za-z0-9_])try_into(?:\s*::\s*<(?:[^<>\[\]]|\[[^\]]*\]|<[^<>]*>)*>)?\s*\(\s*\)"
    r"|\.(?:lock|read|write)\s*\(\s*\))\s*$"
)
CFG_TEST_ATTR = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
SKIP_CRATES = {"rbitcoin-test", "rbitcoin-bench"}
# `impl<T>` and `impl<'a>` have no space after the keyword. A trailing
# space would miss them and drop the cfg(test) skip.
ITEM_RE = re.compile(r"\b(?:mod|fn|impl|struct|enum|trait|const|static|type)\b")


def _blank(chars: list[str], start: int, end: int) -> None:
    for j in range(start, end):
        if chars[j] != "\n":
            chars[j] = " "


def _string_end(src: str, i: int) -> int | None:
    """Index just past a string that starts at i, or None."""
    n = len(src)
    if i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_"):
        return None
    k = i
    raw = False
    # `rb`/`rc` are raw, same as `br`/`cr`. Checked before the cooked `b"`/`c"` arm.
    if src.startswith(
        ("br", "bR", "Br", "BR", "rb", "rB", "Rb", "RB", "cr", "cR", "Cr", "CR", "rc", "rC", "Rc", "RC"),
        i,
    ):
        k = i + 2
        raw = True
    elif i + 1 < n and src[i] in "bBcC" and src[i + 1] == '"':
        k = i + 1
    elif src[i] in "rR":
        k = i + 1
        raw = True
    elif src[i] != '"':
        return None
    if raw:
        hashes = 0
        while k < n and src[k] == "#":
            hashes += 1
            k += 1
        if k >= n or src[k] != '"':
            return None
        k += 1
        closer = '"' + ("#" * hashes)
        while k < n:
            if src.startswith(closer, k):
                return k + len(closer)
            k += 1
        return n
    if k >= n or src[k] != '"':
        return None
    k += 1
    while k < n:
        if src[k] == "\\":
            k += 2
            continue
        if src[k] == '"':
            return k + 1
        if src[k] == "\n":
            return None
        k += 1
    return n


def _char_end(src: str, i: int) -> int | None:
    """Index just past a char literal at i, or None for a lifetime."""
    n = len(src)
    j = i + 1
    if j >= n:
        return None
    if src[j] == "\\":
        j += 1
        if j >= n:
            return None
        if src[j] == "x":
            j += 3
        elif src[j] == "u":
            j += 1
            if j >= n or src[j] != "{":
                return None
            while j < n and src[j] != "}":
                j += 1
            j += 1
        else:
            j += 1
    else:
        j += 1
    if j < n and src[j] == "'":
        return j + 1
    return None


def blank_non_code(src: str) -> str:
    """Spaces out comments, strings, and char literals. Newlines stay."""
    chars = list(src)
    n = len(src)
    i = 0
    while i < n:
        if src.startswith("//", i):
            j = i
            while j < n and src[j] != "\n":
                j += 1
            _blank(chars, i, j)
            i = j
            continue
        if src.startswith("/*", i):
            # Rust nests block comments, including `/**` and `/*!`.
            depth_c = 1
            j = i + 2
            while j < n and depth_c:
                if src.startswith("/*", j):
                    depth_c += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth_c -= 1
                    j += 2
                else:
                    j += 1
            _blank(chars, i, j)
            i = j
            continue
        if src[i] == "'":
            end = _char_end(src, i)
            if end is not None:
                _blank(chars, i, end)
                i = end
                continue
        end = _string_end(src, i)
        if end is not None:
            _blank(chars, i, end)
            i = end
            continue
        i += 1
    return "".join(chars)


def bare_on_line(code: str, prev: str) -> int:
    n = 0
    for match in UNWRAP_RE.finditer(code):
        before = code[: match.start()].rstrip()
        receiver = before if before else prev.rstrip()
        if EXCLUDED_TAIL.search(receiver):
            continue
        n += 1
    return n


def file_count(path: str, line_fn=bare_on_line) -> int:
    lines = blank_non_code(open(path, encoding="utf-8", errors="replace").read()).splitlines()
    depth = 0
    test_stack: list[int] = []
    pending = False
    saw_item = False
    prev = ""
    n = 0
    for line in lines:
        code = line
        if CFG_TEST_ATTR.search(code):
            pending = True
            saw_item = False
        stripped = code.strip()
        in_test = bool(test_stack)
        if pending and "{" in code:
            test_stack.append(depth)
            pending = False
            saw_item = False
            in_test = True
        elif pending and stripped:
            # Attribute-only lines keep the skip open. Once the item header
            # starts, a `where` clause stays with it until `{` or `;`.
            # A braceless item ends in `;` and must not swallow the next one.
            attr_only = (
                stripped.startswith("#")
                and "{" not in stripped
                and not stripped.endswith(";")
            )
            if not attr_only:
                if ITEM_RE.search(code):
                    saw_item = True
                if stripped.endswith(";"):
                    pending = False
                    saw_item = False
                elif not saw_item:
                    pending = False
        if not in_test:
            n += line_fn(code, prev)
        depth += code.count("{") - code.count("}")
        while test_stack and depth <= test_stack[-1]:
            test_stack.pop()
        if depth < 0:
            depth = 0
        prev = code.rstrip()
    return n


def scan(root: str, line_fn=bare_on_line) -> dict[str, int]:
    crates = os.path.join(root, "crates")
    counts: dict[str, int] = {}
    for dirpath, dirnames, filenames in os.walk(crates):
        dirnames[:] = [d for d in dirnames if d not in ("target",)]
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        parts = rel_dir.split("/")
        if "tests" in parts or "benches" in parts:
            continue
        if len(parts) > 1 and parts[1] in SKIP_CRATES:
            continue
        for name in filenames:
            if not name.endswith(".rs") or name.endswith("tests.rs"):
                continue
            rel = f"{rel_dir}/{name}"
            got = file_count(os.path.join(dirpath, name), line_fn)
            if got:
                counts[rel] = got
    return counts


def read_baseline(path: str) -> dict[str, int]:
    if not os.path.exists(path):
        sys.exit(f"missing baseline {path}")
    out: dict[str, int] = {}
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path_s, count_s = line.split("\t")
        out[path_s] = int(count_s)
    return out


def write_baseline(path: str, counts: dict[str, int]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = [f"{p}\t{counts[p]}\n" for p in sorted(counts)]
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


def check(counts: dict[str, int], base: dict[str, int], noun: str = "unwraps") -> list[str]:
    errors = []
    for path in sorted(set(counts) | set(base)):
        got = counts.get(path, 0)
        if path not in base:
            errors.append(f"{path}: {got} {noun}, baseline has no line")
            continue
        want = base[path]
        if got > want:
            errors.append(f"{path}: {got} {noun}, baseline {want}")
        elif got < want:
            errors.append(f"{path}: {got} {noun}, baseline {want} (lower the line)")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    root = os.path.abspath(args.root or os.path.join(os.path.dirname(__file__), ".."))
    baseline = os.path.join(root, "lint", "unwrap-baseline.txt")
    counts = scan(root)
    if args.write:
        write_baseline(baseline, counts)
        print(f"wrote {len(counts)} lines to {baseline}")
        return 0
    errors = check(counts, read_baseline(baseline))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
