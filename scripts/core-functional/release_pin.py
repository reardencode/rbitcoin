#!/usr/bin/env python3
"""Print the official bitcoind tarball pin for this host (or --arch).

Reads [release] from inventory.toml. No network.
"""

from __future__ import annotations

import argparse
import os
import platform
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover
    print("release_pin: need Python 3.11+ (tomllib)", file=sys.stderr)
    sys.exit(2)

HERE = Path(__file__).resolve().parent
DEFAULT_INVENTORY = HERE / "inventory.toml"


def host_arch() -> str:
    sysname = platform.system()
    machine = platform.machine()
    if os.environ.get("FETCH_BITCOIND_ARCH"):
        return os.environ["FETCH_BITCOIND_ARCH"].strip()
    if sysname != "Linux":
        raise SystemExit(f"release_pin: unsupported arch {sysname}/{machine} (linux x86_64/aarch64 only)")
    if machine in ("x86_64", "amd64"):
        return "x86_64-linux-gnu"
    if machine in ("aarch64", "arm64"):
        return "aarch64-linux-gnu"
    raise SystemExit(f"release_pin: unsupported arch {sysname}/{machine} (linux x86_64/aarch64 only)")


def pin_semver(pin: str) -> str:
    s = pin.strip()
    if s.lower().startswith("v"):
        s = s[1:]
    return s


def load_release(path: Path, arch: str) -> dict[str, str]:
    data = tomllib.loads(path.read_bytes().decode())
    pin = data.get("pin")
    if not isinstance(pin, str) or not pin.strip():
        raise SystemExit(f"release_pin: missing pin: {path}")
    rel = data.get("release")
    if not isinstance(rel, dict):
        raise SystemExit("release_pin: missing [release]")
    base = rel.get("base_url")
    linux = rel.get("linux")
    if not isinstance(base, str) or not base.strip():
        raise SystemExit("release_pin: missing [release].base_url")
    if not isinstance(linux, list):
        raise SystemExit("release_pin: missing [[release.linux]]")
    row = None
    for item in linux:
        if isinstance(item, dict) and item.get("arch") == arch:
            row = item
            break
    if row is None:
        raise SystemExit(f"release_pin: unsupported arch {arch} (linux x86_64/aarch64 only)")
    tarball = row.get("tarball")
    sha256 = row.get("sha256")
    if not isinstance(tarball, str) or not tarball:
        raise SystemExit(f"release_pin: missing tarball for {arch}")
    if not isinstance(sha256, str) or not sha256:
        raise SystemExit(f"release_pin: missing sha256 for {arch}")
    ver = pin_semver(pin)
    base = base.rstrip("/")
    return {
        "version": pin if pin.startswith("v") else f"v{pin}",
        "arch": arch,
        "url": f"{base}/{tarball}",
        "tarball": tarball,
        "sha256": sha256.lower(),
        "inner": f"bitcoin-{ver}/bin/bitcoind",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    p.add_argument("--arch", default=None, help="override host arch (e.g. x86_64-linux-gnu)")
    args = p.parse_args(argv)
    if not args.inventory.is_file():
        print(f"release_pin: missing inventory: {args.inventory}", file=sys.stderr)
        return 1
    try:
        arch = args.arch.strip() if args.arch else host_arch()
        row = load_release(args.inventory, arch)
    except SystemExit as e:
        msg = str(e)
        if msg:
            print(msg, file=sys.stderr)
        return 1
    for k in ("version", "arch", "url", "tarball", "sha256", "inner"):
        print(f"{k}={row[k]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
