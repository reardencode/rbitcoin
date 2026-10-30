#!/usr/bin/env python3
"""Build the rbitcoin 199-block store used by setup_clean_chain=False tests.

Core's `_initialize_chain` mines 199 blocks then **deletes** everything except
`blocks/` + `chainstate/` (LevelDB). We never consume that. Instead:

1. This script mines 199 via `generatetoaddress` (Core payee schedule:
   PRIV_KEYS[0:3] + MiniWallet P2TR) into `scripts/core-functional/cache/store`.
2. `run.sh` preseeds empty `test/cache/node0/regtest/{blocks,chainstate}` and
   passes that directory last as `--cachedir`, so v32.1's temp cache does not
   win and Core skips remine.
3. The bitcoind shim copies `RBITCOIN_CACHE/store` when the dest looks like a
   Core cache copy (has `blocks/` + `chainstate/`, no `store/`).

Not invoked by default `cargo test`. Re-run after a schema bump (wipe HEIGHT).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CACHE = HERE / "cache"


def pick_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def rpc_until(url: str, cookie: str, method: str, params=None, deadline: float | None = None):
    """Call until the proxy is past warmup.

    JSON-RPC -28 is Core's loading code. The shim returns it after the tip
    leaves IBD and before tx relay is on. Cache mining hits that window:
    setmocktime makes the genesis tip fresh, then generatetoaddress has to
    wait for relay. A refused connection is the same wait.
    """
    end = time.time() + 30 if deadline is None else deadline
    last: object = None
    while True:
        remaining = end - time.time()
        if remaining <= 0:
            raise TimeoutError(last)
        try:
            resp = rpc_call(
                url, cookie, method, params, timeout=max(1.0, remaining)
            )
        except Exception as exc:  # noqa: BLE001 — node or proxy not up yet
            last = exc
            continue
        err = resp.get("error") if isinstance(resp, dict) else None
        if isinstance(err, dict) and err.get("code") == -28:
            last = err
            continue
        return resp


def rpc_call(url: str, cookie: str, method: str, params=None, timeout: float = 30):
    body = json.dumps(
        {"jsonrpc": "1.0", "id": "cache", "method": method, "params": params or []}
    ).encode()
    tok = base64.b64encode(cookie.encode()).decode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Basic {tok}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# Must match Core `_initialize_chain`: 199 blocks cycling TestNode.PRIV_KEYS[0:3]
# plus MiniWallet's deterministic P2TR OP_TRUE (blocks 76–100).
CACHE_MARK = "199-mw1-genesis-mock"
CACHE_ADDRS = [
    "mjTkW3DjgyZck4KbiRusZsqTgaYTxdSz6z",
    "msX6jQXvxiNhx3Q62PKeLPrhrqZQdSimTg",
    "mnonCMyH9TmAsSj3M59DsbH8H63U3RKoFP",
    "bcrt1p9yfmy5h72durp7zrhlw9lf7jpwjgvwdg0jr0lqmmjtgg83266lqsekaqka",
]


def cache_ready(cache: Path) -> bool:
    height = cache / "HEIGHT"
    store = cache / "store"
    return (
        height.is_file()
        and height.read_text().strip() == CACHE_MARK
        and store.is_dir()
        and any(store.iterdir())
    )


def build_cache(cache: Path) -> int:
    if cache_ready(cache):
        print(f"create_cache: already ready at {cache}")
        return 0

    rpcport = pick_port()
    p2pport = pick_port()
    tmp = Path(tempfile.mktemp(prefix="rbitcoin-cf-cache-"))
    tmp.mkdir()
    datadir = tmp / "node0"
    datadir.mkdir()
    (datadir / "bitcoin.conf").write_text(
        f"regtest=1\n[regtest]\nport={p2pport}\nrpcport={rpcport}\nserver=1\n"
    )
    cookie_path = datadir / "regtest" / ".cookie"
    shim = HERE / "bitcoind"
    # Do not seed from an incomplete cache while we are building it.
    env = os.environ.copy()
    env.pop("RBITCOIN_CACHE", None)
    proc = subprocess.Popen(
        [
            sys.executable,
            str(shim),
            f"-datadir={datadir}",
            "-regtest",
            "-server",
            "-disablewallet",
            f"-rpcport={rpcport}",
            f"-port={p2pport}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            if proc.poll() is not None:
                err = (proc.stderr.read() or b"").decode()
                print(f"create_cache: shim exited {proc.returncode}: {err}", file=sys.stderr)
                return 1
            if cookie_path.is_file() and cookie_path.stat().st_size > 0:
                break
            time.sleep(0.1)
        else:
            print(f"create_cache: no cookie at {cookie_path}", file=sys.stderr)
            return 1
        cookie = cookie_path.read_text().strip()
        url = f"http://127.0.0.1:{rpcport}/"
        try:
            resp = rpc_until(url, cookie, "getblockcount", deadline=deadline)
        except TimeoutError as e:
            print(f"create_cache: RPC not up ({e})", file=sys.stderr)
            return 1
        if resp.get("result") != 0:
            print(f"create_cache: RPC not up ({resp})", file=sys.stderr)
            return 1

        # Core `_initialize_chain`: setmocktime(genesis tip) so the 199-block
        # cache ages from 2011, not wall clock. Startup then mines one wall-clock
        # block; MTP stays old so later setmocktime(now-25h)+generate works.
        try:
            tip = rpc_until(url, cookie, "getbestblockhash", deadline=deadline).get(
                "result"
            )
            if not tip:
                print("create_cache: missing genesis tip hash", file=sys.stderr)
                return 1
            hdr = rpc_until(url, cookie, "getblockheader", [tip], deadline=deadline).get(
                "result"
            ) or {}
            genesis_time = hdr.get("time")
            if genesis_time is None:
                print("create_cache: missing genesis tip time", file=sys.stderr)
                return 1
            resp = rpc_until(
                url, cookie, "setmocktime", [int(genesis_time)], deadline=deadline
            )
            if resp.get("error"):
                print(f"create_cache: setmocktime: {resp['error']}", file=sys.stderr)
                return 1

            # Same payee schedule as Core `_initialize_chain` (25×7 + 24).
            # setmocktime drops IBD before relay is on, so these calls see -28
            # until the proxy opens.
            gen_deadline = time.time() + 180
            hashes: list = []
            for i in range(8):
                nblocks = 25 if i != 7 else 24
                addr = CACHE_ADDRS[i % len(CACHE_ADDRS)]
                resp = rpc_until(
                    url,
                    cookie,
                    "generatetoaddress",
                    [nblocks, addr],
                    deadline=gen_deadline,
                )
                if resp.get("error"):
                    print(
                        f"create_cache: generatetoaddress: {resp['error']}",
                        file=sys.stderr,
                    )
                    return 1
                hashes.extend(resp.get("result") or [])
        except TimeoutError as e:
            print(f"create_cache: generate failed: {e}", file=sys.stderr)
            return 1
        if len(hashes) != 199:
            print(f"create_cache: generate returned {len(hashes)} hashes", file=sys.stderr)
            return 1
        while time.time() < gen_deadline:
            try:
                height = rpc_call(url, cookie, "getblockcount").get("result")
                if height == 199:
                    break
            except Exception:  # noqa: BLE001
                continue
        else:
            print("create_cache: tip never reached 199", file=sys.stderr)
            return 1

        rpc_call(url, cookie, "stop")
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    src = datadir / "regtest" / "store"
    if not src.is_dir():
        print(f"create_cache: missing store at {src}", file=sys.stderr)
        shutil.rmtree(tmp, ignore_errors=True)
        return 1

    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / "store"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    (cache / "HEIGHT").write_text(CACHE_MARK + "\n")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"create_cache: wrote {dest} ({CACHE_MARK})")
    return 0


def preseed_core_dummy(core_src: Path) -> None:
    """Empty blocks/chainstate so Core `_initialize_chain` skips remine."""
    base = core_src / "test" / "cache" / "node0" / "regtest"
    (base / "blocks").mkdir(parents=True, exist_ok=True)
    (base / "chainstate").mkdir(parents=True, exist_ok=True)


def seed_store(node_dir: Path, cache: Path) -> bool:
    """Copy cache store into dest when dest looks like a Core cache tree."""
    if not ((node_dir / "blocks").is_dir() and (node_dir / "chainstate").is_dir()):
        return False
    dest = node_dir / "store"
    src = cache / "store"
    if dest.exists() or not src.is_dir():
        return False
    shutil.copytree(src, dest)
    return True


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    p.add_argument(
        "--preseed-core",
        type=Path,
        default=None,
        help="Create empty node0/regtest/{blocks,chainstate} under this Core src",
    )
    p.add_argument(
        "--ensure",
        action="store_true",
        help="Build only if HEIGHT/store are missing",
    )
    args = p.parse_args(argv)
    if args.preseed_core is not None:
        preseed_core_dummy(args.preseed_core)
        print(f"create_cache: preseeded dummy Core cache under {args.preseed_core}")
        # Preseed alone does not mine. Pair with --ensure to also build.
        if not args.ensure:
            return 0
    if args.ensure and cache_ready(args.cache):
        print(f"create_cache: already ready at {args.cache}")
        return 0
    return build_cache(args.cache)


if __name__ == "__main__":
    sys.exit(main())
