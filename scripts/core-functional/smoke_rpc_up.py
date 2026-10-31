#!/usr/bin/env python3
"""Start the bitcoind shim like TestNode and assert cookie + getblockcount==0.

The node writes `{datadir}/rpc.token`; the shim mirrors `__cookie__:<token>`
to `{datadir}/.cookie` for BitcoinTestFramework. Needs a built rbitcoin-node
(RBITCOIN_NODE). Not invoked by default cargo test.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHIM = HERE / "bitcoind"


def pick_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def rpc_call(url: str, cookie: str, method: str, params=None):
    body = json.dumps(
        {"jsonrpc": "1.0", "id": "smoke", "method": method, "params": params or []}
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
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    rpcport = pick_port()
    p2pport = pick_port()
    tmp = Path(tempfile.mkdtemp(prefix="rbitcoin-smoke-"))
    datadir = tmp / "node0"
    datadir.mkdir()
    (datadir / "bitcoin.conf").write_text(
        f"regtest=1\n[regtest]\nport={p2pport}\nrpcport={rpcport}\nserver=1\n"
    )
    cookie_path = datadir / "regtest" / ".cookie"
    pid_path = datadir / "regtest" / "bitcoind.pid"
    proc = subprocess.Popen(
        [
            sys.executable,
            str(SHIM),
            f"-datadir={datadir}",
            "-regtest",
            "-server",
            "-disablewallet",
            f"-rpcport={rpcport}",
            f"-port={p2pport}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.poll() is not None:
                err = (proc.stderr.read() or b"").decode()
                print(f"shim exited {proc.returncode}: {err}", file=sys.stderr)
                return 1
            if cookie_path.is_file() and cookie_path.stat().st_size > 0:
                break
            time.sleep(0.1)
        else:
            print(f"no cookie at {cookie_path}", file=sys.stderr)
            return 1
        if not pid_path.is_file():
            print(f"no pid file at {pid_path}", file=sys.stderr)
            return 1
        cookie = cookie_path.read_text().strip()
        if not cookie.startswith("__cookie__:"):
            print(f"bad cookie: {cookie!r}", file=sys.stderr)
            return 1
        url = f"http://127.0.0.1:{rpcport}/"
        last_err = None
        height = None
        while time.time() < deadline:
            try:
                resp = rpc_call(url, cookie, "getblockcount")
                height = resp.get("result")
                break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                last_err = e
                time.sleep(0.1)
        if height != 0:
            print(f"getblockcount={height!r} last_err={last_err}", file=sys.stderr)
            return 1
        rpc_call(url, cookie, "stop")
        proc.wait(timeout=15)
        if proc.returncode not in (0, None):
            # stop requests shutdown; 0 is success.
            pass
        print(f"smoke_rpc_up: ok cookie={cookie_path} height=0")
        return 0
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
