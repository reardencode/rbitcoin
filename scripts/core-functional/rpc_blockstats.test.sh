#!/usr/bin/env bash
# Pin the proxy's Core getblockstats utxo_size_inc / utxo_size_inc_actual.
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="${PWD}${PYTHONPATH:+:${PYTHONPATH}}"
python3 - <<'PY'
from rpc_blockstats import getblockstats_with_sizes, utxo_size_stats
from rpc_proxy import RpcError

P2WPKH = "0014" + "11" * 20  # 22 bytes: 8 + 1 + 22 + 41 = 72
OP_RETURN = "6a"  # 1 byte: 8 + 1 + 1 + 41 = 51
coinbase = {
    "vin": [{"is_coinbase": True}],
    "vout": [{"scriptpubkey": P2WPKH}, {"scriptpubkey": OP_RETURN}],
}
spend = {
    "vin": [{"is_coinbase": False, "prevout": {"scriptpubkey": P2WPKH}}],
    "vout": [{"scriptpubkey": P2WPKH}, {"scriptpubkey": P2WPKH}],
}
assert utxo_size_stats(5, [coinbase, spend]) == (72 + 51 + 144 - 72, 72 + 144 - 72)
assert utxo_size_stats(0, [coinbase]) == (123, 0), "genesis enters no UTXO"
big = "00" * 300  # compact size 3 bytes: 8 + 3 + 300 + 41
assert utxo_size_stats(1, [{"vin": [{"is_coinbase": True}], "vout": [{"scriptpubkey": big}]}]) == (352, 352)
oversize = "00" * 10_001
assert utxo_size_stats(1, [{"vin": [{"is_coinbase": True}], "vout": [{"scriptpubkey": oversize}]}])[1] == 0

FULL = {"blockhash": "ab" * 32, "height": 5, "txs": 2, "minfee": 7}
calls = []


def forward(params):
    calls.append(params)
    stats = params[1] if len(params) > 1 else None
    if stats:
        bad = [s for s in stats if s not in FULL]
        if bad:
            raise RpcError(-8, f"Invalid selected statistic '{bad[0]}'")
        return {s: FULL[s] for s in stats}
    return dict(FULL)


def esplora(path):
    if path == f"/block/{'ab' * 32}/txids":
        return ["c0", "c1"]
    return {"/tx/c0": coinbase, "/tx/c1": spend}[path]


got = getblockstats_with_sizes([5], forward, esplora)
assert got == {**FULL, "utxo_size_inc": 195, "utxo_size_inc_actual": 144}, got

got = getblockstats_with_sizes({"hash_or_height": 5, "stats": ["utxo_size_inc"]}, forward, esplora)
assert got == {"utxo_size_inc": 195}, got

got = getblockstats_with_sizes([5, ["minfee", "utxo_size_inc_actual"]], forward, esplora)
assert got == {"minfee": 7, "utxo_size_inc_actual": 144}, got

try:
    getblockstats_with_sizes([5, ["minfee", "aaa"]], forward, esplora)
except RpcError as e:
    assert e.code == -8 and "aaa" in e.message, e
else:
    raise AssertionError("an unknown stat still errors")

calls.clear()
got = getblockstats_with_sizes([5, ["minfee"]], lambda p: calls.append(p) or forward(p), lambda _: 1 / 0)
assert got == {"minfee": 7}, "no esplora walk when no size stat is selected"
for odd in (["00", 1, 2], [5, 1], [], {}):
    calls.clear()
    got = getblockstats_with_sizes(odd, lambda p: calls.append(p) or "node", lambda _: 1 / 0)
    assert got == "node" and calls == [odd], "a shape the proxy does not own goes to the node as is"
import socket
import threading
import time

from rpc_blockstats import fetch_esplora_json

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]


def listen_late():
    time.sleep(0.2)
    sock.listen(1)
    conn, _ = sock.accept()
    conn.recv(4096)
    body = b"[1]"
    conn.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n" + body
    )
    conn.close()


threading.Thread(target=listen_late, daemon=True).start()
got = fetch_esplora_json(
    f"http://127.0.0.1:{port}", "/block", attempts=20, pause_s=0.05
)
assert got == [1], got
sock.close()

try:
    fetch_esplora_json("http://127.0.0.1:1", "/nope", attempts=2, pause_s=0.01)
except RpcError as e:
    assert e.code == -1 and "Connection refused" in e.message, e
else:
    raise AssertionError("a closed port must still surface connection refused")

print("rpc_blockstats: ok")
PY
