#!/usr/bin/env bash
# Contract pin for the test-only wallet façade (no cargo, no Core suite).
set -euo pipefail
cd "$(dirname "$0")"
python3 - <<'PY'
import base64
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from rpc_proxy import RpcProxy
from rpc_util import COIN
from rpc_wallet import CACHE_WIF_0, register_wallet, script_to_address
from test_framework.address import key_to_p2pkh
from test_framework.key import ECKey
from test_framework.address import base58_to_byte

# --- script_to_address ---
data, _ver = base58_to_byte(CACHE_WIF_0)
key = ECKey()
key.set(data[:32], True)
pub = key.get_pubkey().get_bytes()
p2pkh = key_to_p2pkh(pub)
from test_framework.address import address_to_scriptpubkey

spk = bytes(address_to_scriptpubkey(p2pkh))
assert script_to_address(spk) == p2pkh, (script_to_address(spk), p2pkh)

COOKIE = "__cookie__:secret"
UTXO = {
    "txid": "11" * 32,
    "vout": 0,
    "value": 50 * COIN,
    "status": {"confirmed": True, "block_height": 1},
}
STORE = {"utxos": {p2pkh: [UTXO]}, "rawtxs": {}, "tip": 200}


class FakeNode(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        item = json.loads(self.rfile.read(n).decode())
        method = item.get("method")
        params = item.get("params") or []
        if isinstance(params, dict):
            args = params.get("args") or []
            # flatten a few names
            def g(i, name, default=None):
                if name in params:
                    return params[name]
                return args[i] if i < len(args) else (params.get(str(i), default) if False else (params[list(params)[i]] if False else default))
        else:
            def g(i, name, default=None):
                return params[i] if i < len(params) else default
        result = None
        error = None
        if method == "getblockcount":
            result = STORE["tip"]
        elif method == "gettxout":
            txid = g(0, "txid")
            vout = int(g(1, "n") if g(1, "n") is not None else g(1, "vout") or 0)
            if txid == UTXO["txid"] and vout == 0:
                result = {
                    "value": 50,
                    "confirmations": 200,
                    "coinbase": True,
                    "scriptPubKey": {"hex": spk.hex()},
                }
            else:
                # look at broadcast txs
                result = None
                for hx, txid_s in list(STORE["rawtxs"].items()):
                    pass
                for txid_s, rec in STORE["rawtxs"].items():
                    if txid_s == txid:
                        tx = rec["tx"]
                        if vout < len(tx["vout"]):
                            result = {
                                "value": tx["vout"][vout]["value"],
                                "confirmations": 0,
                                "coinbase": False,
                                "scriptPubKey": tx["vout"][vout]["scriptPubKey"],
                            }
        elif method == "sendrawtransaction":
            hx = g(0, "hexstring")
            from test_framework.messages import tx_from_hex
            from rpc_wallet import script_to_address as s2a

            tx = tx_from_hex(hx)
            txid = tx.txid_hex
            vouts = []
            for o in tx.vout:
                raw = bytes(o.scriptPubKey)
                vouts.append(
                    {
                        "value": o.nValue / COIN,
                        "scriptPubKey": {"hex": raw.hex(), "address": s2a(raw)},
                    }
                )
            STORE["rawtxs"][txid] = {
                "hex": hx,
                "tx": {"vout": vouts},
                "in_mempool": True,
            }
            # spend the cache utxo if consumed
            for vin in tx.vin:
                prev = "%064x" % vin.prevout.hash
                if prev == UTXO["txid"] and vin.prevout.n == 0:
                    STORE["utxos"][p2pkh] = []
            result = txid
        elif method == "getrawtransaction":
            txid = g(0, "txid")
            verbose = g(1, "verbose") or False
            rec = STORE["rawtxs"].get(txid)
            if rec is None:
                error = {"code": -5, "message": "No such mempool or blockchain transaction"}
            elif not verbose:
                result = rec["hex"]
            else:
                result = {
                    "txid": txid,
                    "hex": rec["hex"],
                    "in_mempool": True,
                    "vout": rec["tx"]["vout"],
                    "vin": [],
                }
        else:
            error = {"code": -32601, "message": f"Method not found: {method}"}
        body = json.dumps({"result": result, "error": error, "id": item.get("id")}).encode()
        self.send_response(200 if error is None else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeEsplora(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/blocks/tip/height":
            body = json.dumps(STORE["tip"]).encode()
        elif path.startswith("/address/") and path.endswith("/utxo"):
            addr = path[len("/address/") : -len("/utxo")]
            body = json.dumps(STORE["utxos"].get(addr, [])).encode()
        elif path.startswith("/tx/") and path.endswith("/status"):
            txid = path[len("/tx/") : -len("/status")]
            if txid in STORE["rawtxs"]:
                body = json.dumps({"confirmed": False}).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


node = HTTPServer(("127.0.0.1", 0), FakeNode)
esplora = HTTPServer(("127.0.0.1", 0), FakeEsplora)
threading.Thread(target=node.serve_forever, daemon=True).start()
threading.Thread(target=esplora.serve_forever, daemon=True).start()
node_port = node.server_address[1]
esplora_port = esplora.server_address[1]

proxy = RpcProxy(("127.0.0.1", 0), f"http://127.0.0.1:{node_port}", lambda: COOKIE)
register_wallet(proxy, f"http://127.0.0.1:{esplora_port}")
listen = proxy._httpd.server_address[1]
proxy.start()
time.sleep(0.05)


def call(method, params=None):
    tok = base64.b64encode(COOKIE.encode()).decode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{listen}/",
        data=json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}
        ).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Basic " + tok},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


body = call("getbalance")
assert body["error"] and body["error"]["code"] == -18, body

body = call("createwallet", ["default_wallet"])
assert body["error"] is None, body
assert body["result"]["name"] == "default_wallet", body

from test_framework.descriptors import descsum_create

desc = descsum_create(f"combo({CACHE_WIF_0})")
body = call("importdescriptors", [[{"desc": desc, "timestamp": 0, "label": "coinbase"}]])
assert body["error"] is None, body
assert body["result"][0]["success"] is True, body

body = call("getbalance")
assert body["error"] is None, body
assert body["result"] == 50, body

body = call("listunspent", [0])
assert body["error"] is None, body
assert len(body["result"]) == 1, body
assert body["result"][0]["amount"] == 50, body

# External payee (not imported) so gettransaction.amount is the debit.
dest = "mnonCMyH9TmAsSj3M59DsbH8H63U3RKoFP"

body = call("send", [[{dest: 10}]])
assert body["error"] is None, body
assert body["result"]["complete"] is True, body
txid = body["result"]["txid"]
assert len(txid) == 64, txid

body = call("gettransaction", [txid])
assert body["error"] is None, body
assert body["result"]["confirmations"] == 0, body
assert body["result"]["amount"] == -10, body
assert body["result"]["fee"] < 0, body

body = call("getrawtransaction", [txid, True])
assert body["error"] is None, body
assert any(
    (v.get("scriptPubKey") or {}).get("address") == dest for v in body["result"]["vout"]
), body

print("ok - rpc_wallet createwallet / combo / listunspent / send / gettransaction")
proxy.shutdown()
node.shutdown()
esplora.shutdown()
PY

python3 - <<'PY'
"""Esplora binds after the scripthash collect. Balance must wait, not read as zero."""
import base64
import hashlib
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from rpc_proxy import RpcProxy
from rpc_util import COIN
from rpc_wallet import CACHE_WIF_0, register_wallet
from test_framework.address import address_to_scriptpubkey, base58_to_byte, key_to_p2pkh
from test_framework.descriptors import descsum_create
from test_framework.key import ECKey

data, _ver = base58_to_byte(CACHE_WIF_0)
key = ECKey()
key.set(data[:32], True)
pub = key.get_pubkey().get_bytes()
p2pkh = key_to_p2pkh(pub)
spk = bytes(address_to_scriptpubkey(p2pkh))
sh = hashlib.sha256(spk).digest()[::-1].hex()
TXID = "22" * 32
COOKIE = "__cookie__:secret"
TIP = 200
UTXO = {
    "txid": TXID,
    "vout": 0,
    "value": 50 * COIN,
    "status": {"confirmed": True, "block_height": 1},
}
TX = {"vin": [{"is_coinbase": True}], "vout": [{"value": 50 * COIN}]}


class Node(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        item = json.loads(self.rfile.read(n).decode())
        result = TIP if item.get("method") == "getblockcount" else None
        error = None if result is not None else {"code": -32601, "message": "no"}
        body = json.dumps({"result": result, "error": error, "id": item.get("id")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class Esplora(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/blocks/tip/height":
            body = json.dumps(TIP).encode()
        elif path.startswith("/address/") and path.endswith("/utxo"):
            addr = path[len("/address/") : -len("/utxo")]
            body = json.dumps([UTXO] if addr == p2pkh else []).encode()
        elif path == f"/scripthash/{sh}/utxo":
            body = json.dumps([UTXO]).encode()
        elif path == f"/tx/{TXID}":
            body = json.dumps(TX).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def listen_later(port: int, delay_s: float) -> HTTPServer:
    # Stay down across the old 4s esplora retry. The wallet then waits
    # until this socket accepts. delay_s is that stayed-down interval.
    time.sleep(delay_s)
    httpd = HTTPServer(("127.0.0.1", port), Esplora)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def proxy_on(esplora_port: int) -> tuple[RpcProxy, HTTPServer, int]:
    node = HTTPServer(("127.0.0.1", 0), Node)
    threading.Thread(target=node.serve_forever, daemon=True).start()
    proxy = RpcProxy(
        ("127.0.0.1", 0),
        f"http://127.0.0.1:{node.server_address[1]}",
        lambda: COOKIE,
    )
    register_wallet(proxy, f"http://127.0.0.1:{esplora_port}")
    proxy.start()
    return proxy, node, proxy._httpd.server_address[1]


def call(port: int, method: str, params=None, timeout: float = 30):
    tok = base64.b64encode(COOKIE.encode()).decode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/",
        data=json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + tok,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def import_wallet(port: int) -> None:
    body = call(port, "createwallet", ["w"])
    assert body["error"] is None, body
    desc = descsum_create(f"combo({CACHE_WIF_0})")
    body = call(port, "importdescriptors", [[{"desc": desc, "timestamp": 0}]])
    assert body["error"] is None and body["result"][0]["success"], body


# Listener comes up after the old 4s retry would have given up.
late_port = free_port()
threading.Thread(target=listen_later, args=(late_port, 5), daemon=True).start()
proxy, node, listen = proxy_on(late_port)
import_wallet(listen)
body = call(listen, "getbalance")
assert body["error"] is None, body
assert body["result"] == 50, body
raw = f"raw({spk.hex()})"
body = call(listen, "scantxoutset", ["start", [raw]])
assert body["error"] is None, body
assert body["result"]["total_amount"] == 50, body
assert len(body["result"]["unspents"]) == 1, body
proxy.shutdown()
node.shutdown()
print("ok - balance and scantxoutset wait for a late esplora")

# A listener that never binds is an error, not a zero balance.
import rpc_proxy

_saved_ready = getattr(rpc_proxy, "ESPLORA_READY_S", 60.0)
rpc_proxy.ESPLORA_READY_S = 0.4
dead_port = free_port()
proxy, node, listen = proxy_on(dead_port)
import_wallet(listen)
body = call(listen, "getbalance", timeout=10)
assert body["error"] is not None, body
assert body["error"]["code"] == -1, body
assert "esplora unreachable" in body["error"]["message"], body
assert body["result"] != 0, body
body = call(listen, "scantxoutset", ["start", [raw]], timeout=10)
assert body["error"] is not None, body
assert "esplora unreachable" in body["error"]["message"], body
proxy.shutdown()
node.shutdown()
rpc_proxy.ESPLORA_READY_S = _saved_ready
print("ok - dead esplora is an error, not a zero balance")
PY
