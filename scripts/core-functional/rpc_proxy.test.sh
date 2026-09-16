#!/usr/bin/env bash
# Contract pin for the test-only RPC proxy (no cargo, no Core).
set -euo pipefail
cd "$(dirname "$0")"
python3 - <<'PY'
import base64
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from rpc_proxy import (
    RpcError,
    RpcProxy,
    core_btc_kvb_to_sat_vb,
    esplora_port,
    node_rpc_port,
    rewrite_core_maxfeerate,
)

assert core_btc_kvb_to_sat_vb(0) == 0
assert core_btc_kvb_to_sat_vb(0.1) == 10_000
assert core_btc_kvb_to_sat_vb("0.10") == 10_000
try:
    core_btc_kvb_to_sat_vb(1)
    raise SystemExit("expected -8 for 1 BTC/kvB")
except RpcError as e:
    assert e.code == -8
    assert "1BTC/kvB" in e.message
item = {
    "method": "sendrawtransaction",
    "params": ["00", 0.1],
}
rewrite_core_maxfeerate(item)
assert item["params"][1] == 10_000, item

assert node_rpc_port(18443) == 28443
assert esplora_port(18443) == 38443
# Consecutive Core rpcports must not share node-RPC / Esplora binds.
for base in (16000, 18443, 20000, 45535):
    seen = set()
    for n in range(12):
        pub = base + n
        ports = {pub, node_rpc_port(pub), esplora_port(pub)}
        assert len(ports) == 3, ports
        assert ports.isdisjoint(seen), (pub, ports & seen)
        seen |= ports
# Wrap stays in range and still misses the public port.
assert node_rpc_port(60000) == 50000
assert esplora_port(50000) == 30000
assert 1 <= esplora_port(56000) <= 65535

COOKIE = "__cookie__:secret"


class FakeNode(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        want = "Basic " + base64.b64encode(COOKIE.encode()).decode()
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        item = json.loads(raw.decode())
        if auth != want:
            body = json.dumps(
                {
                    "result": None,
                    "error": {"code": -32600, "message": "auth"},
                    "id": item.get("id"),
                }
            ).encode()
            self.send_response(401)
        else:
            body = json.dumps(
                {"result": item.get("method"), "error": None, "id": item.get("id")}
            ).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


node = HTTPServer(("127.0.0.1", 0), FakeNode)
threading.Thread(target=node.serve_forever, daemon=True).start()
node_port = node.server_address[1]

proxy = RpcProxy(("127.0.0.1", 0), f"http://127.0.0.1:{node_port}", lambda: COOKIE)
listen_port = proxy._httpd.server_address[1]
proxy.start()
time.sleep(0.05)


def call(method, auth=True):
    tok = base64.b64encode(COOKIE.encode()).decode()
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = "Basic " + tok
    req = urllib.request.Request(
        f"http://127.0.0.1:{listen_port}/",
        data=json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": []}
        ).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


st, body = call("getblockcount")
assert st == 200, st
assert body["result"] == "getblockcount", body
assert body["error"] is None

st, _body = call("getblockcount", auth=False)
assert st == 401, st

proxy.register("echo", lambda p: p)
st, body = call("echo")
assert body["result"] == [], body

# Core sync_mempools calls this; the node omits it. Proxy returns null.
proxy.register("syncwithvalidationinterfacequeue", lambda _: None)
st, body = call("syncwithvalidationinterfacequeue")
assert st == 200, st
assert body["result"] is None, body
assert body["error"] is None, body

node.shutdown()
proxy.shutdown()
print("ok - rpc_proxy forward + local handler")
PY
