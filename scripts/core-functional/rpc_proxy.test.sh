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

from rpcauth import password_to_hmac
from rpc_proxy import (
    RpcError,
    RpcProxy,
    authenticated_user,
    authorization_ok,
    esplora_port,
    node_authorization,
    node_rpc_port,
    peel_authproxy_args,
    rewrite_testmempoolaccept_abort,
    rewrite_unspendable_spend,
    shim_miniwallet_scantxoutset,
    whitelist_map,
)

txid = "ab" * 32
native = {
    "result": None,
    "error": {
        "code": -25,
        "message": (
            "TestBlockValidity failed: consensus: "
            f"script verification failed: script too large txid={txid} vin=0"
        ),
    },
    "id": 1,
}
assert rewrite_unspendable_spend("generateblock", native)
assert native["error"]["message"] == (
    "TestBlockValidity failed: bad-txns-inputs-missingorspent, "
    f"CheckTxInputs: inputs missing/spent in transaction {txid}"
), native
op_return = {
    "result": None,
    "error": {
        "code": -25,
        "message": f"script verification failed: OP_RETURN txid={txid} vin=1",
    },
    "id": 1,
}
assert rewrite_unspendable_spend("generateblock", op_return)
assert "inputs missing/spent" in op_return["error"]["message"]
kept = {
    "result": None,
    "error": {"code": -25, "message": "TestBlockValidity failed: bad-txns-nonfinal"},
    "id": 1,
}
assert not rewrite_unspendable_spend("generateblock", kept)
assert kept["error"]["message"].endswith("bad-txns-nonfinal")
other_method = {
    "error": {
        "code": -25,
        "message": f"script verification failed: script too large txid={txid} vin=0",
    }
}
assert not rewrite_unspendable_spend("submitblock", other_method)
assert "script too large" in other_method["error"]["message"]
missing_input = {
    "result": None,
    "error": {
        "code": -25,
        "message": (
            "TestBlockValidity failed: bad-txns-inputs-missingorspent "
            f"in transaction {txid}"
        ),
    },
    "id": 1,
}
assert "CheckTxInputs:" not in missing_input["error"]["message"]
assert rewrite_unspendable_spend("generateblock", missing_input)
assert missing_input["error"]["message"] == (
    "TestBlockValidity failed: bad-txns-inputs-missingorspent, "
    f"CheckTxInputs: inputs missing/spent in transaction {txid}"
), missing_input
plain_missing = {
    "result": None,
    "error": {
        "code": -25,
        "message": "TestBlockValidity failed: bad-txns-inputs-missingorspent",
    },
    "id": 1,
}
assert not rewrite_unspendable_spend("generateblock", plain_missing)
assert plain_missing["error"]["message"].endswith("bad-txns-inputs-missingorspent")

seq = {
    "result": [
        {
            "txid": "aa",
            "wtxid": "wa",
            "allowed": True,
            "vsize": 110,
            "fees": {"base": 0.00001},
        },
        {
            "txid": "bb",
            "wtxid": "wb",
            "allowed": False,
            "reject-reason": "missing-inputs",
        },
    ]
}
import hashlib

script = bytes.fromhex("51")
sh = hashlib.sha256(script).digest()[::-1].hex()
txid = "ab" * 32
genesis = "22" * 32
seen = []

def esplora(path):
    seen.append(path)
    if path == "/blocks/tip/height":
        return 5
    if path == f"/scripthash/{sh}/utxo":
        return [
            {
                "txid": txid,
                "vout": 0,
                "value": 50_0000_0000,
                "status": {
                    "confirmed": True,
                    "block_height": 2,
                    "block_hash": "cd" * 32,
                },
            },
            {
                "txid": "11" * 32,
                "vout": 1,
                "value": 1,
                "status": {"confirmed": False},
            },
            {
                "txid": genesis,
                "vout": 0,
                "value": 50_0000_0000,
                "status": {
                    "confirmed": True,
                    "block_height": 0,
                    "block_hash": "00" * 32,
                },
            },
        ]
    if path == f"/tx/{txid}":
        return {"vin": [{"is_coinbase": True}]}
    if path == f"/tx/{genesis}":
        return {"vin": [{"is_coinbase": True}]}
    raise AssertionError(path)

# Checksum suffix is ignored. This is not a descriptor checksum test.
got = shim_miniwallet_scantxoutset(
    {"action": "start", "scanobjects": ["raw(51)#abcd1234"]},
    esplora=esplora,
    tip_height=5,
)
assert got["success"] is True, got
assert got["height"] == 5, got
assert len(got["unspents"]) == 1, got
u = got["unspents"][0]
assert u == {
    "txid": txid,
    "vout": 0,
    "amount": 50.0,
    "height": 2,
    "coinbase": True,
}, u
try:
    shim_miniwallet_scantxoutset(
        ["start", ["combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"]],
        esplora=esplora,
        tip_height=1,
    )
    raise SystemExit("combo must not be expanded")
except RpcError as e:
    assert "raw()" in e.message, e.message
rewrite_testmempoolaccept_abort("testmempoolaccept", seq)
assert seq["result"][0] == {"txid": "aa", "wtxid": "wa"}, seq
assert seq["result"][1]["reject-reason"] == "missing-inputs", seq
lone = {
    "result": [
        {
            "txid": "aa",
            "wtxid": "wa",
            "allowed": False,
            "reject-reason": "missing-inputs",
        }
    ]
}
rewrite_testmempoolaccept_abort("testmempoolaccept", lone)
assert lone["result"][0]["allowed"] is False, lone
ok_pkg = {
    "result": [
        {"txid": "aa", "wtxid": "wa", "allowed": True},
        {"txid": "bb", "wtxid": "wb", "allowed": True},
    ]
}
rewrite_testmempoolaccept_abort("testmempoolaccept", ok_pkg)
assert ok_pkg["result"][0]["allowed"] is True, ok_pkg
fee_abort = {
    "result": [
        {"txid": "aa", "wtxid": "wa", "allowed": True},
        {
            "txid": "bb",
            "wtxid": "wb",
            "allowed": False,
            "reject-reason": "max-fee-exceeded",
        },
        {"txid": "cc", "wtxid": "wc", "allowed": False, "reject-reason": "missing-inputs"},
    ]
}
rewrite_testmempoolaccept_abort("testmempoolaccept", fee_abort)
assert fee_abort["result"][0] == {"txid": "aa", "wtxid": "wa"}, fee_abort
assert fee_abort["result"][1]["reject-reason"] == "max-fee-exceeded", fee_abort
assert fee_abort["result"][2] == {"txid": "cc", "wtxid": "wc"}, fee_abort
rbf_abort = {
    "result": [
        {"txid": "aa", "wtxid": "wa", "allowed": True},
        {
            "txid": "bb",
            "wtxid": "wb",
            "allowed": False,
            "reject-reason": "bip125-replacement-disallowed",
        },
    ]
}
rewrite_testmempoolaccept_abort("testmempoolaccept", rbf_abort)
assert rbf_abort["result"][0] == {"txid": "aa", "wtxid": "wa"}, rbf_abort
send = {"result": [{"txid": "aa", "allowed": True}, {"txid": "bb", "allowed": False}]}
rewrite_testmempoolaccept_abort("sendrawtransaction", send)
assert send["result"][0]["allowed"] is True, send

# AuthServiceProxy mixed: peel `args` into a positional list (echo keeps the object).
mixed = {
    "method": "submitpackage",
    "params": {"args": [["aa", "bb"]], "maxfeerate": 0},
}
peel_authproxy_args(mixed)
assert mixed["params"] == [["aa", "bb"], 0], mixed
echo_mixed = {
    "method": "echo",
    "params": {"args": [0, 1], "arg3": 3},
}
peel_authproxy_args(echo_mixed)
assert echo_mixed["params"] == {"args": [0, 1], "arg3": 3}, echo_mixed
args_only = {"method": "getblockhash", "params": {"args": [0]}}
peel_authproxy_args(args_only)
assert args_only["params"] == [0], args_only
send_mixed = {
    "method": "sendrawtransaction",
    "params": {"args": ["dead"], "maxfeerate": 0.1},
}
peel_authproxy_args(send_mixed)
assert send_mixed["params"] == ["dead", 0.1], send_mixed

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

assert node_authorization("__cookie__:secret") == "Bearer secret"
assert node_authorization("secret") == "Bearer secret"

COOKIE = "__cookie__:secret"
assert authorization_ok("Basic " + base64.b64encode(COOKIE.encode()).decode(), COOKIE)
attacker = "Basic " + base64.b64encode(b"attacker:secret").decode()
assert authorization_ok(attacker, COOKIE), "username is ignored; password must match the token"
assert not authorization_ok(
    "Basic " + base64.b64encode(b"attacker:nope").decode(), COOKIE
)


class FakeNode(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        want = "Bearer secret"
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
            if item.get("method") == "testmempoolaccept":
                result = [
                    {
                        "txid": "aa",
                        "wtxid": "wa",
                        "allowed": False,
                        "reject-reason": "missing-inputs",
                    },
                    {
                        "txid": "bb",
                        "wtxid": "wb",
                        "allowed": True,
                        "fees": {"base": 0.00001},
                    },
                ]
            else:
                result = item.get("method")
            body = json.dumps(
                {"result": result, "error": None, "id": item.get("id")}
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

st, body = call("testmempoolaccept")
assert st == 200, st
assert body["result"][0]["reject-reason"] == "missing-inputs", body
assert body["result"][1] == {"txid": "bb", "wtxid": "wb"}, body

node.shutdown()
proxy.shutdown()
print("ok - rpc_proxy forward + local handler")

# Warnet fork-observer: published rpcauth, whitelist, tank password, cookie.
# Drove through RpcProxy.handle_http (the shim's listen path).
FORK_AUTH = (
    "forkobserver:1418183465eecbd407010cf60811c6a0$"
    "d4e5f0647a63429c218da1302d7f19fe627302aeb0a71a74de55346a25d8057c"
)
FORK_PASSWORD = "tabconf2024"
FORK_WHITELIST = (
    "forkobserver:getchaintips,getblockheader,getblockhash,getblock,getnetworkinfo"
)
TANK_PASSWORD = "secret0"
TANK_COOKIE = f"__cookie__:{TANK_PASSWORD}"


class TankNode(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        item = json.loads(raw.decode())
        if auth != "Bearer " + TANK_PASSWORD:
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
                {
                    "result": item.get("method"),
                    "error": None,
                    "id": item.get("id"),
                }
            ).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


node2 = HTTPServer(("127.0.0.1", 0), TankNode)
threading.Thread(target=node2.serve_forever, daemon=True).start()
proxy2 = RpcProxy(
    ("127.0.0.1", 0),
    f"http://127.0.0.1:{node2.server_address[1]}",
    lambda: TANK_COOKIE,
    rpcauth_lines=[FORK_AUTH],
    whitelist_lines=[FORK_WHITELIST],
    whitelist_default="0",
)
proxy2.start()
port2 = proxy2._httpd.server_address[1]


def call2(method, user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port2}/",
        data=json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": []}
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"raw": raw}
        return e.code, body


def call2_cookie(method):
    token = base64.b64encode(TANK_COOKIE.encode()).decode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port2}/",
        data=json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": []}
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + token,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode())


for method in (
    "getchaintips",
    "getblockheader",
    "getblockhash",
    "getblock",
    "getnetworkinfo",
):
    st, body = call2(method, "forkobserver", FORK_PASSWORD)
    assert st == 200, (method, st, body)
    assert body["result"] == method, (method, body)

st, body = call2("generatetoaddress", "forkobserver", FORK_PASSWORD)
assert st == 403, (st, body)
st, body = call2("generatetoaddress", "user", TANK_PASSWORD)
assert st == 200, (st, body)
assert body["result"] == "generatetoaddress", body
st, body = call2("getblock", "forkobserver", "not-the-password")
assert st == 401, (st, body)
st, body = call2_cookie("generatetoaddress")
assert st == 200, (st, body)
assert body["result"] == "generatetoaddress", body

node2.shutdown()
proxy2.shutdown()
print("ok - fork-observer rpcauth whitelist and tank password")

# Core keeps scanning rpcauth rows for one user. A failed HMAC on the
# first row must not hide a later row that matches (password rotation).
_salt_old = "11" * 16
_salt_new = "22" * 16
_old_line = f"rot:{_salt_old}${password_to_hmac(_salt_old, 'old-pass')}"
_new_line = f"rot:{_salt_new}${password_to_hmac(_salt_new, 'new-pass')}"


def _basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


assert authenticated_user(_basic("rot", "new-pass"), TANK_COOKIE, [_old_line, _new_line]) == "rot"
assert authenticated_user(_basic("rot", "old-pass"), TANK_COOKIE, [_old_line, _new_line]) == "rot"
assert authenticated_user(_basic("rot", "new-pass"), None, [_old_line, _new_line]) == "rot"
assert authenticated_user(_basic("rot", "nope"), TANK_COOKIE, [_old_line, _new_line]) is None
assert authenticated_user(_basic("rot", "nope"), None, [_old_line, _new_line]) is None
print("ok - later rpcauth row for the same user")

# Core set-intersects repeated rpcwhitelist lines for one user.
assert whitelist_map(
    [
        "alice:getblock,getnetworkinfo,getbestblockhash",
        "alice:getblock,getchaintips",
    ]
) == {"alice": {"getblock"}}
print("ok - repeated rpcwhitelist lines intersect")
PY

python3 - <<'PY'
"""Hold the test at warmup until a fee filter can be sent."""
import base64
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import rpc_proxy
from rpc_proxy import RpcProxy

# The immediate -28 case must not sit for the production warmup.
rpc_proxy.RPC_WARMUP_S = 0

COOKIE = "__cookie__:secret"
STATE = {"ibd": True, "relay": False}


class RelayNode(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        item = json.loads(self.rfile.read(n).decode())
        method = item.get("method")
        if method == "getblockchaininfo":
            result = {"initialblockdownload": STATE["ibd"]}
        elif method == "getnetworkinfo":
            result = {"localrelay": STATE["relay"]}
        else:
            result = method
        body = json.dumps(
            {"result": result, "error": None, "id": item.get("id")}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


node = HTTPServer(("127.0.0.1", 0), RelayNode)
threading.Thread(target=node.serve_forever, daemon=True).start()


def start(blocks_only=False):
    proxy = RpcProxy(
        ("127.0.0.1", 0),
        f"http://127.0.0.1:{node.server_address[1]}",
        lambda: COOKIE,
        blocks_only=blocks_only,
    )
    proxy.start()
    return proxy


def call(port, method):
    tok = base64.b64encode(COOKIE.encode()).decode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/",
        data=json.dumps(
            {"jsonrpc": "1.0", "id": 7, "method": method, "params": []}
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + tok,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


proxy = start()
port = proxy._httpd.server_address[1]
body = call(port, "getblockcount")
assert body["error"] is None and body["result"] == "getblockcount", body

STATE["ibd"] = False
body = call(port, "getblockcount")
assert body["result"] is None, body
assert body["error"]["code"] == -28, body
assert "Loading" in body["error"]["message"], body

STATE["relay"] = True
body = call(port, "getblockcount")
assert body["error"] is None and body["result"] == "getblockcount", body
STATE["relay"] = False
body = call(port, "getblockcount")
assert body["error"] is None and body["result"] == "getblockcount", body
proxy.shutdown()
print("ok - rpc stays in warmup until tx relay is on")

STATE["ibd"] = False
STATE["relay"] = False
proxy = start(blocks_only=True)
port = proxy._httpd.server_address[1]
body = call(port, "getblockcount")
assert body["error"] is None and body["result"] == "getblockcount", body
proxy.shutdown()
print("ok - blocks-only does not wait for tx relay")

# A call that arrives out of IBD before relay has to wait, not fail.
rpc_proxy.RPC_WARMUP_S = 3
STATE["ibd"] = False
STATE["relay"] = False
proxy = start()
port = proxy._httpd.server_address[1]


def flip_relay():
    time.sleep(0.4)
    STATE["relay"] = True


threading.Thread(target=flip_relay, daemon=True).start()
started = time.monotonic()
body = call(port, "getblockcount")
waited = time.monotonic() - started
assert body["error"] is None and body["result"] == "getblockcount", body
assert waited >= 0.3, waited
proxy.shutdown()
node.shutdown()
print("ok - rpc waits out the tx-relay gap instead of failing")
PY
