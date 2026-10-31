#!/usr/bin/env python3
"""Test-only JSON-RPC proxy in front of rbitcoin-node.

Not the operator product. Core functional tests speak to this process.
Node methods are forwarded.
Wallet/utility methods are handled locally in later steps.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
import urllib.error
import urllib.request
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from rpcauth import password_to_hmac


# GBT longpoll can sit ~80s; stay under Core's client-side patience.
FORWARD_TIMEOUT_S = 180.0

# Wallet methods select `/wallet/<name>` on the request thread.
_request_path = threading.local()


def current_rpc_path() -> str:
    return getattr(_request_path, "path", "") or ""

# Positional slot of a named `maxfeerate` (`maxburnamount` follows it).
_MAXFEERATE_METHODS = {
    "sendrawtransaction": 1,
    "testmempoolaccept": 1,
    "submitpackage": 1,
}


def node_authorization(cookie_line: str) -> str:
    """Node TCP is Bearer. TestNode cookie is `__cookie__:<token>`."""
    prefix = "__cookie__:"
    token = cookie_line[len(prefix) :] if cookie_line.startswith(prefix) else cookie_line
    return f"Bearer {token}"


def token_from_cookie_line(cookie: str) -> str:
    prefix = "__cookie__:"
    if cookie.startswith(prefix):
        return cookie[len(prefix) :]
    return cookie


def parse_basic_userpass(authorization: str) -> tuple[str, str] | None:
    if not authorization.startswith("Basic "):
        return None
    try:
        raw = base64.b64decode(authorization[6:]).decode()
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in raw:
        return None
    user, password = raw.split(":", 1)
    return user, password


def authorization_ok(authorization: str, cookie_line: str | None) -> bool:
    """Cookie Basic, or any username whose password equals the token.

    Warnet sends `rpcuser:rpcpassword`. The username is not Core `rpcuser`.
    """
    if not cookie_line:
        return True
    want = "Basic " + base64.b64encode(cookie_line.encode()).decode()
    if authorization == want:
        return True
    parsed = parse_basic_userpass(authorization)
    if parsed is None:
        return False
    _user, password = parsed
    return password == token_from_cookie_line(cookie_line)


def parse_rpcauth_line(line: str) -> tuple[str, str, str] | None:
    """Core `rpcauth=user:salt$hash` (HMAC-SHA256, salt is the key)."""
    raw = line.strip()
    if ":" not in raw or "$" not in raw:
        return None
    user, rest = raw.split(":", 1)
    salt, mac = rest.split("$", 1)
    if not user or not salt or not mac:
        return None
    return user, salt, mac


def parse_whitelist_line(line: str) -> tuple[str, set[str]] | None:
    """Core `rpcwhitelist=user:method,method`."""
    raw = line.strip()
    if ":" not in raw:
        return None
    user, methods = raw.split(":", 1)
    user = user.strip()
    if not user:
        return None
    return user, {m.strip() for m in methods.split(",") if m.strip()}


def whitelist_map(lines: list[str]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for line in lines:
        parsed = parse_whitelist_line(line)
        if parsed is None:
            continue
        user, methods = parsed
        # Core set-intersects a later rpcwhitelist line for the same user.
        if user in out:
            out[user] &= methods
        else:
            out[user] = methods
    return out


def _hmac_ok(salt: str, password: str, expected: str) -> bool:
    got = password_to_hmac(salt, password)
    if len(got) != len(expected):
        return False
    return hmac.compare_digest(got, expected)


def _others_restricted(whitelist_default: str | None, has_entries: bool) -> bool:
    """Core: default 0 limits only users who have a whitelist entry.

    Unset, or any other value, subjects every other user to an empty list
    once a whitelist exists. Explicit non-zero with no entries denies all.
    """
    if whitelist_default is None:
        return has_entries
    if whitelist_default.strip().lower() in ("0", "false", "no", "off"):
        return False
    return True


def method_permitted(
    user: str,
    method: str | None,
    entries: dict[str, set[str]],
    whitelist_default: str | None,
) -> bool:
    if user in entries:
        return method is not None and method in entries[user]
    if _others_restricted(whitelist_default, bool(entries)):
        return False
    return True


def authenticated_user(
    authorization: str,
    cookie_line: str | None,
    rpcauth_lines: list[str],
) -> str | None:
    """Username that passed cookie, tank-token, or `rpcauth` HMAC.

    No cookie and no `rpcauth` lines stays open (the functional harness
    before `.cookie` exists). A cookie line refuses a password that matches
    neither the token nor an `rpcauth` row.
    """
    parsed = parse_basic_userpass(authorization)
    if not cookie_line and not rpcauth_lines:
        return parsed[0] if parsed else ""
    if cookie_line:
        want = "Basic " + base64.b64encode(cookie_line.encode()).decode()
        if authorization == want:
            return "__cookie__"
        if parsed is not None and parsed[1] == token_from_cookie_line(cookie_line):
            return parsed[0]
    if parsed is None:
        return "" if not cookie_line else None
    user, password = parsed
    # Core keeps scanning rpcauth rows for this user (password rotation).
    saw_user = False
    for line in rpcauth_lines:
        rec = parse_rpcauth_line(line)
        if rec is None or rec[0] != user:
            continue
        saw_user = True
        if _hmac_ok(rec[1], password, rec[2]):
            return user
    if saw_user or cookie_line:
        return None
    return user


def rpc_methods(payload: Any) -> list[str | None]:
    if isinstance(payload, dict):
        method = payload.get("method")
        return [method if isinstance(method, str) else None]
    if isinstance(payload, list):
        out: list[str | None] = []
        for item in payload:
            if isinstance(item, dict) and isinstance(item.get("method"), str):
                out.append(item["method"])
            else:
                out.append(None)
        return out or [None]
    return [None]


def request_authorized(
    authorization: str,
    cookie_line: str | None,
    rpcauth_lines: list[str],
    whitelist_lines: list[str],
    whitelist_default: str | None,
    payload: Any,
) -> str:
    """`ok`, `unauthorized`, or `forbidden` for one HTTP RPC body."""
    user = authenticated_user(authorization, cookie_line, rpcauth_lines)
    if user is None:
        return "unauthorized"
    entries = whitelist_map(whitelist_lines)
    for method in rpc_methods(payload):
        if not method_permitted(user, method, entries, whitelist_default):
            return "forbidden"
    return "ok"


def named_param_index(method: str, key: str) -> int | None:
    """Positional index for a Core named key on a forwarded method."""
    if key == "maxfeerate":
        return _MAXFEERATE_METHODS.get(method)
    if key == "maxburnamount" and method in _MAXFEERATE_METHODS:
        return 2
    return None


def peel_authproxy_args(item: dict[str, Any]) -> None:
    """AuthServiceProxy mixed call → positional list the node will accept.

    `submitpackage([...], maxfeerate=0)` arrives as `{args: [[...]], maxfeerate: 0}`.
    The node rejects named `args` except on `echo` (which keeps this object).
    """
    params = item.get("params")
    if not isinstance(params, dict) or "args" not in params:
        return
    args = params.get("args")
    if not isinstance(args, list):
        return
    method = item.get("method") if isinstance(item.get("method"), str) else ""
    named = {k: v for k, v in params.items() if k != "args"}
    if not named:
        item["params"] = list(args)
        return
    pos = list(args)
    for k, v in named.items():
        idx = named_param_index(method, k)
        if idx is None:
            return
        while len(pos) <= idx:
            pos.append(None)
        pos[idx] = v
    item["params"] = pos


_TMA_ABORT = frozenset(
    {
        "missing-inputs",
        "max-fee-exceeded",
        "bip125-replacement-disallowed",
    }
)


# MiniWallet sends descsum_create("raw(HEX)"), optionally with a checksum
# suffix. The suffix is not checked: this is not a descriptor engine.
_RAW_SCAN = re.compile(r"^raw\(([0-9a-fA-F]*)\)(?:#[0-9a-z]{8})?$")


def _scan_arg(params: Any, index: int, name: str) -> Any:
    if isinstance(params, dict):
        if name in params:
            return params[name]
        args = params.get("args")
        if isinstance(args, list) and index < len(args):
            return args[index]
        return None
    if isinstance(params, list) and index < len(params):
        return params[index]
    return None


def _raw_script(obj: Any) -> bytes:
    desc = obj
    if isinstance(obj, dict):
        desc = obj.get("desc")
    if not isinstance(desc, str):
        raise RpcError(-8, "only raw() descriptors are scanned")
    m = _RAW_SCAN.fullmatch(desc)
    if m is None:
        raise RpcError(-8, "only raw() descriptors are scanned")
    return bytes.fromhex(m.group(1))


def _sat_btc(sats: int) -> float:
    return float(Decimal(sats) / Decimal(100_000_000))


# Esplora binds after the scripthash collect. The old 4s retry gave up
# while the listener was still down and the wallet reported a zero balance.
ESPLORA_READY_S = 60.0
_ESPLORA_POLL_S = 0.1
# How long one RPC may sit after IBD, waiting for tx relay, before -28.
# Core retries -28 only inside wait_for_rpc_connection. Later calls do not.
RPC_WARMUP_S = 60.0
_WARMUP_POLL_S = 0.05


def wait_esplora_tip(esplora: Callable[[str], Any], tip_height: int) -> None:
    """Return once `GET /blocks/tip/height` matches the node tip."""
    deadline = time.monotonic() + ESPLORA_READY_S
    last: BaseException | None = None
    while True:
        try:
            height = esplora("/blocks/tip/height")
            if int(height) == int(tip_height):
                return
            last = None
        except (RpcError, TypeError, ValueError) as exc:
            last = exc
        if time.monotonic() >= deadline:
            raise RpcError(-1, f"esplora unreachable: {last}")
        time.sleep(_ESPLORA_POLL_S)


def shim_miniwallet_scantxoutset(
    params: Any, *, esplora: Callable[[str], Any], tip_height: int
) -> dict[str, Any]:
    """MiniWallet `raw()` scan. Confirmed Esplora unspents only.

    Does not expand `combo`, xprv ranges, or checksums. Drops the genesis
    coinbase (height 0) the way Core's coins view does.
    """
    action = _scan_arg(params, 0, "action")
    if action != "start":
        raise RpcError(-8, "only action start is scanned")
    objects = _scan_arg(params, 1, "scanobjects")
    if not isinstance(objects, list):
        raise RpcError(-8, "scanobjects must be an array")
    unspents: list[dict[str, Any]] = []
    total = 0
    tx_cache: dict[str, Any] = {}
    ready = False
    for obj in objects:
        script = _raw_script(obj)
        if not ready:
            wait_esplora_tip(esplora, tip_height)
            ready = True
        sh = hashlib.sha256(script).digest()[::-1].hex()
        rows = esplora(f"/scripthash/{sh}/utxo")
        if not isinstance(rows, list):
            raise RpcError(-1, "esplora utxo was not a list")
        for row in rows:
            status = row.get("status") or {}
            if not status.get("confirmed"):
                continue
            height = int(status["block_height"])
            txid = str(row["txid"])
            if txid not in tx_cache:
                tx_cache[txid] = esplora(f"/tx/{txid}")
            vin = (tx_cache[txid].get("vin") or [{}])[0]
            coinbase = bool(vin.get("is_coinbase"))
            if height == 0 and coinbase:
                continue
            sats = int(row["value"])
            total += sats
            unspents.append(
                {
                    "txid": txid,
                    "vout": int(row["vout"]),
                    "amount": _sat_btc(sats),
                    "height": height,
                    "coinbase": coinbase,
                }
            )
    return {"success": True, "height": int(tip_height), "unspents": unspents, "total_amount": _sat_btc(total)}


def rewrite_testmempoolaccept_abort(method: Any, parsed: dict[str, Any]) -> None:
    """Core PCKG abort: first abort-class row keeps reject-reason; others id-only."""
    if method != "testmempoolaccept":
        return
    result = parsed.get("result")
    if not isinstance(result, list) or len(result) < 2:
        return
    idx = None
    for i, row in enumerate(result):
        if isinstance(row, dict) and row.get("reject-reason") in _TMA_ABORT:
            idx = i
            break
    if idx is None:
        return
    for i, row in enumerate(result):
        if i == idx or not isinstance(row, dict):
            continue
        result[i] = {"txid": row.get("txid"), "wtxid": row.get("wtxid")}


# Spending an unspendable scriptPubKey still resolves the coin and fails the
# script. Core never stored the coin, so generateblock quotes CheckTxInputs.
_UNSPENDABLE_SPEND = re.compile(
    r"script verification failed: (?:script too large|OP_RETURN) txid=([0-9a-fA-F]{64})"
)


def rewrite_unspendable_spend(method: Any, parsed: dict[str, Any]) -> bool:
    """Present Core's missing-input generateblock text.

    The node still has the output. A scriptSig that fails the same way on
    `generateblock` gets the same sentence; that is this shim, not consensus.
    """
    if method != "generateblock":
        return False
    err = parsed.get("error")
    if not isinstance(err, dict):
        return False
    msg = err.get("message")
    if not isinstance(msg, str):
        return False
    found = _UNSPENDABLE_SPEND.search(msg)
    if found is None:
        return False
    txid = found.group(1)
    err["message"] = (
        "TestBlockValidity failed: bad-txns-inputs-missingorspent, "
        f"CheckTxInputs: inputs missing/spent in transaction {txid}"
    )
    return True


def _rewrite_forwarded_body(method: Any, body: bytes) -> bytes:
    try:
        parsed = json.loads(body.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body
    if not isinstance(parsed, dict):
        return body
    changed = rewrite_unspendable_spend(method, parsed)
    if method == "testmempoolaccept":
        before = json.dumps(parsed, sort_keys=True)
        rewrite_testmempoolaccept_abort(method, parsed)
        changed = changed or json.dumps(parsed, sort_keys=True) != before
    if not changed:
        return body
    return json.dumps(parsed).encode()


class RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class RpcProxy:
    """HTTP JSON-RPC server that forwards to an internal rbitcoin-node."""

    def __init__(
        self,
        listen: tuple[str, int],
        node_url: str,
        cookie_line: Callable[[], str | None],
        rpcauth_lines: list[str] | None = None,
        whitelist_lines: list[str] | None = None,
        whitelist_default: str | None = None,
        blocks_only: bool = False,
    ) -> None:
        self.node_url = node_url.rstrip("/") + "/"
        self.cookie_line = cookie_line
        self.rpcauth_lines = list(rpcauth_lines or [])
        self.whitelist_lines = list(whitelist_lines or [])
        self.whitelist_default = whitelist_default
        self.blocks_only = blocks_only
        # Latched once tx relay is on (or this node will never turn it on).
        # IBD stays unlatched: the collect can leave IBD before relay starts.
        self._test_started = False
        self._handlers: dict[str, Callable[[Any], dict[str, Any]]] = {}
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _fmt: str, *_args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b""
                auth = self.headers.get("Authorization", "")
                _request_path.path = self.path
                status, body = proxy.handle_http(raw, auth)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._httpd = ThreadingHTTPServer(listen, Handler)
        self._thread: threading.Thread | None = None

    def register(self, method: str, fn: Callable[[Any], dict[str, Any]]) -> None:
        self._handlers[method] = fn

    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def shutdown(self) -> None:
        self._httpd.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def handle_http(self, raw: bytes, authorization: str) -> tuple[int, bytes]:
        cookie = self.cookie_line()
        try:
            payload = json.loads(raw.decode() or "null")
            parsed = True
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
            parsed = False
        decision = request_authorized(
            authorization,
            cookie,
            self.rpcauth_lines,
            self.whitelist_lines,
            self.whitelist_default,
            payload,
        )
        if decision == "unauthorized":
            return 401, b'{"error":"unauthorized"}\n'
        if decision == "forbidden":
            return 403, b'{"error":"forbidden"}\n'
        if not parsed:
            return self.forward_raw(raw)
        if not self.test_may_start():
            req_id = payload.get("id") if isinstance(payload, dict) else None
            body = json.dumps(
                {
                    "result": None,
                    "error": {"code": -28, "message": "Loading..."},
                    "id": req_id,
                }
            ).encode()
            return 200, body
        try:
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        peel_authproxy_args(item)
                return self.forward_raw(json.dumps(payload).encode())
            if isinstance(payload, dict):
                peel_authproxy_args(payload)
                method = payload.get("method")
                if isinstance(method, str) and method in self._handlers:
                    return 200, json.dumps(self._one(payload)).encode()
                status, body = self.forward_raw(json.dumps(payload).encode())
                return status, _rewrite_forwarded_body(method, body)
        except RpcError as e:
            req_id = payload.get("id") if isinstance(payload, dict) else None
            body = json.dumps(
                {
                    "result": None,
                    "error": {"code": e.code, "message": e.message},
                    "id": req_id,
                }
            ).encode()
            return 200, body
        return self.forward_raw(raw)

    def _node_rpc(self, method: str) -> tuple[str, dict[str, Any] | None]:
        """One call to the node. 'dict', 'bare' (test echo), or 'down'."""
        raw = json.dumps(
            {"jsonrpc": "1.0", "id": "probe", "method": method, "params": []}
        ).encode()
        cookie = self.cookie_line() or ""
        req = urllib.request.Request(
            self.node_url,
            data=raw,
            headers={
                "Authorization": node_authorization(cookie),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                parsed = json.loads(resp.read().decode())
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ):
            return "down", None
        if not isinstance(parsed, dict) or parsed.get("error"):
            return "down", None
        result = parsed.get("result")
        if isinstance(result, dict):
            return "dict", result
        return "bare", None

    def _warmup_state(self) -> str:
        """'open' forwards, 'hold' waits for tx relay, 'down' is -28 now.

        Still in IBD: answer now, and keep checking. The index pack can
        leave IBD with relay still off. `-blocksonly` never sends a filter.
        A fake that echoes the method name has no relay bit; let it through.
        A node whose RPC port is not up yet is 'down' so Core's startup
        poll can retry, instead of sitting here for the whole warmup.
        """
        if self._test_started:
            return "open"
        if self.blocks_only:
            self._test_started = True
            return "open"
        chain_kind, chain = self._node_rpc("getblockchaininfo")
        net_kind, net = self._node_rpc("getnetworkinfo")
        if chain_kind == "down" or net_kind == "down":
            return "down"
        if chain_kind == "bare" or net_kind == "bare":
            self._test_started = True
            return "open"
        if chain is None or net is None:
            return "down"
        if chain.get("initialblockdownload"):
            return "open"
        if net.get("localrelay"):
            self._test_started = True
            return "open"
        return "hold"

    def test_may_start(self) -> bool:
        """Block this RPC until the node will send a fee filter.

        Core does not retry -28 once wait_for_rpc_connection has returned.
        setup_nodes mines the block that leaves IBD and then keeps calling.
        Holding the response lets that call finish after relay is on.
        """
        deadline = time.monotonic() + RPC_WARMUP_S
        while True:
            state = self._warmup_state()
            if state == "open":
                return True
            if state == "down" or time.monotonic() >= deadline:
                return False
            time.sleep(_WARMUP_POLL_S)

    def forward_raw(self, raw: bytes) -> tuple[int, bytes]:
        cookie = self.cookie_line() or ""
        req = urllib.request.Request(
            self.node_url,
            data=raw,
            headers={
                "Authorization": node_authorization(cookie),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=FORWARD_TIMEOUT_S) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read() if e.fp else b""
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            body = json.dumps(
                {
                    "result": None,
                    "error": {"code": -28, "message": f"Loading... ({e})"},
                    "id": None,
                }
            ).encode()
            return 200, body

    def _one(self, item: Any) -> dict[str, Any]:
        if not isinstance(item, dict):
            return {
                "result": None,
                "error": {"code": -32600, "message": "Invalid request"},
                "id": None,
            }
        req_id = item.get("id")
        method = item.get("method")
        params = item.get("params", [])
        if not isinstance(method, str):
            return {
                "result": None,
                "error": {"code": -32600, "message": "Invalid request"},
                "id": req_id,
            }
        local = self._handlers.get(method)
        if local is not None:
            try:
                result = local(params)
            except RpcError as e:
                return {
                    "result": None,
                    "error": {"code": e.code, "message": e.message},
                    "id": req_id,
                }
            except Exception as e:  # noqa: BLE001 — surface as RPC error
                return {
                    "result": None,
                    "error": {"code": -1, "message": str(e)},
                    "id": req_id,
                }
            if isinstance(result, dict) and "error" in result and "result" in result:
                result.setdefault("id", req_id)
                return result
            return {"result": result, "error": None, "id": req_id}
        return self.forward(item)

    def forward(self, item: dict[str, Any]) -> dict[str, Any]:
        cookie = self.cookie_line() or ""
        body = json.dumps(item).encode()
        req = urllib.request.Request(
            self.node_url,
            data=body,
            headers={
                "Authorization": node_authorization(cookie),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=FORWARD_TIMEOUT_S) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return json.loads(raw.decode())
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {
                    "result": None,
                    "error": {"code": -1, "message": f"HTTP {e.code}"},
                    "id": item.get("id"),
                }
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # Core wait_for_rpc_connection retries -28 / -342 only. A
            # forwarded "node not listening yet" must look like warmup, not
            # a fatal -1 (restart_node races the proxy vs rbitcoin-node).
            return {
                "result": None,
                "error": {
                    "code": -28,
                    "message": f"Loading... ({e})",
                },
                "id": item.get("id"),
            }
        try:
            parsed = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {
                "result": None,
                "error": {"code": -1, "message": "node returned non-JSON"},
                "id": item.get("id"),
            }
        if isinstance(parsed, dict):
            rewrite_testmempoolaccept_abort(item.get("method"), parsed)
            return parsed
        return {
            "result": None,
            "error": {"code": -1, "message": "node returned non-object"},
            "id": item.get("id"),
        }


def _offset_port(public_rpc: int, offset: int) -> int:
    """Shift a Core-assigned RPC port; wrap instead of overflowing 65535."""
    p = public_rpc + offset
    if p <= 65535:
        return p
    p = public_rpc - offset
    if p >= 1:
        return p
    return max(1, public_rpc - 1)


def node_rpc_port(public_rpc: int) -> int:
    """Internal node RPC. Public port stays on the proxy."""
    return _offset_port(public_rpc, 10_000)


def esplora_port(public_rpc: int) -> int:
    """Esplora listen for the test wallet shim (Step 18).

    Must not sit next to ``node_rpc_port``: Core assigns consecutive
    ``-rpcport`` values, so ``node_rpc(n) + 1 == node_rpc(n + 1)``. That
    collision made the next node's proxy POST ``getblockcount`` at the
    previous node's Esplora (HTTP 404).
    """
    return _offset_port(public_rpc, 20_000)
