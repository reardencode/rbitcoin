#!/usr/bin/env python3
"""Test-only JSON-RPC proxy in front of rbitcoin-node.

Not the operator product. Core functional tests speak to this process.
Node methods are forwarded; `maxfeerate` BTC/kvB is rewritten to sat/vB.
Wallet/utility methods are handled locally in later steps.
"""

from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable


# GBT longpoll can sit ~80s; stay under Core's client-side patience.
FORWARD_TIMEOUT_S = 180.0

# Node maxfeerate is sat/vB. Core tests speak BTC/kvB.
_MAXFEERATE_METHODS = {
    "sendrawtransaction": 1,
    "testmempoolaccept": 1,
    "submitpackage": 1,
}
_CORE_MAXFEERATE_MSG = (
    "Fee rates larger than or equal to 1BTC/kvB are not accepted"
)


def node_authorization(cookie_line: str) -> str:
    """Node TCP is Bearer. TestNode cookie is `__cookie__:<token>`."""
    prefix = "__cookie__:"
    token = cookie_line[len(prefix) :] if cookie_line.startswith(prefix) else cookie_line
    return f"Bearer {token}"


def parse_basic_userpass(authorization: str) -> tuple[str, str] | None:
    header = authorization.strip()
    rest = header[6:] if header[:6].lower() == "basic " else None
    if rest is None:
        return None
    try:
        raw = base64.b64decode(rest.strip())
        s = raw.decode()
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in s:
        return None
    user, password = s.split(":", 1)
    return user, password


def token_from_cookie_line(cookie: str) -> str:
    if cookie.startswith("__cookie__:"):
        return cookie.split(":", 1)[1]
    return cookie


def authorization_ok(authorization: str, cookie_line: str | None) -> bool:
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


def core_btc_kvb_to_sat_vb(value: Any) -> int:
    """Core `maxfeerate` BTC/kvB → node sat/vB. `>= 1` is Core `-8`."""
    if value is None:
        raise RpcError(-8, "Invalid amount")
    if isinstance(value, bool):
        raise RpcError(-8, "Invalid amount")
    if isinstance(value, int):
        btc = float(value)
    elif isinstance(value, float):
        btc = value
    elif isinstance(value, str):
        try:
            btc = float(value.strip())
        except ValueError as e:
            raise RpcError(-8, "Invalid amount") from e
    else:
        raise RpcError(-8, "Invalid amount")
    if btc < 0:
        raise RpcError(-8, "Amount out of range")
    if btc >= 1:
        raise RpcError(-8, _CORE_MAXFEERATE_MSG)
    return int(round(btc * 100_000))


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


def rewrite_core_maxfeerate(item: dict[str, Any]) -> None:
    method = item.get("method")
    idx = _MAXFEERATE_METHODS.get(method) if isinstance(method, str) else None
    if idx is None:
        return
    params = item.get("params", [])
    if isinstance(params, list):
        if len(params) > idx and params[idx] is not None:
            params[idx] = core_btc_kvb_to_sat_vb(params[idx])
    elif isinstance(params, dict) and "maxfeerate" in params:
        params["maxfeerate"] = core_btc_kvb_to_sat_vb(params["maxfeerate"])


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
    ) -> None:
        self.node_url = node_url.rstrip("/") + "/"
        self.cookie_line = cookie_line
        self._handlers: dict[str, Callable[[Any], dict[str, Any]]] = {}
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _fmt: str, *_args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b""
                auth = self.headers.get("Authorization", "")
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
        if not authorization_ok(authorization, cookie):
            return 401, b'{"error":"unauthorized"}\n'
        try:
            payload = json.loads(raw.decode() or "null")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.forward_raw(raw)
        try:
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        peel_authproxy_args(item)
                        rewrite_core_maxfeerate(item)
                return self.forward_raw(json.dumps(payload).encode())
            if isinstance(payload, dict):
                peel_authproxy_args(payload)
                rewrite_core_maxfeerate(payload)
                method = payload.get("method")
                if isinstance(method, str) and method in self._handlers:
                    return 200, json.dumps(self._one(payload)).encode()
                return self.forward_raw(json.dumps(payload).encode())
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
