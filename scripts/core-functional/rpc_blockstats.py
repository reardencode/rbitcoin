"""Core getblockstats utxo_size_inc / utxo_size_inc_actual for the harness.

rbitcoin does not report these two coins-database size stats. Core's
rpc_getblockstats.py requires the full key set, so the proxy computes them
the way Core does from the block's Esplora tx JSON (which carries prevouts).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from rpc_proxy import RpcError

# Core PER_UTXO_OVERHEAD: sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool).
PER_UTXO_OVERHEAD = 41
MAX_SCRIPT_SIZE = 10_000
SIZE_STATS = ("utxo_size_inc", "utxo_size_inc_actual")


def _compact_size_len(n: int) -> int:
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFF_FFFF:
        return 5
    return 9


def _utxo_size(spk_hex: str) -> int:
    n = len(spk_hex) // 2
    return 8 + _compact_size_len(n) + n + PER_UTXO_OVERHEAD


def _unspendable(spk_hex: str) -> bool:
    return spk_hex[:2] == "6a" or len(spk_hex) // 2 > MAX_SCRIPT_SIZE


def utxo_size_stats(height: int, txs: list[dict[str, Any]]) -> tuple[int, int]:
    """(utxo_size_inc, utxo_size_inc_actual) over Esplora-shaped txs."""
    inc = 0
    actual = 0
    for tx in txs:
        for out in tx["vout"]:
            size = _utxo_size(out["scriptpubkey"])
            inc += size
            # Genesis outputs never enter the UTXO set. Regtest has no
            # BIP30-repeat coinbases, the other Core exclusion.
            if height == 0 or _unspendable(out["scriptpubkey"]):
                continue
            actual += size
        for vin in tx["vin"]:
            if vin.get("is_coinbase"):
                continue
            size = _utxo_size(vin["prevout"]["scriptpubkey"])
            inc -= size
            actual -= size
    return inc, actual


def _param(params: Any, idx: int, name: str) -> Any:
    if isinstance(params, dict):
        return params.get(name)
    if isinstance(params, list) and len(params) > idx:
        return params[idx]
    return None


def fetch_esplora_json(
    url: str,
    path: str,
    *,
    attempts: int = 120,
    pause_s: float = 0.25,
) -> Any:
    """GET Esplora JSON, waiting while scripthash materialize still owns startup.

    Esplora binds only after that scan. ``submitblock`` can return first, and
    ``getblockstats`` then reads ``/block`` and ``/tx`` on this port.
    """
    target = url + path
    last: BaseException | None = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(target, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.URLError as e:
            last = e
            reason = e.reason
            refused = isinstance(reason, ConnectionRefusedError) or (
                isinstance(reason, OSError) and getattr(reason, "errno", None) in (111, 61)
            )
            if not refused or i + 1 == attempts:
                raise RpcError(-1, f"<urlopen error {reason}>") from e
            time.sleep(pause_s)
        except (TimeoutError, OSError, json.JSONDecodeError) as e:
            raise RpcError(-1, f"<urlopen error {e}>") from e
    raise RpcError(-1, f"<urlopen error {last}>")


def getblockstats_with_sizes(
    params: Any,
    forward: Callable[[Any], Any],
    esplora: Callable[[str], Any],
) -> Any:
    """Forward getblockstats and add the two size stats Core reports."""
    target = _param(params, 0, "hash_or_height")
    stats = _param(params, 1, "stats")
    too_many = isinstance(params, list) and len(params) > 2
    if target is None or too_many or not (stats is None or isinstance(stats, list)):
        return forward(params)
    if stats:
        rest = [s for s in stats if s not in SIZE_STATS]
        if rest:
            forward([target, rest])
    full = forward([target])
    if not isinstance(full, dict):
        raise RpcError(-1, "getblockstats: unexpected reply")
    if not stats or any(s in SIZE_STATS for s in stats):
        txids = esplora(f"/block/{full['blockhash']}/txids")
        txs = [esplora(f"/tx/{txid}") for txid in txids]
        full["utxo_size_inc"], full["utxo_size_inc_actual"] = utxo_size_stats(
            int(full["height"]), txs
        )
    if not stats:
        return full
    return {s: full[s] for s in stats}
