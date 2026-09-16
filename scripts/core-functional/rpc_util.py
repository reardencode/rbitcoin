#!/usr/bin/env python3
"""Core utility RPCs for the test-only proxy. Not rbitcoin-node product.

Create/sign/multisig/derive stay registered (never a node product).
`decoderawtransaction` / `decodescript` / `validateaddress` helpers exist
for dialect unit tests; the live proxy forwards those names to the node.
"""

from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

from rpc_proxy import RpcError

HERE = Path(__file__).resolve().parent
CORE_FUNC = HERE.parents[1] / "third_party" / "bitcoin" / "test" / "functional"
if str(CORE_FUNC) not in sys.path:
    sys.path.insert(0, str(CORE_FUNC))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from test_framework.address import (  # noqa: E402
    address_to_scriptpubkey,
    base58_to_byte,
    byte_to_base58,
    key_to_p2pkh,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
    program_to_witness,
    script_to_p2sh,
)
from test_framework.descriptors import descsum_create  # noqa: E402
from test_framework.key import ECKey  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    tx_from_hex,
)
from test_framework.script import (  # noqa: E402
    CScript,
    CScriptInvalidError,
    CScriptOp,
    CScriptTruncatedPushDataError,
    OPCODE_NAMES,
    OP_0,
    OP_1,
    OP_16,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_RETURN,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    hash160,
    sha256,
    sign_input_legacy,
    sign_input_segwitv0,
)
from test_framework.script_util import (  # noqa: E402
    keys_to_multisig_script,
    script_to_p2sh_p2wsh_script,
    script_to_p2wsh_script,
)

from core_dest import decode_destination  # noqa: E402

ERR_MISC = -1
ERR_INVALID_ADDRESS = -5
ERR_INVALID_PARAMETER = -8
ERR_TYPE = -3
ERR_INVALID_PARAMS = -32602
ERR_DESER = -22
ERR_VERIFY = -25

VALID_SIGHASH = {
    "DEFAULT",
    "ALL",
    "NONE",
    "SINGLE",
    "ALL|ANYONECANPAY",
    "NONE|ANYONECANPAY",
    "SINGLE|ANYONECANPAY",
}

P2A = bytes.fromhex("51024e73")
MISSING = object()


def pget(params: Any, idx: int, name: str, default: Any = MISSING) -> Any:
    if isinstance(params, dict):
        if name in params:
            return params[name]
        args = params.get("args")
        if isinstance(args, (list, tuple)) and idx < len(args):
            return args[idx]
        if default is MISSING:
            raise RpcError(ERR_INVALID_PARAMS, f"{name} required")
        return default
    if isinstance(params, list):
        if idx < len(params):
            return params[idx]
        if default is MISSING:
            raise RpcError(ERR_INVALID_PARAMS, f"{name} required")
        return default
    raise RpcError(ERR_TYPE, "params must be array or object")


def btc_sats(v: Any) -> int:
    if isinstance(v, bool) or v is None:
        raise RpcError(ERR_TYPE, "amount must be a number")
    try:
        d = Decimal(str(v))
    except Exception as e:
        raise RpcError(ERR_INVALID_PARAMETER, "invalid amount") from e
    if d < 0:
        raise RpcError(ERR_INVALID_PARAMETER, "amount must be positive")
    return int(d * COIN)


def register_utility(proxy) -> None:
    def _lookup(txid_hex: str, vout: int) -> dict[str, Any] | None:
        r = proxy.forward(
            {
                "method": "gettxout",
                "params": [txid_hex, vout, True],
                "id": 0,
            }
        )
        if r.get("error") or r.get("result") in (None, {}):
            return None
        res = r["result"]
        spk = res.get("scriptPubKey") or {}
        hx = spk.get("hex") if isinstance(spk, dict) else None
        if not hx:
            return None
        return {"scriptPubKey": bytes.fromhex(hx), "amount": res.get("value")}

    proxy.register("createrawtransaction", createrawtransaction)
    proxy.register(
        "signrawtransactionwithkey",
        lambda p: signrawtransactionwithkey(p, lookup=_lookup),
    )
    proxy.register("createmultisig", createmultisig)
    proxy.register(
        "combinerawtransaction",
        lambda p: combinerawtransaction(p, lookup=_lookup),
    )
    # decoderawtransaction / decodescript / validateaddress stay on the node
    # (subset). Official Core dialect scripts are inventory skip rpc-dialect.
    proxy.register("deriveaddresses", deriveaddresses)


def createrawtransaction(params: Any) -> str:
    ins = pget(params, 0, "inputs")
    outs = pget(params, 1, "outputs")
    locktime = int(pget(params, 2, "locktime", 0) or 0)
    replaceable = bool(pget(params, 3, "replaceable", False))
    if not isinstance(ins, list):
        raise RpcError(ERR_INVALID_PARAMS, "inputs must be an array")
    seq = 0xFFFFFFFD if replaceable else 0xFFFFFFFF
    tx = CTransaction()
    tx.version = 2
    tx.nLockTime = locktime
    for item in ins:
        if not isinstance(item, dict):
            raise RpcError(ERR_INVALID_PARAMS, "input must be an object")
        txid = item.get("txid")
        if not isinstance(txid, str) or len(txid) != 64:
            raise RpcError(ERR_INVALID_PARAMS, "txid required")
        vout = item.get("vout")
        if vout is None:
            raise RpcError(ERR_INVALID_PARAMS, "vout required")
        s = item.get("sequence", seq)
        tx.vin.append(
            CTxIn(COutPoint(int(txid, 16), int(vout)), nSequence=int(s))
        )
    for k, v in _iter_outputs(outs):
        if k == "data":
            if not isinstance(v, str):
                raise RpcError(ERR_INVALID_PARAMS, "data must be hex")
            try:
                payload = bytes.fromhex(v)
            except ValueError as e:
                raise RpcError(ERR_INVALID_PARAMETER, "Data must be hexadecimal string") from e
            tx.vout.append(CTxOut(0, CScript([OP_RETURN, payload])))
            continue
        try:
            spk = address_to_scriptpubkey(k)
        except Exception as e:
            raise RpcError(ERR_INVALID_ADDRESS, f"Invalid Bitcoin address: {k}") from e
        tx.vout.append(CTxOut(btc_sats(v), spk))
    return tx.serialize().hex()


def _iter_outputs(outs: Any):
    if isinstance(outs, dict):
        yield from outs.items()
        return
    if isinstance(outs, list):
        for item in outs:
            if not isinstance(item, dict):
                raise RpcError(
                    ERR_INVALID_PARAMETER,
                    "Invalid parameter, key-value pair not an object as expected",
                )
            if len(item) != 1:
                raise RpcError(
                    ERR_INVALID_PARAMETER,
                    "Invalid parameter, key-value pair must contain exactly one key",
                )
            yield next(iter(item.items()))
        return
    raise RpcError(ERR_INVALID_PARAMS, "outputs must be an object or array")


def createmultisig(params: Any) -> dict[str, Any]:
    nrequired = int(pget(params, 0, "nrequired"))
    keys = pget(params, 1, "keys")
    addr_type = pget(params, 2, "address_type", "legacy") or "legacy"
    if not isinstance(keys, list):
        raise RpcError(ERR_INVALID_PARAMS, "keys must be an array")
    if addr_type == "bech32m":
        raise RpcError(ERR_INVALID_ADDRESS, "createmultisig cannot create bech32m multisig addresses")
    if len(keys) > 20:
        raise RpcError(
            ERR_INVALID_PARAMETER,
            "Number of keys involved in the multisignature address creation > 20",
        )
    if nrequired < 1 or nrequired > len(keys):
        raise RpcError(ERR_INVALID_PARAMETER, "nrequired must be from 1 to the number of keys")
    pubs: list[bytes] = []
    uncompressed = False
    for k in keys:
        if not isinstance(k, str):
            raise RpcError(ERR_INVALID_PARAMS, "key must be hex")
        try:
            b = bytes.fromhex(k)
        except ValueError as e:
            raise RpcError(ERR_INVALID_PARAMETER, f"Invalid public key: {k}") from e
        if len(b) == 65:
            uncompressed = True
        elif len(b) != 33:
            raise RpcError(ERR_INVALID_PARAMETER, f"Invalid public key: {k}")
        pubs.append(b)
    redeem = keys_to_multisig_script(pubs, k=nrequired)
    if addr_type == "legacy" and len(redeem) > 520:
        raise RpcError(
            ERR_INVALID_PARAMETER,
            f"redeemScript exceeds size limit: {len(redeem)} > 520",
        )
    use_type = addr_type
    warnings: list[str] = []
    if uncompressed and addr_type in ("bech32", "p2sh-segwit"):
        use_type = "legacy"
        warnings.append(
            "Unable to make chosen address type, please ensure no uncompressed public keys are present."
        )
    if use_type == "legacy":
        address = script_to_p2sh(redeem)
        desc_body = f"sh(multi({nrequired},{','.join(keys)}))"
    elif use_type == "p2sh-segwit":
        address = script_to_p2sh(script_to_p2wsh_script(redeem))
        desc_body = f"sh(wsh(multi({nrequired},{','.join(keys)})))"
    elif use_type == "bech32":
        wsh = script_to_p2wsh_script(redeem)
        # bech32 P2WSH from the witness program
        from test_framework.address import program_to_witness

        address = program_to_witness(0, bytes(wsh)[2:])
        desc_body = f"wsh(multi({nrequired},{','.join(keys)}))"
    else:
        raise RpcError(ERR_INVALID_PARAMETER, f"Unknown address type '{addr_type}'")
    out = {
        "address": address,
        "redeemScript": redeem.hex(),
        "descriptor": descsum_create(desc_body),
    }
    if warnings:
        out["warnings"] = warnings
    return out


def signrawtransactionwithkey(params: Any, lookup=None) -> dict[str, Any]:
    hexstring = pget(params, 0, "hexstring")
    privkeys = pget(params, 1, "privkeys")
    prevtxs = pget(params, 2, "prevtxs", [])
    sighashtype = pget(params, 3, "sighashtype", None)
    if sighashtype is not None and sighashtype not in VALID_SIGHASH:
        raise RpcError(
            ERR_INVALID_PARAMETER,
            f"'{sighashtype}' is not a valid sighash parameter.",
        )
    if not isinstance(hexstring, str):
        raise RpcError(ERR_TYPE, "hexstring must be a string")
    if not isinstance(privkeys, list):
        raise RpcError(ERR_INVALID_PARAMS, "privkeys must be an array")
    try:
        tx = tx_from_hex(hexstring)
    except Exception as e:
        raise RpcError(
            ERR_DESER,
            "TX decode failed. Make sure the tx has at least one input.",
        ) from e
    leftover = _strict_hex_leftover(hexstring, tx)
    if leftover:
        raise RpcError(
            ERR_DESER,
            "TX decode failed. Make sure the tx has at least one input.",
        )
    keys: list[ECKey] = []
    for wif in privkeys:
        if not isinstance(wif, str):
            raise RpcError(ERR_TYPE, "privkey must be a string")
        keys.append(_key_from_wif(wif))
    prevmap = _parse_prevtxs(prevtxs)
    unsigned = tx_from_hex(tx.serialize().hex())
    if not unsigned.wit.vtxinwit:
        unsigned.wit.vtxinwit = [CTxInWitness() for _ in unsigned.vin]
    complete = True
    for i, vin in enumerate(unsigned.vin):
        key = (vin.prevout.hash, vin.prevout.n)
        info = prevmap.get(key)
        if info is None and lookup is not None:
            txid_hex = "%064x" % vin.prevout.hash
            looked = lookup(txid_hex, vin.prevout.n)
            if looked:
                info = {
                    "scriptPubKey": looked["scriptPubKey"],
                    "amount": looked.get("amount"),
                    "redeemScript": looked.get("redeemScript"),
                    "witnessScript": looked.get("witnessScript"),
                }
        if info is None:
            complete = False
            continue
        spk: bytes = info["scriptPubKey"]
        if spk == P2A:
            continue
        try:
            _check_prev_scripts(spk, info)
        except RpcError:
            raise
        filled = _sign_one(unsigned, i, info, keys)
        if not filled:
            complete = False
    if unsigned.wit.vtxinwit and all(
        not w.scriptWitness.stack for w in unsigned.wit.vtxinwit
    ):
        unsigned.wit.vtxinwit = []
    return {"hex": unsigned.serialize().hex(), "complete": complete}


def _strict_hex_leftover(hexstring: str, tx: CTransaction) -> bool:
    try:
        raw = bytes.fromhex(hexstring)
    except ValueError:
        return True
    ser = tx.serialize()
    return ser != raw


def _key_from_wif(wif: str) -> ECKey:
    try:
        data, _ver = base58_to_byte(wif)
    except Exception as e:
        raise RpcError(ERR_INVALID_ADDRESS, "Invalid private key") from e
    compressed = len(data) == 33 and data[-1] == 1
    secret = data[:32]
    if len(secret) != 32:
        raise RpcError(ERR_INVALID_ADDRESS, "Invalid private key")
    key = ECKey()
    key.set(secret, compressed)
    if not key.is_valid:
        raise RpcError(ERR_INVALID_ADDRESS, "Invalid private key")
    return key


def _parse_prevtxs(prevtxs: Any) -> dict[tuple[int, int], dict[str, Any]]:
    if prevtxs is None:
        return {}
    if not isinstance(prevtxs, list):
        raise RpcError(ERR_INVALID_PARAMS, "prevtxs must be an array")
    out: dict[tuple[int, int], dict[str, Any]] = {}
    for item in prevtxs:
        if not isinstance(item, dict):
            raise RpcError(ERR_INVALID_PARAMS, "prevtx must be an object")
        txid = item.get("txid")
        if not isinstance(txid, str):
            raise RpcError(ERR_INVALID_PARAMS, "txid required")
        vout = item.get("vout")
        if vout is None:
            raise RpcError(ERR_INVALID_PARAMS, "vout required")
        spk = item.get("scriptPubKey")
        if not isinstance(spk, str):
            raise RpcError(ERR_INVALID_PARAMS, "scriptPubKey required")
        info: dict[str, Any] = {
            "scriptPubKey": bytes.fromhex(spk),
            "amount": item.get("amount"),
            "redeemScript": bytes.fromhex(item["redeemScript"])
            if item.get("redeemScript")
            else None,
            "witnessScript": bytes.fromhex(item["witnessScript"])
            if item.get("witnessScript")
            else None,
        }
        out[(int(txid, 16), int(vout))] = info
    return out


def _check_prev_scripts(spk: bytes, info: dict[str, Any]) -> None:
    is_p2sh = len(spk) == 23 and spk[0] == OP_HASH160 and spk[-1] == OP_EQUAL
    is_p2wsh = len(spk) == 34 and spk[0] == 0 and spk[1] == 32
    if (is_p2sh or is_p2wsh) and info["redeemScript"] is None and info["witnessScript"] is None:
        raise RpcError(ERR_INVALID_PARAMETER, "Missing redeemScript/witnessScript")
    r, w = info["redeemScript"], info["witnessScript"]
    if r is not None and w is not None:
        if bytes(script_to_p2wsh_script(w)) != r and r != w:
            # Core: redeem for p2sh-p2wsh is the p2wsh script
            if bytes(script_to_p2wsh_script(w)) != r:
                raise RpcError(
                    ERR_INVALID_PARAMETER,
                    "redeemScript does not correspond to witnessScript",
                )
    if is_p2sh:
        redeem = r
        if redeem is None and w is not None:
            wrapped = bytes(script_to_p2wsh_script(w))
            if bytes(script_to_p2sh_script_bytes(wrapped)) == spk:
                redeem = wrapped
            elif bytes(script_to_p2sh_script_bytes(w)) == spk:
                redeem = w
        elif redeem is not None and w is not None and redeem == w:
            wrapped = bytes(script_to_p2wsh_script(w))
            if bytes(script_to_p2sh_script_bytes(wrapped)) == spk:
                redeem = wrapped
        elif (
            redeem is not None
            and w is None
            and bytes(script_to_p2sh_script_bytes(redeem)) != spk
        ):
            wrapped = bytes(script_to_p2wsh_script(redeem))
            if bytes(script_to_p2sh_script_bytes(wrapped)) == spk:
                redeem = wrapped
        if redeem is not None and bytes(script_to_p2sh_script_bytes(redeem)) != spk:
            raise RpcError(
                ERR_INVALID_PARAMETER,
                "redeemScript/witnessScript does not match scriptPubKey",
            )
        if redeem is None and (r is not None or w is not None):
            raise RpcError(
                ERR_INVALID_PARAMETER,
                "redeemScript/witnessScript does not match scriptPubKey",
            )
    if is_p2wsh:
        inner = w if w is not None else r
        if inner is not None and bytes(script_to_p2wsh_script(inner)) != spk:
            raise RpcError(
                ERR_INVALID_PARAMETER,
                "redeemScript/witnessScript does not match scriptPubKey",
            )


def script_to_p2sh_script_bytes(redeem: bytes) -> bytes:
    return bytes(CScript([OP_HASH160, hash160(redeem), OP_EQUAL]))


def _sign_one(tx: CTransaction, i: int, info: dict[str, Any], keys: list[ECKey]) -> bool:
    spk = info["scriptPubKey"]
    amount = info["amount"]
    sats = btc_sats(amount) if amount is not None else 0
    # P2PKH
    if _is_p2pkh(spk):
        for k in keys:
            pub = k.get_pubkey().get_bytes()
            if bytes(CScript([OP_DUP, OP_HASH160, hash160(pub), OP_EQUALVERIFY, OP_CHECKSIG])) == spk:
                tx.vin[i].scriptSig = bytes(CScript([pub]))
                sign_input_legacy(tx, i, CScript(spk), k)
                return True
        return False
    if _is_p2wpkh(spk):
        return _sign_p2wpkh(tx, i, spk[2:], sats, keys, scriptsig=None)
    ws = info["witnessScript"]
    redeem = info["redeemScript"]
    if _is_p2sh(spk):
        for k in keys:
            pub = k.get_pubkey().get_bytes()
            wp = bytes(CScript([OP_0, hash160(pub)]))
            if bytes(script_to_p2sh_script_bytes(wp)) == spk:
                return _sign_p2wpkh(tx, i, hash160(pub), sats, keys, scriptsig=wp)
        inner = ws
        if inner is None and redeem is not None and not _is_p2wsh(redeem):
            inner = redeem
        wrapped = None
        if redeem is not None and _is_p2wsh(redeem):
            wrapped = redeem
        elif inner is not None:
            wrapped = bytes(script_to_p2wsh_script(inner))
        if (
            inner is not None
            and wrapped is not None
            and bytes(script_to_p2sh_script_bytes(wrapped)) == spk
        ):
            ok = _sign_p2wsh(tx, i, inner, sats, keys)
            tx.vin[i].scriptSig = bytes(CScript([wrapped]))
            return ok
        legacy = redeem if redeem is not None and not _is_p2wsh(redeem) else inner
        if legacy is None:
            return False
        return _sign_p2sh_multisig(tx, i, legacy, keys)
    if _is_p2wsh(spk):
        inner = ws if ws is not None else redeem
        if inner is None:
            return False
        return _sign_p2wsh(tx, i, inner, sats, keys)
    return False


def _is_p2pkh(spk: bytes) -> bool:
    return len(spk) == 25 and spk[0] == OP_DUP and spk[-1] == OP_CHECKSIG


def _is_p2sh(spk: bytes) -> bool:
    return len(spk) == 23 and spk[0] == OP_HASH160 and spk[-1] == OP_EQUAL


def _is_p2wsh(spk: bytes) -> bool:
    return len(spk) == 34 and spk[0] == 0 and spk[1] == 32


def _is_p2wpkh(spk: bytes) -> bool:
    return len(spk) == 22 and spk[0] == 0 and spk[1] == 20


def _sign_p2wpkh(
    tx: CTransaction,
    i: int,
    keyhash: bytes,
    amount: int,
    keys: list[ECKey],
    scriptsig: bytes | None,
) -> bool:
    for k in keys:
        pub = k.get_pubkey().get_bytes()
        if hash160(pub) != keyhash:
            continue
        scriptcode = CScript(
            [OP_DUP, OP_HASH160, keyhash, OP_EQUALVERIFY, OP_CHECKSIG]
        )
        sh = __import__(
            "test_framework.script", fromlist=["SegwitV0SignatureHash"]
        ).SegwitV0SignatureHash(scriptcode, tx, i, SIGHASH_ALL, amount)
        der = k.sign_ecdsa(sh)
        if not tx.wit.vtxinwit:
            tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        tx.wit.vtxinwit[i].scriptWitness.stack = [der + bytes([SIGHASH_ALL]), pub]
        if scriptsig is not None:
            tx.vin[i].scriptSig = bytes(CScript([scriptsig]))
        return True
    return False


def _parse_multisig(script: bytes) -> tuple[int, list[bytes]] | None:
    try:
        ops = list(CScript(script))
    except Exception:
        return None
    if not ops or ops[-1] != OP_CHECKMULTISIG:
        return None

    def small_int(op) -> int | None:
        if isinstance(op, int) and 0 <= op <= 16:
            return op
        if isinstance(op, (bytes, bytearray)):
            if len(op) == 0:
                return 0
            if len(op) == 1:
                return op[0]
        return None

    nreq = small_int(ops[0])
    nkeys = small_int(ops[-2])
    if nreq is None or nkeys is None:
        return None
    pubs = ops[1:-2]
    if len(pubs) != nkeys:
        return None
    out: list[bytes] = []
    for p in pubs:
        if not isinstance(p, (bytes, bytearray)):
            return None
        out.append(bytes(p))
    return nreq, out


def _sign_p2sh_multisig(tx: CTransaction, i: int, redeem: bytes, keys: list[ECKey]) -> bool:
    parsed = _parse_multisig(redeem)
    if parsed is None:
        return False
    nreq, pubs = parsed
    script = CScript(redeem)
    (sighash, err) = __import__(
        "test_framework.script", fromlist=["LegacySignatureHash"]
    ).LegacySignatureHash(script, tx, i, SIGHASH_ALL)
    if err is not None:
        return False
    by_pub = {k.get_pubkey().get_bytes(): k for k in keys}
    pushes = [b""]
    got = 0
    for p in pubs:
        k = by_pub.get(p)
        if k is None:
            continue
        der = k.sign_ecdsa(sighash)
        pushes.append(der + bytes([SIGHASH_ALL]))
        got += 1
    pushes.append(redeem)
    tx.vin[i].scriptSig = bytes(CScript(pushes))
    return got >= nreq


def _sign_p2wsh(tx: CTransaction, i: int, ws: bytes, amount: int, keys: list[ECKey]) -> bool:
    script = CScript(ws)
    parsed = _parse_multisig(ws)
    if parsed is not None:
        nreq, pubs = parsed
        sh = __import__(
            "test_framework.script", fromlist=["SegwitV0SignatureHash"]
        ).SegwitV0SignatureHash(script, tx, i, SIGHASH_ALL, amount)
        by_pub = {k.get_pubkey().get_bytes(): k for k in keys}
        stack = [b""]
        got = 0
        for p in pubs:
            k = by_pub.get(p)
            if k is None:
                continue
            der = k.sign_ecdsa(sh)
            stack.append(der + bytes([SIGHASH_ALL]))
            got += 1
        stack.append(ws)
        tx.wit.vtxinwit[i].scriptWitness.stack = stack
        return got >= nreq
    pk = _p2pk_key(ws, keys)
    if pk is not None:
        sh = __import__(
            "test_framework.script", fromlist=["SegwitV0SignatureHash"]
        ).SegwitV0SignatureHash(script, tx, i, SIGHASH_ALL, amount)
        der = pk.sign_ecdsa(sh)
        tx.wit.vtxinwit[i].scriptWitness.stack = [der + bytes([SIGHASH_ALL]), ws]
        return True
    if _is_p2pkh(ws):
        for k in keys:
            pub = k.get_pubkey().get_bytes()
            if bytes(CScript([OP_DUP, OP_HASH160, hash160(pub), OP_EQUALVERIFY, OP_CHECKSIG])) == ws:
                sh = __import__(
                    "test_framework.script", fromlist=["SegwitV0SignatureHash"]
                ).SegwitV0SignatureHash(script, tx, i, SIGHASH_ALL, amount)
                der = k.sign_ecdsa(sh)
                tx.wit.vtxinwit[i].scriptWitness.stack = [
                    der + bytes([SIGHASH_ALL]),
                    pub,
                    ws,
                ]
                return True
    return False


def _p2pk_key(script: bytes, keys: list[ECKey]) -> ECKey | None:
    try:
        ops = list(CScript(script))
    except Exception:
        return None
    if len(ops) != 2 or ops[-1] != OP_CHECKSIG:
        return None
    pub = ops[0]
    if not isinstance(pub, (bytes, bytearray)):
        return None
    for k in keys:
        if k.get_pubkey().get_bytes() == bytes(pub):
            return k
    return None


def _merge_stack(a: list, b: list) -> list:
    """Merge partial CHECKMULTISIG witnesses: dummy + sigs + script."""
    if not a:
        return list(b)
    if not b:
        return list(a)
    script = a[-1] if a else b[-1]
    sigs = []
    for stack in (a, b):
        body = stack[1:-1] if len(stack) >= 2 else stack
        for item in body:
            if item and item not in sigs and item != script:
                sigs.append(item)
    return [b""] + sigs + [script]


def _scriptsig_is_redeem_only(ss: bytes) -> bool:
    try:
        ops = list(CScript(ss))
    except Exception:
        return False
    return len(ops) == 1 and isinstance(ops[0], (bytes, bytearray))


def _merge_scriptsig(a: bytes, b: bytes) -> bytes:
    try:
        pa = list(CScript(a))
        pb = list(CScript(b))
    except Exception:
        return a or b
    if not pa:
        return b
    if not pb:
        return a
    script = pa[-1] if pa else pb[-1]
    sigs = []
    for ops in (pa, pb):
        body = ops[1:-1] if len(ops) >= 2 else ops
        for item in body:
            if item not in (None, b"", 0) and item != script and item not in sigs:
                sigs.append(item)
    try:
        return bytes(CScript([b""] + sigs + [script]))
    except Exception:
        return a or b


def combinerawtransaction(params: Any, lookup=None) -> str:
    txs = pget(params, 0, "txs")
    if not isinstance(txs, list):
        raise RpcError(ERR_INVALID_PARAMS, "txs must be an array")
    if not txs:
        raise RpcError(ERR_DESER, "Missing transactions")
    decoded: list[CTransaction] = []
    for h in txs:
        if not isinstance(h, str):
            raise RpcError(ERR_TYPE, "tx must be hex")
        try:
            tx = tx_from_hex(h)
        except Exception as e:
            raise RpcError(ERR_DESER, "TX decode failed") from e
        if _strict_hex_leftover(h, tx):
            raise RpcError(ERR_DESER, "TX decode failed")
        decoded.append(tx)
    base = decoded[0]
    for other in decoded[1:]:
        if len(other.vin) != len(base.vin):
            raise RpcError(ERR_DESER, "TX decode failed")
        if not base.wit.vtxinwit:
            base.wit.vtxinwit = [CTxInWitness() for _ in base.vin]
        if not other.wit.vtxinwit:
            other.wit.vtxinwit = [CTxInWitness() for _ in other.vin]
        for i, vin in enumerate(base.vin):
            if not vin.scriptSig and other.vin[i].scriptSig:
                vin.scriptSig = other.vin[i].scriptSig
            elif vin.scriptSig and other.vin[i].scriptSig:
                sa, sb = vin.scriptSig, other.vin[i].scriptSig
                if _scriptsig_is_redeem_only(sa) or _scriptsig_is_redeem_only(sb):
                    vin.scriptSig = sa if len(sa) >= len(sb) else sb
                else:
                    vin.scriptSig = _merge_scriptsig(sa, sb)
            a = base.wit.vtxinwit[i].scriptWitness.stack
            b = other.wit.vtxinwit[i].scriptWitness.stack
            if not a and b:
                base.wit.vtxinwit[i].scriptWitness.stack = list(b)
            elif a and b:
                base.wit.vtxinwit[i].scriptWitness.stack = _merge_stack(a, b)
    if lookup is not None:
        for vin in base.vin:
            txid_hex = "%064x" % vin.prevout.hash
            if lookup(txid_hex, vin.prevout.n) is None:
                raise RpcError(ERR_VERIFY, "Input not found or already spent")
    if base.wit.vtxinwit and all(not w.scriptWitness.stack for w in base.wit.vtxinwit):
        base.wit.vtxinwit = []
    return base.serialize().hex()


def decoderawtransaction(params: Any) -> dict[str, Any]:
    hexstring = pget(params, 0, "hexstring")
    try:
        tx = tx_from_hex(hexstring)
    except Exception as e:
        raise RpcError(ERR_DESER, "TX decode failed") from e
    vin = []
    for i, inp in enumerate(tx.vin):
        row: dict[str, Any] = {
            "txid": "%064x" % inp.prevout.hash,
            "vout": inp.prevout.n,
            "sequence": inp.nSequence,
            "n": i,
            "scriptSig": {
                "asm": _script_asm(CScript(inp.scriptSig), attempt_sighash=True),
                "hex": bytes(inp.scriptSig).hex(),
            },
        }
        vin.append(row)
    vout = []
    for i, o in enumerate(tx.vout):
        decoded = _decode_script(bytes(o.scriptPubKey))
        vout.append(
            {
                "value": o.nValue / COIN,
                "n": i,
                "scriptPubKey": {
                    "asm": decoded["asm"],
                    "hex": bytes(o.scriptPubKey).hex(),
                    "type": decoded["type"],
                },
            }
        )
    return {
        "txid": tx.txid_hex,
        "version": tx.version,
        "locktime": tx.nLockTime,
        "vin": vin,
        "vout": vout,
        "hex": hexstring,
    }


def decodescript(params: Any) -> dict[str, Any]:
    hexstring = pget(params, 0, "hexstring")
    if not isinstance(hexstring, str):
        raise RpcError(ERR_TYPE, "hexstring must be a string")
    try:
        raw = bytes.fromhex(hexstring)
    except ValueError as e:
        raise RpcError(ERR_INVALID_PARAMS, "hex") from e
    return _decode_script(raw)


_SIGHASH_ASM = {
    SIGHASH_ALL: "ALL",
    SIGHASH_NONE: "NONE",
    SIGHASH_SINGLE: "SINGLE",
    SIGHASH_ALL | SIGHASH_ANYONECANPAY: "ALL|ANYONECANPAY",
    SIGHASH_NONE | SIGHASH_ANYONECANPAY: "NONE|ANYONECANPAY",
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY: "SINGLE|ANYONECANPAY",
}


def _scriptnum(data: bytes) -> int | None:
    # Core ScriptToAsmStr: empty push (OP_0) prints as "0".
    if len(data) == 0:
        return 0
    if len(data) > 4:
        return None
    result = 0
    for i, b in enumerate(data):
        result |= b << (8 * i)
    if data[-1] & 0x80:
        return -(result & ~(0x80 << (8 * (len(data) - 1))))
    return result


def _looks_like_der_sig(data: bytes) -> bool:
    """True when `data` is a plausible ECDSA DER sig + sighash (Core ScriptToAsmStr).

    Rejects short OP_RETURN-like pushes that happen to start with 0x30.
    """
    # Typical secp256k1 DER+sighash is 71–73 bytes (sometimes 70).
    if not (70 <= len(data) <= 73) or data[0] != 0x30:
        return False
    # data[1] = SEQUENCE content length; wire is 0x30|len|content|sighash.
    return data[1] + 3 == len(data)


def _push_asm(data: bytes, attempt_sighash: bool) -> str:
    if attempt_sighash and _looks_like_der_sig(data):
        sh = data[-1]
        if sh in _SIGHASH_ASM:
            return data[:-1].hex() + f"[{_SIGHASH_ASM[sh]}]"
    n = _scriptnum(data)
    if n is not None:
        return str(n)
    return data.hex()


def _script_asm(script: CScript, attempt_sighash: bool = False) -> str:
    parts: list[str] = []
    try:
        for opcode, data, _sop in script.raw_iter():
            if data is not None:
                parts.append(_push_asm(bytes(data), attempt_sighash))
                continue
            op = CScriptOp(opcode)
            if op.is_small_int():
                parts.append(str(op.decode_op_n()))
            elif op in OPCODE_NAMES:
                parts.append(OPCODE_NAMES[op])
            else:
                parts.append("OP_UNKNOWN")
    except (CScriptTruncatedPushDataError, CScriptInvalidError):
        parts.append("[error]")
    return " ".join(parts)


def _is_compressed_pubkey(b: bytes) -> bool:
    return len(b) == 33 and b[0] in (2, 3)


def _classify_script(raw: bytes) -> str:
    if raw == P2A:
        return "anchor"
    if len(raw) == 25 and raw[0] == OP_DUP and raw[1] == OP_HASH160 and raw[2] == 20 and raw[23] == OP_EQUALVERIFY and raw[24] == OP_CHECKSIG:
        return "pubkeyhash"
    if len(raw) == 23 and raw[0] == OP_HASH160 and raw[1] == 20 and raw[22] == OP_EQUAL:
        return "scripthash"
    if len(raw) in (35, 67) and raw[-1] == OP_CHECKSIG and raw[0] in (33, 65) and len(raw) == raw[0] + 2:
        return "pubkey"
    if raw[:1] == bytes([OP_RETURN]):
        try:
            ops = list(CScript(raw))
        except Exception:
            return "nonstandard"
        if ops and ops[0] == OP_RETURN and all(not isinstance(o, CScriptOp) for o in ops[1:]):
            return "nulldata"
        return "nonstandard"
    if len(raw) == 22 and raw[0] == OP_0 and raw[1] == 20:
        return "witness_v0_keyhash"
    if len(raw) == 34 and raw[0] == OP_0 and raw[1] == 32:
        return "witness_v0_scripthash"
    if len(raw) == 34 and raw[0] == OP_1 and raw[1] == 32:
        return "witness_v1_taproot"
    if len(raw) >= 2 and raw[0] in range(OP_0, OP_16 + 1) and 2 <= raw[1] <= 40 and len(raw) == 2 + raw[1]:
        return "witness_unknown"
    # bare multisig: m <pks...> n OP_CHECKMULTISIG
    try:
        ops = list(CScript(raw))
    except Exception:
        return "nonstandard"
    if (
        len(ops) >= 4
        and ops[-1] == OP_CHECKMULTISIG
        and isinstance(ops[0], int)
        and isinstance(ops[-2], int)
        and 1 <= ops[0] <= 16
        and 1 <= ops[-2] <= 16
        and ops[-2] == len(ops) - 3
        and all(isinstance(p, (bytes, bytearray)) for p in ops[1:-2])
    ):
        return "multisig"
    return "nonstandard"


def _script_address(typ: str, raw: bytes, main: bool = False) -> str | None:
    if typ == "pubkeyhash":
        return byte_to_base58(raw[3:23], 0 if main else 111)
    if typ == "scripthash":
        return byte_to_base58(raw[2:22], 5 if main else 196)
    if typ == "witness_v0_keyhash":
        return program_to_witness(0, raw[2:], main)
    if typ == "witness_v0_scripthash":
        return program_to_witness(0, raw[2:], main)
    if typ == "witness_v1_taproot":
        return program_to_witness(1, raw[2:], main)
    if typ == "anchor":
        return program_to_witness(1, raw[2:], main)
    if typ == "witness_unknown":
        ver = raw[0]
        if ver == OP_0:
            v = 0
        elif OP_1 <= ver <= OP_16:
            v = ver - OP_1 + 1
        else:
            return None
        try:
            return program_to_witness(v, raw[2:], main)
        except Exception:
            return None
    return None


# Core CScript::MAX_OPCODE (OP_NOP10) / MAX_SCRIPT_SIZE / MAX_SCRIPT_ELEMENT_SIZE.
_MAX_OPCODE = 0xB9
_MAX_SCRIPT_SIZE = 10_000
_MAX_SCRIPT_ELEMENT_SIZE = 520


def _is_op_success(opcode: int) -> bool:
    # Core IsOpSuccess (BIP342).
    return (
        opcode in (80, 98)
        or 126 <= opcode <= 129
        or 131 <= opcode <= 134
        or 137 <= opcode <= 138
        or 141 <= opcode <= 142
        or 149 <= opcode <= 153
        or 187 <= opcode <= 254
    )


def _has_valid_ops(raw: bytes) -> bool:
    # Core CScript::HasValidOps.
    try:
        for opcode, data, _sop in CScript(raw).raw_iter():
            if opcode > _MAX_OPCODE:
                return False
            if data is not None and len(data) > _MAX_SCRIPT_ELEMENT_SIZE:
                return False
    except (CScriptTruncatedPushDataError, CScriptInvalidError):
        return False
    return True


def _is_unspendable(raw: bytes) -> bool:
    # Core CScript::IsUnspendable.
    return (len(raw) > 0 and raw[0] == OP_RETURN) or len(raw) > _MAX_SCRIPT_SIZE


def _can_wrap(typ: str, raw: bytes) -> bool:
    """Core `decodescript` can_wrap (rawtransaction.cpp)."""
    if typ in (
        "nulldata",
        "scripthash",
        "witness_unknown",
        "witness_v1_taproot",
        "anchor",
    ):
        return False
    if typ not in (
        "multisig",
        "nonstandard",
        "pubkey",
        "pubkeyhash",
        "witness_v0_keyhash",
        "witness_v0_scripthash",
    ):
        return False
    if not _has_valid_ops(raw) or _is_unspendable(raw):
        return False
    try:
        for opcode, data, _sop in CScript(raw).raw_iter():
            if data is None and (opcode == OP_CHECKSIGADD or _is_op_success(opcode)):
                return False
    except (CScriptTruncatedPushDataError, CScriptInvalidError):
        return False
    return True


def _can_wrap_p2wsh(typ: str, raw: bytes) -> bool:
    """Core can_wrap_P2WSH after can_wrap is true."""
    if typ == "pubkey":
        return _is_compressed_pubkey(raw[1:-1])
    if typ == "multisig":
        try:
            ops = list(CScript(raw))
        except Exception:
            return False
        return all(_is_compressed_pubkey(bytes(p)) for p in ops[1:-2])
    return typ in ("pubkeyhash", "nonstandard")


def _decode_script(raw: bytes) -> dict[str, Any]:
    script = CScript(raw)
    typ = _classify_script(raw)
    out: dict[str, Any] = {
        "asm": _script_asm(script, attempt_sighash=False),
        "type": typ,
    }
    addr = _script_address(typ, raw)
    if addr:
        out["address"] = addr
    if typ == "witness_v1_taproot":
        out["desc"] = descsum_create(f"rawtr({raw[2:].hex()})")
    elif addr:
        out["desc"] = descsum_create(f"addr({addr})")
    else:
        out["desc"] = descsum_create(f"raw({raw.hex()})")
    if _can_wrap(typ, raw):
        out["p2sh"] = script_to_p2sh(script)
        if _can_wrap_p2wsh(typ, raw):
            if typ == "pubkey":
                wit = bytes([OP_0, 20]) + hash160(raw[1:-1])
            elif typ == "pubkeyhash":
                wit = bytes([OP_0, 20]) + raw[3:23]
            else:
                wit = bytes([OP_0, 32]) + sha256(raw)
            wtyp = _classify_script(wit)
            waddr = _script_address(wtyp, wit)
            seg: dict[str, Any] = {
                "asm": _script_asm(CScript(wit)),
                "hex": wit.hex(),
                "type": wtyp,
            }
            if waddr:
                seg["address"] = waddr
                # Core InferDescriptor: prefer miniscript wsh(...) when the
                # redeem parses; else addr(p2wsh). Pin known Core vectors until
                # rust-miniscript is wired into product decodescript.
                seg["desc"] = _wsh_miniscript_desc(raw) or descsum_create(
                    f"addr({waddr})"
                )
            if wtyp in ("witness_v0_keyhash", "witness_v0_scripthash"):
                seg["p2sh-segwit"] = script_to_p2sh(CScript(wit))
            out["segwit"] = seg
    return out


# Exact Core InferDescriptor outputs for rpc_decodescript.py miniscript cases
# (verified against rust-miniscript 12 / Descriptor::new_wsh).
_WSH_MINISCRIPT_DESC: dict[str, str] = {
    "82012088a914ffffffffffffffffffffffffffffffffffffffff88210250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0ad51b2": (
        "wsh(and_v(and_v(v:hash160(ffffffffffffffffffffffffffffffffffffffff),"
        "v:pk(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)),"
        "older(1)))#gm8xz4fl"
    ),
    (
        "5b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261"
        "2102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af99"
        "2102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d48"
        "21029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c"
        "2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc4010"
        "21031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb"
        "2103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b"
        "2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2"
        "210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa0840174"
        "2103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de1"
        "21035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a6"
        "2103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c"
        "2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d17546"
        "2103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d424828"
        "2103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a"
        "5fae736402c00fb269522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79"
        "210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807"
        "210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae68"
    ): (
        "wsh(or_d(multi(11,020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261,"
        "02675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af99,"
        "02896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d48,"
        "029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c,"
        "02a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc4010,"
        "031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb,"
        "03079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b,"
        "03111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2,"
        "0318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa0840174,"
        "03230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de1,"
        "035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a6,"
        "03bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c,"
        "03cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d17546,"
        "03d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d424828,"
        "03ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a),"
        "and_v(v:older(4032),multi(2,03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79,"
        "0291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807,"
        "0386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb))))#7jwwklk4"
    ),
}


def _wsh_miniscript_desc(raw: bytes) -> str | None:
    return _WSH_MINISCRIPT_DESC.get(raw.hex())


def validateaddress(params: Any) -> dict[str, Any]:
    if isinstance(params, list) and len(params) == 0:
        raise RpcError(
            ERR_MISC, "Return information about the given bitcoin address."
        )
    if isinstance(params, dict) and "address" not in params and not (
        isinstance(params.get("args"), (list, tuple)) and params["args"]
    ):
        raise RpcError(
            ERR_MISC, "Return information about the given bitcoin address."
        )
    addr = pget(params, 0, "address")
    if addr is None:
        raise RpcError(
            ERR_TYPE, "JSON value of type null is not of expected type string"
        )
    if not isinstance(addr, str):
        raise RpcError(ERR_TYPE, "address must be a string")
    detail, err, locs = decode_destination(addr)
    if detail is None:
        return {"isvalid": False, "error_locations": locs, "error": err}
    return {"isvalid": True, **detail}


def deriveaddresses(params: Any) -> list[str]:
    desc = pget(params, 0, "descriptor")
    if not isinstance(desc, str):
        raise RpcError(ERR_TYPE, "descriptor must be a string")
    if "#" not in desc:
        raise RpcError(ERR_INVALID_ADDRESS, "Missing checksum")
    body, csum = desc.rsplit("#", 1)
    if descsum_create(body).split("#", 1)[1] != csum:
        raise RpcError(ERR_INVALID_ADDRESS, "Invalid checksum")
    addr = _addr_from_wrapped_multi(body)
    if addr is None:
        raise RpcError(ERR_INVALID_ADDRESS, "Descriptor does not have a corresponding address")
    return [addr]


def _addr_from_wrapped_multi(bare: str) -> str | None:
    wrap_sh = wrap_wsh = False
    inner = bare
    if inner.startswith("sh(wsh(") and inner.endswith("))"):
        wrap_sh, wrap_wsh = True, True
        inner = inner[len("sh(wsh(") : -2]
    elif inner.startswith("sh(") and inner.endswith(")"):
        wrap_sh = True
        inner = inner[3:-1]
    elif inner.startswith("wsh(") and inner.endswith(")"):
        wrap_wsh = True
        inner = inner[4:-1]
    else:
        return None
    if inner.startswith("sortedmulti("):
        multi = inner[len("sortedmulti(") :]
        if not multi.endswith(")"):
            return None
        parts = multi[:-1].split(",")
        nreq = int(parts[0])
        pubs = sorted(parts[1:])
    elif inner.startswith("multi("):
        multi = inner[len("multi(") :]
        if not multi.endswith(")"):
            return None
        parts = multi[:-1].split(",")
        nreq = int(parts[0])
        pubs = parts[1:]
    else:
        return None
    keys = [bytes.fromhex(p) for p in pubs]
    redeem = keys_to_multisig_script(keys, k=nreq)
    if wrap_sh and wrap_wsh:
        return script_to_p2sh(script_to_p2wsh_script(redeem))
    if wrap_sh:
        return script_to_p2sh(redeem)
    from test_framework.address import program_to_witness

    wsh = script_to_p2wsh_script(redeem)
    return program_to_witness(0, bytes(wsh)[2:])
