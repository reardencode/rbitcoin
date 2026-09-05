#!/usr/bin/env python3
"""IBD-client serve bench against a live rbitcoin P2P listener.

rbitcoin is BIP324 v2-only (plaintext v1 is disconnected). This script
handshakes as an initiator, walks `getheaders`, then `getdata`
MSG_WITNESS_BLOCK with a 16-hash window (rbitcoin `MAX_SERVE_BLOCKS`).
It counts decrypted `block` payload bytes — the same witness wire
format an IBD peer stores — without validating scripts.

Install cryptography so ChaCha20-Poly1305 is not the bottleneck:

  python3 -m pip install --user cryptography
  python3 scripts/ibd-serve-bench.py 127.0.0.1:8333
  python3 scripts/ibd-serve-bench.py --network signet 127.0.0.1:38333
  python3 scripts/ibd-serve-bench.py --bytes 2G --window 16 127.0.0.1:8333

Ctrl-C prints the totals so far.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import random
import socket
import struct
import sys
import time
from collections import deque
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _CryptoAead

    _HAS_CRYPTO = True
except ImportError:
    _CryptoAead = None
    _HAS_CRYPTO = False

# ── networks ────────────────────────────────────────────────────────────────

def _internal(display_hex: str) -> bytes:
    return bytes.fromhex(display_hex)[::-1]


NETWORKS = {
    "mainnet": {
        "magic": bytes.fromhex("f9beb4d9"),
        "port": 8333,
        "genesis": _internal("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
    },
    "testnet": {
        "magic": bytes.fromhex("0b110907"),
        "port": 18333,
        "genesis": _internal("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
    },
    "signet": {
        "magic": bytes.fromhex("0a03cf40"),
        "port": 38333,
        "genesis": _internal("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
    },
    "regtest": {
        "magic": bytes.fromhex("fabfb5da"),
        "port": 18444,
        "genesis": _internal("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
    },
}

SERVICE_NETWORK = 1
SERVICE_WITNESS = 8
SERVICE_P2P_V2 = 1 << 11
OUR_SERVICES = SERVICE_NETWORK | SERVICE_WITNESS | SERVICE_P2P_V2
PROTOCOL_VERSION = 70016
MSG_WITNESS_BLOCK = 2 | (1 << 30)
MAX_SERVE_BLOCKS = 16
MAX_HEADERS = 2000
MAX_GARBAGE = 4095
REKEY_INTERVAL = 224
USER_AGENT = "/ibd-serve-bench:0.1/"

SHORT_IDS = [
    "",
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
]
SHORT_BY_NAME = {n: i for i, n in enumerate(SHORT_IDS) if n}

# ── sizes / hashes ──────────────────────────────────────────────────────────


def parse_size(s: str) -> int:
    t = s.strip().upper().replace("IB", "").replace("B", "")
    mul = 1
    if t.endswith("G"):
        mul, t = 1 << 30, t[:-1]
    elif t.endswith("M"):
        mul, t = 1 << 20, t[:-1]
    elif t.endswith("K"):
        mul, t = 1 << 10, t[:-1]
    return int(float(t) * mul)


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def h256(b: bytes) -> str:
    return b[::-1].hex()


def tagged_hash(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def hkdf_sha256(length: int, ikm: bytes, salt: bytes, info: bytes) -> bytes:
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    out = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_compact_size(buf: bytes, i: int) -> tuple[int, int]:
    if i >= len(buf):
        raise ValueError("short compact size")
    n = buf[i]
    if n < 0xFD:
        return n, i + 1
    if n == 0xFD:
        return struct.unpack_from("<H", buf, i + 1)[0], i + 3
    if n == 0xFE:
        return struct.unpack_from("<I", buf, i + 1)[0], i + 5
    return struct.unpack_from("<Q", buf, i + 1)[0], i + 9


# ── secp256k1 + ElligatorSwift (handshake only) ─────────────────────────────

_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _modinv(a: int) -> int:
    return pow(a % _P, -1, _P)


class _FE:
    __slots__ = ("n",)

    def __init__(self, n: int = 0):
        self.n = n % _P

    def __add__(self, o):
        return _FE(self.n + (o.n if isinstance(o, _FE) else o))

    def __radd__(self, o):
        return _FE(self.n + o)

    def __sub__(self, o):
        return _FE(self.n - (o.n if isinstance(o, _FE) else o))

    def __rsub__(self, o):
        return _FE((o if not isinstance(o, _FE) else o.n) - self.n)

    def __mul__(self, o):
        return _FE(self.n * (o.n if isinstance(o, _FE) else o))

    def __rmul__(self, o):
        return _FE(self.n * o)

    def __truediv__(self, o):
        return _FE(self.n * _modinv(o.n if isinstance(o, _FE) else o))

    def __neg__(self):
        return _FE(-self.n)

    def __eq__(self, o):
        if isinstance(o, _FE):
            return self.n == o.n
        return self.n == (o % _P)

    def __pow__(self, e):
        return _FE(pow(self.n, e, _P))

    def sqrt(self):
        s = pow(self.n, (_P + 1) // 4, _P)
        if (s * s) % _P == self.n:
            return _FE(s)
        return None

    def is_square(self) -> bool:
        return pow(self.n, (_P - 1) // 2, _P) != _P - 1

    def to_bytes(self) -> bytes:
        return self.n.to_bytes(32, "big")


_MINUS_3_SQRT = _FE(-3).sqrt()
assert _MINUS_3_SQRT is not None


class _GE:
    __slots__ = ("x", "y")

    def __init__(self, x, y):
        self.x = x if isinstance(x, _FE) else _FE(x)
        self.y = y if isinstance(y, _FE) else _FE(y)

    def double(self):
        lam = (3 * self.x * self.x) / (2 * self.y)
        x3 = lam * lam - 2 * self.x
        y3 = lam * (self.x - x3) - self.y
        return _GE(x3, y3)

    def __add__(self, o):
        if o is None:
            return self
        if self.x != o.x:
            lam = (o.y - self.y) / (o.x - self.x)
            x3 = lam * lam - self.x - o.x
            y3 = lam * (self.x - x3) - self.y
            return _GE(x3, y3)
        if self.y == o.y:
            return self.double()
        return None

    def __mul__(self, k: int):
        r = None
        g = self
        while k:
            if k & 1:
                r = g if r is None else r + g
            g = g.double()
            k >>= 1
        return r

    def __rmul__(self, k: int):
        return self * k


_G = _GE(_GX, _GY)


def _valid_x(x: _FE) -> bool:
    return ((x**3) + 7).is_square()


def _xswiftec(u: _FE, t: _FE) -> _FE:
    if u == 0:
        u = _FE(1)
    if t == 0:
        t = _FE(1)
    if u**3 + t**2 + 7 == 0:
        t = _FE(2) * t
    x = (u**3 + 7 - t**2) / (2 * t)
    y = (x + t) / (_MINUS_3_SQRT * u)
    for cand in (u + 4 * y * y, ((-x / y) - u) / 2, ((x / y) - u) / 2):
        if _valid_x(cand):
            return cand
    raise RuntimeError("xswiftec")


def _xswiftec_inv(x: _FE, u: _FE, case: int) -> Optional[_FE]:
    if case & 2 == 0:
        if _valid_x(-x - u):
            return None
        v = x
        s = -(u**3 + 7) / (u * u + u * v + v * v)
    else:
        s = x - u
        if s == 0:
            return None
        r = ((-s) * (4 * (u**3 + 7) + 3 * s * u * u)).sqrt()
        if r is None:
            return None
        if case & 1 and r == 0:
            return None
        v = (-u + r / s) / 2
    w = s.sqrt()
    if w is None:
        return None
    c = case & 5
    if c == 0:
        return -w * (u * (1 - _MINUS_3_SQRT) / 2 + v)
    if c == 1:
        return w * (u * (1 + _MINUS_3_SQRT) / 2 + v)
    if c == 4:
        return w * (u * (1 - _MINUS_3_SQRT) / 2 + v)
    return -w * (u * (1 + _MINUS_3_SQRT) / 2 + v)


def ellswift_create() -> tuple[bytes, bytes]:
    priv = random.randrange(1, _N)
    x = (priv * _G).x
    while True:
        u = _FE(random.randrange(1, _N))
        t = _xswiftec_inv(x, u, random.randrange(0, 8))
        if t is not None:
            return priv.to_bytes(32, "big"), u.to_bytes() + t.to_bytes()


def ellswift_ecdh_xonly(ellswift_theirs: bytes, priv: bytes) -> bytes:
    u = _FE(int.from_bytes(ellswift_theirs[:32], "big"))
    t = _FE(int.from_bytes(ellswift_theirs[32:], "big"))
    px = _xswiftec(u, t)
    yy = (px**3 + 7).sqrt()
    if yy is None:
        raise RuntimeError("lift_x")
    d = int.from_bytes(priv, "big")
    return (d * _GE(px, yy)).x.to_bytes()


def v2_ecdh(priv: bytes, theirs: bytes, ours: bytes, initiating: bool) -> bytes:
    x = ellswift_ecdh_xonly(theirs, priv)
    if initiating:
        return tagged_hash("bip324_ellswift_xonly_ecdh", ours + theirs + x)
    return tagged_hash("bip324_ellswift_xonly_ecdh", theirs + ours + x)


# ── ChaCha20 / Poly1305 ─────────────────────────────────────────────────────

_CHACHA_IDX = (
    (0, 4, 8, 12),
    (1, 5, 9, 13),
    (2, 6, 10, 14),
    (3, 7, 11, 15),
    (0, 5, 10, 15),
    (1, 6, 11, 12),
    (2, 7, 8, 13),
    (3, 4, 9, 14),
)
_CHACHA_C = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl(v: int, b: int) -> int:
    return ((v << b) & 0xFFFFFFFF) | (v >> (32 - b))


def chacha20_block(key: bytes, nonce12: bytes, cnt: int) -> bytes:
    s = [0] * 16
    s[0:4] = _CHACHA_C
    for i in range(8):
        s[4 + i] = int.from_bytes(key[4 * i : 4 * i + 4], "little")
    s[12] = cnt
    for i in range(3):
        s[13 + i] = int.from_bytes(nonce12[4 * i : 4 * i + 4], "little")
    w = list(s)
    for _ in range(10):
        for a, b, c, d in _CHACHA_IDX:
            w[a] = (w[a] + w[b]) & 0xFFFFFFFF
            w[d] = _rotl(w[d] ^ w[a], 16)
            w[c] = (w[c] + w[d]) & 0xFFFFFFFF
            w[b] = _rotl(w[b] ^ w[c], 12)
            w[a] = (w[a] + w[b]) & 0xFFFFFFFF
            w[d] = _rotl(w[d] ^ w[a], 8)
            w[c] = (w[c] + w[d]) & 0xFFFFFFFF
            w[b] = _rotl(w[b] ^ w[c], 7)
    return b"".join(((w[i] + s[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(16))


class _Poly1305:
    MOD = 2**130 - 5

    def __init__(self, key: bytes):
        self.r = int.from_bytes(key[:16], "little") & 0xFFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
        self.s = int.from_bytes(key[16:], "little")
        self.acc = 0

    def add(self, msg: bytes, length: Optional[int] = None, pad: bool = False):
        n = len(msg) if length is None else length
        for i in range((n + 15) // 16):
            chunk = msg[i * 16 : i * 16 + min(16, n - i * 16)]
            val = int.from_bytes(chunk, "little") + 256 ** (16 if pad else len(chunk))
            self.acc = (self.r * (self.acc + val)) % self.MOD
        return self

    def tag(self) -> bytes:
        return ((self.acc + self.s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _aead_encrypt_py(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    out = bytearray()
    for i in range((len(pt) + 63) // 64):
        now = min(64, len(pt) - 64 * i)
        ks = chacha20_block(key, nonce, i + 1)
        out.extend(pt[j + 64 * i] ^ ks[j] for j in range(now))
    poly = _Poly1305(chacha20_block(key, nonce, 0)[:32])
    poly.add(aad, pad=True).add(out, pad=True)
    poly.add(len(aad).to_bytes(8, "little") + len(pt).to_bytes(8, "little"))
    return bytes(out) + poly.tag()


def _aead_decrypt_py(key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> Optional[bytes]:
    if len(ct) < 16:
        return None
    msg_len = len(ct) - 16
    poly = _Poly1305(chacha20_block(key, nonce, 0)[:32])
    poly.add(aad, pad=True)
    poly.add(ct, length=msg_len, pad=True)
    poly.add(len(aad).to_bytes(8, "little") + msg_len.to_bytes(8, "little"))
    if ct[-16:] != poly.tag():
        return None
    out = bytearray()
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        ks = chacha20_block(key, nonce, i + 1)
        out.extend(ct[j + 64 * i] ^ ks[j] for j in range(now))
    return bytes(out)


def _aead_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    if _HAS_CRYPTO:
        return _CryptoAead(key).encrypt(nonce, pt, aad)
    return _aead_encrypt_py(key, nonce, aad, pt)


def _aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> Optional[bytes]:
    if _HAS_CRYPTO:
        try:
            return _CryptoAead(key).decrypt(nonce, ct, aad)
        except Exception:
            return None
    return _aead_decrypt_py(key, nonce, aad, ct)


class FSChaCha20Poly1305:
    def __init__(self, key: bytes):
        self.key = key
        self.n = 0

    def _nonce(self) -> bytes:
        return (self.n % REKEY_INTERVAL).to_bytes(4, "little") + (self.n // REKEY_INTERVAL).to_bytes(
            8, "little"
        )

    def _rekey(self, aad: bytes) -> None:
        if (self.n + 1) % REKEY_INTERVAL == 0:
            rn = b"\xff\xff\xff\xff" + self._nonce()[4:]
            self.key = _aead_encrypt(self.key, rn, aad, b"\x00" * 32)[:32]
        self.n += 1

    def encrypt(self, aad: bytes, pt: bytes) -> bytes:
        out = _aead_encrypt(self.key, self._nonce(), aad, pt)
        self._rekey(aad)
        return out

    def decrypt(self, aad: bytes, ct: bytes) -> Optional[bytes]:
        out = _aead_decrypt(self.key, self._nonce(), aad, ct)
        if out is None:
            return None
        self._rekey(aad)
        return out


class FSChaCha20:
    def __init__(self, key: bytes):
        self.key = key
        self.block_counter = 0
        self.chunk_counter = 0
        self.keystream = b""

    def _ks(self, n: int) -> bytes:
        while len(self.keystream) < n:
            nonce = (0).to_bytes(4, "little") + (self.chunk_counter // REKEY_INTERVAL).to_bytes(
                8, "little"
            )
            self.keystream += chacha20_block(self.key, nonce, self.block_counter)
            self.block_counter += 1
        out, self.keystream = self.keystream[:n], self.keystream[n:]
        return out

    def crypt(self, chunk: bytes) -> bytes:
        ks = self._ks(len(chunk))
        out = bytes(ks[i] ^ chunk[i] for i in range(len(chunk)))
        if (self.chunk_counter + 1) % REKEY_INTERVAL == 0:
            self.key = self._ks(32)
            self.block_counter = 0
        self.chunk_counter += 1
        return out


def init_ciphers(ecdh: bytes, magic: bytes, initiating: bool):
    salt = b"bitcoin_v2_shared_secret" + magic
    keys = {}
    for name, length in (
        ("initiator_L", 32),
        ("initiator_P", 32),
        ("responder_L", 32),
        ("responder_P", 32),
        ("garbage_terminators", 32),
        ("session_id", 32),
    ):
        keys[name] = hkdf_sha256(length, ecdh, salt, name.encode())
    igt, rgt = keys["garbage_terminators"][:16], keys["garbage_terminators"][16:]
    if initiating:
        return (
            FSChaCha20(keys["initiator_L"]),
            FSChaCha20Poly1305(keys["initiator_P"]),
            igt,
            FSChaCha20(keys["responder_L"]),
            FSChaCha20Poly1305(keys["responder_P"]),
            rgt,
        )
    return (
        FSChaCha20(keys["responder_L"]),
        FSChaCha20Poly1305(keys["responder_P"]),
        rgt,
        FSChaCha20(keys["initiator_L"]),
        FSChaCha20Poly1305(keys["initiator_P"]),
        igt,
    )


# ── v2 session ──────────────────────────────────────────────────────────────


class V2:
    def __init__(self, sock: socket.socket, magic: bytes):
        self.s = sock
        self.magic = magic
        self.buf = bytearray()
        self.send_L = self.send_P = self.recv_L = self.recv_P = None
        self.tcp_recv = 0
        self.tcp_sent = 0

    def _read_more(self) -> None:
        chunk = self.s.recv(1024 * 1024)
        if not chunk:
            raise ConnectionError("eof")
        self.tcp_recv += len(chunk)
        self.buf.extend(chunk)

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._read_more()
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def send_all(self, b: bytes) -> None:
        self.s.sendall(b)
        self.tcp_sent += len(b)

    def handshake(self) -> None:
        priv, ours = ellswift_create()
        self.send_all(ours)
        theirs = self.read_exact(64)
        secret = v2_ecdh(priv, theirs, ours, True)
        self.send_L, self.send_P, send_term, self.recv_L, self.recv_P, recv_term = init_ciphers(
            secret, self.magic, True
        )
        # Transport version contents are empty in rust-bitcoin bip324 0.11 (rbitcoin).
        self.send_all(send_term + self._enc_packet(b"", aad=b""))
        # Responder garbage (≤4095) + terminator, then version / decoys.
        maxn = MAX_GARBAGE + 16
        while True:
            if len(self.buf) >= 16:
                idx = bytes(self.buf[: min(len(self.buf), maxn)]).find(recv_term)
                if idx >= 0:
                    garbage = bytes(self.buf[:idx])
                    del self.buf[: idx + 16]
                    break
            if len(self.buf) >= maxn:
                raise RuntimeError("no garbage terminator")
            self._read_more()
        aad = garbage
        while True:
            contents, ignore = self._dec_packet(aad)
            aad = b""
            if not ignore:
                break

    def _enc_packet(self, contents: bytes, aad: bytes = b"", ignore: bool = False) -> bytes:
        header = bytes([0x80 if ignore else 0])
        body = self.send_P.encrypt(aad, header + contents)
        elen = self.send_L.crypt(len(contents).to_bytes(3, "little"))
        return elen + body

    def _dec_packet(self, aad: bytes = b"") -> tuple[bytes, bool]:
        enc_len = self.read_exact(3)
        contents_len = int.from_bytes(self.recv_L.crypt(enc_len), "little")
        rest = self.read_exact(1 + contents_len + 16)
        pt = self.recv_P.decrypt(aad, rest)
        if pt is None:
            raise RuntimeError("aead decrypt failed")
        ignore = bool(pt[0] & 0x80)
        return pt[1:], ignore

    def send_msg(self, command: str, payload: bytes) -> None:
        sid = SHORT_BY_NAME.get(command)
        if sid:
            contents = bytes([sid]) + payload
        else:
            cmd12 = command.encode().ljust(12, b"\x00")[:12]
            contents = b"\x00" + cmd12 + payload
        self.send_all(self._enc_packet(contents))

    def recv_msg(self) -> tuple[str, bytes]:
        while True:
            contents, ignore = self._dec_packet()
            if ignore:
                continue
            if not contents:
                continue
            if contents[0] != 0:
                name = SHORT_IDS[contents[0]] if contents[0] < len(SHORT_IDS) else ""
                if not name:
                    continue
                return name, contents[1:]
            if len(contents) < 13:
                continue
            cmd = contents[1:13].split(b"\x00", 1)[0].decode("ascii", "replace")
            return cmd, contents[13:]


# ── bitcoin messages ────────────────────────────────────────────────────────


def encode_addr(ip: str, port: int, services: int) -> bytes:
    raw = socket.inet_pton(socket.AF_INET, ip) if ":" not in ip else socket.inet_pton(socket.AF_INET6, ip)
    if len(raw) == 4:
        ip16 = b"\x00" * 10 + b"\xff\xff" + raw
    else:
        ip16 = raw
    return struct.pack("<Q", services) + ip16 + struct.pack(">H", port)


def encode_version(start_height: int, nonce: int, recv_ip: str, recv_port: int) -> bytes:
    ua = USER_AGENT.encode()
    return b"".join(
        (
            struct.pack("<i", PROTOCOL_VERSION),
            struct.pack("<Q", OUR_SERVICES),
            struct.pack("<q", int(time.time())),
            encode_addr(recv_ip, recv_port, 0),
            encode_addr("127.0.0.1", 0, OUR_SERVICES),
            struct.pack("<Q", nonce),
            compact_size(len(ua)),
            ua,
            struct.pack("<i", start_height),
            b"\x00",  # relay=false — we are downloading, not taking mempool
        )
    )


def parse_version(payload: bytes) -> dict:
    ver, services, ts = struct.unpack_from("<iQq", payload, 0)
    i = 4 + 8 + 8 + 26 + 26 + 8
    ualen, i = read_compact_size(payload, i)
    ua = payload[i : i + ualen].decode("utf-8", "replace")
    i += ualen
    height = struct.unpack_from("<i", payload, i)[0] if i + 4 <= len(payload) else 0
    return {"version": ver, "services": services, "user_agent": ua, "start_height": height}


def encode_getheaders(locator: list[bytes], stop: bytes = b"\x00" * 32) -> bytes:
    out = struct.pack("<i", PROTOCOL_VERSION) + compact_size(len(locator))
    for h in locator:
        out += h
    return out + stop


def encode_getdata_blocks(hashes: list[bytes]) -> bytes:
    out = compact_size(len(hashes))
    for h in hashes:
        out += struct.pack("<I", MSG_WITNESS_BLOCK) + h
    return out


def parse_headers(payload: bytes) -> list[bytes]:
    n, i = read_compact_size(payload, 0)
    hashes = []
    for _ in range(n):
        hdr = payload[i : i + 80]
        if len(hdr) < 80:
            break
        hashes.append(sha256d(hdr))
        i += 80
        _, i = read_compact_size(payload, i)
    return hashes


# ── IBD loop ────────────────────────────────────────────────────────────────


def fmt_rate(nbytes: int, dt: float) -> str:
    if dt <= 0:
        return "inf"
    bps = nbytes / dt
    if bps >= 1 << 30:
        return f" {bps / (1 << 30):.2f} GiB/s"
    if bps >= 1 << 20:
        return f" {bps / (1 << 20):.2f} MiB/s"
    if bps >= 1 << 10:
        return f" {bps / (1 << 10):.1f} KiB/s"
    return f" {bps:.0f} B/s"


def fmt_bytes(n: int) -> str:
    if n >= 1 << 30:
        return f" {n / (1 << 30):.2f} GiB"
    if n >= 1 << 20:
        return f" {n / (1 << 20):.2f} MiB"
    if n >= 1 << 10:
        return f" {n / (1 << 10):.1f} KiB"
    return f" {n} B"


def run(args: argparse.Namespace) -> int:
    net = NETWORKS[args.network]
    host, port_s = args.peer.rsplit(":", 1) if ":" in args.peer else (args.peer, str(net["port"]))
    port = int(port_s)
    max_bytes = parse_size(args.bytes) if args.bytes else 0
    max_blocks = args.blocks
    window = args.window
    if window < 1 or window > MAX_SERVE_BLOCKS:
        print(
            f"window={window} — rbitcoin silently drops getdata past {MAX_SERVE_BLOCKS} inflight",
            file=sys.stderr,
        )

    if not _HAS_CRYPTO:
        print(
            "warning: 'cryptography' not installed; pure-Python AEAD will cap measured rate.\n"
            "  python3 -m pip install --user cryptography",
            file=sys.stderr,
        )

    sock = socket.create_connection((host, port), timeout=args.timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    except OSError:
        pass
    sock.settimeout(args.timeout)

    t0 = time.perf_counter()
    sess = V2(sock, net["magic"])
    sess.handshake()
    nonce = int.from_bytes(os.urandom(8), "little")
    sess.send_msg("version", encode_version(0, nonce, host, port))
    their = None
    while their is None:
        cmd, payload = sess.recv_msg()
        if cmd == "version":
            their = parse_version(payload)
        elif cmd == "ping":
            sess.send_msg("pong", payload)
    if their["version"] >= 70016:
        sess.send_msg("wtxidrelay", b"")
    sess.send_msg("sendaddrv2", b"")
    sess.send_msg("verack", b"")
    while True:
        cmd, payload = sess.recv_msg()
        if cmd == "verack":
            break
        if cmd == "ping":
            sess.send_msg("pong", payload)
    hs_ms = (time.perf_counter() - t0) * 1000
    print(
        f"handshake {hs_ms:.0f}ms  peer={their['user_agent']!r}  "
        f"version={their['version']}  start_height={their['start_height']}  "
        f"crypto={'cryptography' if _HAS_CRYPTO else 'pure-python'}",
        flush=True,
    )

    locator = [bytes.fromhex(args.from_hash)[::-1]] if args.from_hash else [net["genesis"]]
    want: deque[bytes] = deque()
    inflight: dict[bytes, float] = {}
    seen_headers: set[bytes] = set()
    last_locator = locator[-1]
    headers_done = False
    n_headers = 0

    n_blocks = 0
    n_bytes = 0
    t_blocks = None
    last_print = time.perf_counter()
    last_n_blocks = 0
    last_n_bytes = 0

    def ask_headers() -> None:
        nonlocal last_locator
        loc = [last_locator]
        sess.send_msg("getheaders", encode_getheaders(loc))

    def topup() -> None:
        while len(inflight) < window and want:
            batch = []
            while want and len(batch) + len(inflight) < window:
                h = want.popleft()
                if h in inflight:
                    continue
                batch.append(h)
            if not batch:
                break
            now = time.perf_counter()
            for h in batch:
                inflight[h] = now
            sess.send_msg("getdata", encode_getdata_blocks(batch))

    ask_headers()
    stall = args.stall

    try:
        while True:
            if max_blocks and n_blocks >= max_blocks:
                break
            if max_bytes and n_bytes >= max_bytes:
                break
            if headers_done and not want and not inflight:
                break

            now = time.perf_counter()
            if inflight and stall > 0:
                oldest = min(inflight.values())
                if now - oldest > stall:
                    dropped = [h256(h)[:16] for h, t in inflight.items() if now - t > stall]
                    print(
                        f"stall: no block for {stall:.0f}s "
                        f"({len(dropped)} inflight, e.g. {dropped[0]}…) — "
                        "node may lack those bodies",
                        flush=True,
                    )
                    inflight.clear()
                    if headers_done and not want:
                        break
                    topup()

            try:
                cmd, payload = sess.recv_msg()
            except socket.timeout:
                if inflight:
                    continue
                if not headers_done:
                    ask_headers()
                continue

            if cmd == "ping":
                sess.send_msg("pong", payload)
                continue
            if cmd == "headers":
                hs = parse_headers(payload)
                n_headers += len(hs)
                if hs:
                    last_locator = hs[-1]
                    for h in hs:
                        if h not in seen_headers:
                            seen_headers.add(h)
                            want.append(h)
                    print(f"headers +{len(hs):4d}  total={n_headers}  queued={len(want)}", flush=True)
                    if len(hs) >= MAX_HEADERS and (not max_blocks or n_headers < max_blocks + window):
                        ask_headers()
                    else:
                        headers_done = True
                else:
                    headers_done = True
                topup()
                continue
            if cmd == "block":
                if t_blocks is None:
                    t_blocks = time.perf_counter()
                if len(payload) < 80:
                    continue
                bh = sha256d(payload[:80])
                inflight.pop(bh, None)
                n_blocks += 1
                n_bytes += len(payload)
                topup()
                if not headers_done and len(want) < window * 4:
                    ask_headers()
                now = time.perf_counter()
                if now - last_print >= args.report or n_blocks % 64 == 0:
                    dt = now - last_print
                    dbytes = n_bytes - last_n_bytes
                    dblk = n_blocks - last_n_blocks
                    elapsed = now - (t_blocks or now)
                    print(
                        f"blocks {n_blocks:6d}  {fmt_bytes(n_bytes):>10}  "
                        f"inst {fmt_rate(dbytes, dt):>12}  {dblk / dt if dt else 0:6.1f} blk/s  "
                        f"avg {fmt_rate(n_bytes, elapsed):>12}  "
                        f"inflight={len(inflight)} queued={len(want)}",
                        flush=True,
                    )
                    last_print = now
                    last_n_blocks = n_blocks
                    last_n_bytes = n_bytes
                continue
            if cmd == "notfound":
                # Each inv: 4-byte type + 32-byte hash.
                i = 0
                n, i = read_compact_size(payload, 0)
                for _ in range(n):
                    h = payload[i + 4 : i + 36]
                    inflight.pop(h, None)
                    i += 36
                topup()
    except (KeyboardInterrupt, ConnectionError) as e:
        if isinstance(e, KeyboardInterrupt):
            print("\n^C", flush=True)
        else:
            print(f"disconnect: {e}", flush=True)

    t1 = time.perf_counter()
    elapsed = (t1 - t_blocks) if t_blocks else 0.0
    print()
    print(f"peer          {their['user_agent']}")
    print(f"headers       {n_headers}")
    print(f"blocks        {n_blocks}")
    print(f"block bytes   {n_bytes} ({fmt_bytes(n_bytes).strip()})")
    print(f"tcp recv      {sess.tcp_recv} ({fmt_bytes(sess.tcp_recv).strip()})")
    print(f"tcp sent      {sess.tcp_sent} ({fmt_bytes(sess.tcp_sent).strip()})")
    if elapsed > 0 and n_blocks:
        print(f"wall (blocks) {elapsed:.3f}s")
        print(f"throughput    {fmt_rate(n_bytes, elapsed).strip()}")
        print(f"block rate    {n_blocks / elapsed:.2f} blk/s")
        print(f"avg block     {fmt_bytes(n_bytes // n_blocks).strip()}")
    else:
        print("no blocks received")
    sock.close()
    return 0 if n_blocks else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("peer", nargs="?", default="127.0.0.1:8333", help="host:port (default 127.0.0.1:8333)")
    p.add_argument("--network", default="mainnet", choices=sorted(NETWORKS))
    p.add_argument("--bytes", default="512M", help="stop after this much block payload (0 = no cap)")
    p.add_argument("--blocks", type=int, default=0, help="stop after N blocks (0 = no cap)")
    p.add_argument("--window", type=int, default=MAX_SERVE_BLOCKS, help="getdata inflight (rbitcoin max 16)")
    p.add_argument("--from-hash", default="", help="locator hash (display hex); default genesis")
    p.add_argument("--timeout", type=float, default=30.0, help="socket timeout seconds")
    p.add_argument("--stall", type=float, default=20.0, help="abort inflight if no block this long")
    p.add_argument("--report", type=float, default=1.0, help="progress print interval seconds")
    args = p.parse_args()
    if args.bytes in ("0", "0B", ""):
        args.bytes = ""
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
