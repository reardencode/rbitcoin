#!/usr/bin/env bash
# Contract pin for the test-only bitcoin-cli shim (no cargo).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLI="$ROOT/scripts/core-functional/bitcoin-cli"
PASS=0
FAIL=0

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-cli-shim.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

out="$(env -u BITCOIN_DATA HOME="$WORKDIR/nohome" "$CLI" getblockcount 2>&1)" || true
if printf '%s' "$out" | grep -q -- "datadir is required"; then
  echo "ok - missing HOME/.bitcoin still requires datadir"
  PASS=$((PASS + 1))
else
  echo "not ok - missing HOME/.bitcoin still requires datadir (got: $out)"
  FAIL=$((FAIL + 1))
fi

HOME_DD="$WORKDIR/home"
mkdir -p "$HOME_DD/.bitcoin/regtest"
printf 'rpcport=18443\nrpcuser=user\nrpcpassword=secret0\n' >"$HOME_DD/.bitcoin/bitcoin.conf"
out="$(env -u BITCOIN_DATA HOME="$HOME_DD" "$CLI" getblockcount 2>&1)" || true
if printf '%s' "$out" | grep -q -- "datadir is required"; then
  echo "not ok - HOME/.bitcoin default datadir still hard-fails (got: $out)"
  FAIL=$((FAIL + 1))
else
  echo "ok - HOME/.bitcoin default datadir"
  PASS=$((PASS + 1))
fi

python3 - "$CLI" "$WORKDIR" <<'PY'
import base64
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

cli, workdir = sys.argv[1], Path(sys.argv[2])
got = {"auth": None, "method": None}


class H(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        got["auth"] = self.headers.get("Authorization", "")
        item = json.loads(raw.decode())
        got["method"] = item.get("method")
        body = json.dumps({"result": 7, "error": None, "id": item.get("id")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


httpd = HTTPServer(("127.0.0.1", 0), H)
port = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
home = workdir / "rpc-home"
dd = home / ".bitcoin"
dd.mkdir(parents=True)
(dd / "bitcoin.conf").write_text(
    f"rpcport={port}\nrpcuser=user\nrpcpassword=secret0\n"
)
env = os.environ.copy()
env["HOME"] = str(home)
env.pop("BITCOIN_DATA", None)
r = subprocess.run(
    [cli, "getblockcount"],
    env=env,
    capture_output=True,
    text=True,
    timeout=10,
)
assert r.returncode == 0, r.stderr
assert r.stdout.strip() == "7", r.stdout
want = "Basic " + base64.b64encode(b"user:secret0").decode()
assert got["auth"] == want, got["auth"]
assert got["method"] == "getblockcount"
httpd.shutdown()
print("ok - bitcoin-cli conf rpcuser/rpcpassword Basic")
PY

echo
echo "$PASS passed, $FAIL failed (plus python pin above)"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
