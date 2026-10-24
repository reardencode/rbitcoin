#!/usr/bin/env bash
# Run contract for the operator image (needs docker and curl). Text
# contract: ./scripts/dockerfile.test.sh. release.yml runs this per arch on
# a native runner before anything is pushed.
#
# Usage: ./scripts/docker-smoke.sh IMAGE SHA256SUMS
#
# SHA256SUMS is the staged file for that arch. Checks:
#   - node and cli in the image hash to SHA256SUMS
#   - node --version is this tree's workspace version
#   - regtest boots on a fresh named volume as the image user
#   - /healthz answers on a published port
#   - docker exec rbitcoin-cli reaches RPC with no --datadir
#   - SIGTERM gives a clean exit 0 inside the stop timeout
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 IMAGE SHA256SUMS" >&2
  exit 2
fi

IMAGE="$1"
[[ -s "$2" ]] || { echo "error: missing $2" >&2; exit 1; }
SUMS="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=release-lib.sh
source "$HERE/release-lib.sh"
cd "$ROOT"

WANT_VER="$(release_cargo_workspace_version)"

NAME="rbitcoin-smoke-$$"
VOL="rbitcoin-smoke-$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-docker-smoke.XXXXXX")"
# -v: the image declares VOLUME /data, so docker create gives the copy
# container an anonymous volume that plain rm would leave behind.
cleanup() {
  docker rm -f -v "$NAME" "$NAME-cp" >/dev/null 2>&1 || true
  docker volume rm -f "$VOL" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "docker-smoke: FAIL $*" >&2
  if docker inspect "$NAME" >/dev/null 2>&1; then
    echo "--- container log (tail) ---" >&2
    docker logs "$NAME" 2>&1 | tail -n 40 >&2
  fi
  exit 1
}
step() { echo "docker-smoke: $*"; }

step "binaries match $SUMS"
docker create --name "$NAME-cp" "$IMAGE" >/dev/null
for b in rbitcoin-node rbitcoin-cli; do
  docker cp -q "$NAME-cp:/usr/local/bin/$b" "$WORK/$b"
done
docker rm -v "$NAME-cp" >/dev/null
(cd "$WORK" && sha256sum -c --quiet "$SUMS") || fail "image binaries differ from $SUMS"

step "version $WANT_VER"
got="$(docker run --rm "$IMAGE" --version 2>&1)"
[[ "$got" == "rbitcoin-node $WANT_VER" ]] || fail "node --version: $got"
got="$(docker run --rm --entrypoint /usr/local/bin/rbitcoin-cli "$IMAGE" --version 2>&1)"
[[ "$got" == "rbitcoin-cli $WANT_VER" ]] || fail "cli --version: $got"

step "regtest boot on a fresh volume"
docker run -d --name "$NAME" -v "$VOL:/data" -p 127.0.0.1::9332 "$IMAGE" \
  --network regtest --health-listen 0.0.0.0:9332 \
  --rpc-listen 127.0.0.1:18443 >/dev/null
# A node that dies at once (e.g. unwritable datadir) has no port mapping.
port="$(docker port "$NAME" 9332/tcp 2>/dev/null | head -n 1 | sed 's/.*://')" || true
[[ -n "$port" ]] || fail "health port not published (node exited during boot?)"

step "healthz on 127.0.0.1:$port"
ok=""
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$port/healthz" 2>/dev/null; then
    ok=1
    break
  fi
  [[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" == true ]] || fail "node exited during boot"
  sleep 1
done
[[ -n "$ok" ]] || fail "healthz did not answer in 60 s"

step "cli over docker exec"
count=""
for _ in $(seq 1 60); do
  if count="$(docker exec "$NAME" /usr/local/bin/rbitcoin-cli --network regtest getblockcount 2>/dev/null)"; then
    break
  fi
  count=""
  sleep 1
done
[[ "$count" == 0 ]] || fail "getblockcount: ${count:-no answer in 60 s}"

step "SIGTERM stop"
docker stop -t 300 "$NAME" >/dev/null
code="$(docker inspect -f '{{.State.ExitCode}}' "$NAME")"
[[ "$code" == 0 ]] || fail "exit code $code after SIGTERM"
docker logs "$NAME" 2>&1 | grep -q 'node: clean exit' || fail "no clean exit line"

step "ok $IMAGE"
