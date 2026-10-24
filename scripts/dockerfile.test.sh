#!/usr/bin/env bash
# Text contract for the operator image Dockerfile (no docker required).
# The run contract (boot, health, cli, stop) is scripts/docker-smoke.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DF="$ROOT/Dockerfile"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"

# Exact Dockerfile line.
has() { grep -qxF "$1" "$DF"; }
# Line number of the first exact match (empty when absent).
line_of() { grep -nxF "$1" "$DF" | head -n 1 | cut -d: -f1; }
# Exact line $1 appears before exact line $2.
before() {
  local a b
  a="$(line_of "$1")"
  b="$(line_of "$2")"
  [[ -n "$a" && -n "$b" && "$a" -lt "$b" ]]
}

assert_ok "Dockerfile exists" test -f "$DF"

# The image wraps the Release musl binaries. A cargo stage would ship
# different bytes than the GitHub Release asset.
assert_ok "FROM scratch" has 'FROM scratch'
assert_fail "single stage (no cargo build)" grep -qE '^FROM .* AS ' "$DF"
# No RUN, so one runner assembles amd64 + arm64 without emulation.
assert_fail "no RUN" grep -qE '^RUN( |$)' "$DF"
assert_ok "per-platform binaries" has 'ARG TARGETARCH'
# Artifact download drops the exec bit, so the mode is set here.
assert_ok "copies node and cli executable" \
  has 'COPY --chmod=0755 ${TARGETARCH}/rbitcoin-node ${TARGETARCH}/rbitcoin-cli /usr/local/bin/'

# Node and cli both default to ./datadir. WORKDIR after USER is created
# owned by that uid, so /data/datadir is the datadir with no flag.
assert_ok "numeric non-root user" has 'USER 10001:10001'
assert_ok "WORKDIR /data" has 'WORKDIR /data'
assert_ok "WORKDIR after USER" before 'USER 10001:10001' 'WORKDIR /data'
assert_ok "volume /data" has 'VOLUME ["/data"]'

assert_ok "STOPSIGNAL SIGTERM" has 'STOPSIGNAL SIGTERM'
assert_ok "exec-form entrypoint" has 'ENTRYPOINT ["/usr/local/bin/rbitcoin-node"]'
assert_fail "no CMD (args pass through)" grep -qE '^CMD( |\[)' "$DF"
assert_ok "expose mainnet p2p" has 'EXPOSE 8333'
assert_fail "no RBITCOIN_ env knob" grep -qE '^ENV +RBITCOIN_' "$DF"

assert_ok "OCI source label" grep -qE 'org\.opencontainers\.image\.source=' "$DF"
assert_ok "OCI version label" grep -qE 'org\.opencontainers\.image\.version="\$\{VERSION\}"' "$DF"
assert_ok "OCI revision label" grep -qE 'org\.opencontainers\.image\.revision="\$\{REVISION\}"' "$DF"
assert_ok "OCI licenses label" grep -qF 'org.opencontainers.image.licenses="MIT OR Apache-2.0"' "$DF"

echo
echo "passed=$PASS failed=$FAIL"
test "$FAIL" -eq 0
