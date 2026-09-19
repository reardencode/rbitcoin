# Lab image for an all-rbitcoin Warnet tank. Not an operator Release.
# Build from the repo root after `cargo build -p rbitcoin-node` and
# `./scripts/core-functional/init-submodule.sh`:
#
#   docker build -t rbitcoin-warnet:local \
#     --build-arg NODE_BIN=target/dev/debug/rbitcoin-node \
#     -f scripts/core-functional/warnet/Dockerfile .

FROM debian:bookworm-slim

ARG NODE_BIN=target/dev/debug/rbitcoin-node

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && cp /usr/bin/python3 /usr/local/bin/bitcoind

COPY ${NODE_BIN} /usr/local/bin/rbitcoin-node
COPY scripts/core-functional/bitcoind /opt/rbitcoin/shim/bitcoind
COPY scripts/core-functional/bitcoin-cli /usr/local/bin/bitcoin-cli
COPY scripts/core-functional/*.py /opt/rbitcoin/shim/
COPY scripts/core-functional/debuglog_map.toml /opt/rbitcoin/shim/
COPY third_party/bitcoin/test/functional/test_framework /opt/rbitcoin/functional/test_framework
COPY scripts/core-functional/warnet/entrypoint.sh /entrypoint.sh

RUN chmod +x /usr/local/bin/rbitcoin-node /usr/local/bin/bitcoin-cli \
        /opt/rbitcoin/shim/bitcoind /entrypoint.sh \
    && chmod 755 /usr/local/bin/bitcoind

ENV BITCOIN_DATA=/root/.bitcoin
ENV RBITCOIN_NODE=/usr/local/bin/rbitcoin-node
ENV RBITCOIN_LOG_STDOUT=1
ENV PYTHONPATH=/opt/rbitcoin/shim:/opt/rbitcoin/functional

ENTRYPOINT ["/entrypoint.sh"]
