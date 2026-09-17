#!/bin/sh
set -e
DATADIR="${BITCOIN_DATA:-/root/.bitcoin}"
export BITCOIN_DATA="$DATADIR"
export RBITCOIN_NODE="${RBITCOIN_NODE:-/usr/local/bin/rbitcoin-node}"
export RBITCOIN_LOG_STDOUT="${RBITCOIN_LOG_STDOUT:-1}"
export PYTHONPATH="${PYTHONPATH:-/opt/rbitcoin/shim:/opt/rbitcoin/functional}"
mkdir -p "$DATADIR"
if [ "$#" -eq 0 ]; then
  exec /usr/local/bin/bitcoind /opt/rbitcoin/shim/bitcoind -datadir="$DATADIR"
fi
exec /usr/local/bin/bitcoind /opt/rbitcoin/shim/bitcoind "$@"
