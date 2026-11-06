Fixed

- **Windows listen ports are exclusive.** Another process under the same
  user could bind a port the node listens on with `SO_REUSEADDR` and take
  its P2P, RPC, Electrum, Esplora, health, or SV2 connections. As in Core
  ([bitcoin/bitcoin#36305](https://github.com/bitcoin/bitcoin/pull/36305),
  [bitcoin/bitcoin#36169](https://github.com/bitcoin/bitcoin/pull/36169)),
  every listener now sets `SO_EXCLUSIVEADDRUSE` on Windows.
