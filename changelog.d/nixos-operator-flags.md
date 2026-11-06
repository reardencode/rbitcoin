Added

- **The NixOS module accepts the operator flags.** Peering, mempool, permission, index, RPC, signet, and notify settings are `services.rbitcoin` options. `p2p.maxInbound` defaults to 200 and omits `--max-inbound` at that value. `esplora.hiddenService = false` passes `--esplora-onion=0` when Tor control is on. `extraArgs` remains for `--conf`, test knobs, and secrets that must stay off argv.
