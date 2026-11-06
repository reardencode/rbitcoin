Added

- **The NixOS module accepts the operator flags.** Peering, mempool, permission, index, RPC, signet, and notify settings are `services.rbitcoin` options. `p2p.maxInbound` defaults to 200 and omits `--max-inbound` at that value. `esplora.hiddenService = false` passes `--esplora-onion=0` when Tor control is on. `netPermissionBind` requires `p2p.listen` and is refused with `trustPeer`. `apiLog` outside the datadir is writable. `esplora.blockTemplate` and `esplora.socketPath` require `esplora.enable`. `extraArgs` remains for `--conf`, test knobs, and secrets that must stay off argv.
