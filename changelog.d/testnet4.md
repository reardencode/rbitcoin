Added

- **`--network testnet4`.** Core's testnet4 chain (BIP94): P2P port 48333, RPC port 48332, Core's DNS and fixed seeds, `getblockchaininfo.chain` `testnet4`, and `tb` addresses. The conf file takes a bare `testnet4` line or `testnet4=1`, and NixOS `services.rbitcoin.network` takes `"testnet4"`.
- **BIP94 is enforced on testnet4.** A retarget multiplies the `nBits` of the period's first block, so a min-difficulty parent does not lower the next period. A period's first header more than 600 seconds before its parent is `time-timewarp-attack`. Mainnet, testnet3, signet, and regtest are unchanged. There is no `-test=bip94`.
- **Testnet4 runs every script by default.** The default milestone is 0, as on signet, and `--min-chain-work` defaults to Core's testnet4 `nMinimumChainWork`.
