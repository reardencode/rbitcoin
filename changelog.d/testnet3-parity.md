Fixed

- **Testnet3 BIP16 exception.** The testnet3 block Bitcoin Core exempts
  from script checks (`00000000dd30457c…a432b105`) no longer enforces
  P2SH, so full script validation accepts that historical block.
- **Testnet3 default milestone is anchored.** The omitted `--milestone` on
  testnet3 now requires Bitcoin Core's assumeutxo block at height 2500000
  and Core's testnet3 minimum chain work before it skips scripts, like
  mainnet. Before, any testnet chain skipped scripts up to 2500000 by
  height alone, and testnet had no default minimum chain work. Testnet3
  now uses Core's default minimum chain work, which also gates IBD state,
  relay, and low-work header handling until the chain reaches it.
