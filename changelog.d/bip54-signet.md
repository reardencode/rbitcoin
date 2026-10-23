Added

- The default signet enforces BIP 54 consensus cleanup from block 291168,
  the Bitcoin Inquisition buried height: 64-byte transactions, the coinbase
  locktime and sequence rule, the two-hour timewarp limit, the negative
  difficulty-interval check, and the 2500-legacy-sigop transaction limit.
  Mainnet, testnet, a custom signet, and regtest stay off.
