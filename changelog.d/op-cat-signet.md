Added

- The default signet enforces `OP_CAT` (BIP 347) from block 193536, the
  Bitcoin Inquisition buried height. Regtest enables it at every height.
  Mainnet, testnet, and a custom signet stay off. While the deployment is
  off, the byte is still `OP_SUCCESS`.
