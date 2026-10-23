Added

- The default signet enforces `OP_CHECKTEMPLATEVERIFY` (BIP 119) from block
  106704, the Bitcoin Inquisition buried height. Regtest enables it at every
  height. Mainnet, testnet, and a custom signet stay off. While the
  deployment is off, `OP_NOP4` stays a NOP.
