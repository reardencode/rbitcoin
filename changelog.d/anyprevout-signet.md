Added

- The default signet enforces `SIGHASH_ANYPREVOUT` (BIP 118) from block
  106704, the Bitcoin Inquisition buried height. Regtest enables it at every
  height. Mainnet, testnet, and a custom signet stay off. While the
  deployment is off, a `0x01` public key stays an upgradable tapscript key.
