Fixed

- **`submitblock` reports `bad-cb-height` for a wrong BIP34 coinbase
  height.** It returned `bip34 height encoding`, which is not a Bitcoin
  Core reason. The block is still remembered as invalid.
