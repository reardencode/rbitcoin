Fixed

- **`submitblock` reports `bad-cb-height` for a wrong BIP34 coinbase
  height.** It returned `bip34 height encoding`, which is not a Bitcoin
  Core reason. The block is still remembered as invalid.
- **A coinbase scriptSig shorter than two bytes is `bad-cb-length` once
  BIP34 is active.** The height check ran first and reported the BIP34
  failure. Bitcoin Core checks the length first.
