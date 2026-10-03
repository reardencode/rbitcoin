Fixed

- **`submitblock` reports `bad-cb-height` for a wrong BIP34 coinbase
  height.** It returned `bip34 height encoding`, which is not a Bitcoin
  Core reason. The block is still remembered as invalid.
- **A coinbase scriptSig shorter than two bytes is `bad-cb-length` once
  BIP34 is active.** The height check ran first and reported the BIP34
  failure. Bitcoin Core checks the length first.
- **`submitblock` checks the merkle root before the transactions.** A
  body the header does not commit to reported a transaction reason such
  as `bad-cb-missing` or `bad-txns-duplicate`. It now reports
  `bad-txnmrklroot`, as Bitcoin Core does.
- **`submitblock` reports Bitcoin Core's reason for a repeated
  transaction.** Every repeated txid was `bad-txns-duplicate`. Core keeps
  that reason for a repeat that leaves the merkle root unchanged. A second
  coinbase is now `bad-cb-multiple`, and any other repeat is
  `bad-txns-inputs-missingorspent`.
- **A transaction with no outputs or no inputs gets Bitcoin Core's reason.**
  `submitblock` and the block reject log said `no outputs` and `no inputs`.
  They now say `bad-txns-vout-empty` and `bad-txns-vin-empty`.
- **A block that spends an immature coinbase reports
  `bad-txns-premature-spend-of-coinbase`.** It said `coinbase immature`.
