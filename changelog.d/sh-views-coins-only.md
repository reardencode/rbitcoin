Fixed

- **Address views list coins only.** Electrum `listunspent` and Esplora
  `/utxo` listed `OP_RETURN` outputs (witness commitments included) and
  scripts over 10,000 bytes as unspent. Balance and `chain_stats` counted
  them. Those outputs are now skipped, and the paying transaction stays in
  history. The genesis coinbase no longer appears in any address view:
  Electrum showed it as a height-0 (mempool) row and as spendable.
