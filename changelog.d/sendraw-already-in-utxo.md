Fixed

- **`sendrawtransaction` of a confirmed transaction with an unspent output is `-27`.**
  The message is `Transaction outputs already in utxo set`. It was `-26`
  `missing-inputs`, which wallets treat as a double spend. A confirmed
  transaction whose outputs are all spent stays `missing-inputs`.
