Fixed

- **`sendrawtransaction` of a confirmed transaction with an unspent output is `-27`.**
  The message is `Transaction outputs already in utxo set`. It was `-26`
  `missing-inputs`, which wallets treat as a double spend. The check is
  after `maxburnamount` and before the version and `maxfeerate` rejects.
  A confirmed transaction whose outputs are all spent stays `missing-inputs`.
  The genesis coinbase stays `bad-txns-is-coinbase`.
