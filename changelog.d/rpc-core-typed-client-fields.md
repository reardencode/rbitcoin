Fixed

- **Mempool entries carry `bip125-replaceable`.** `getmempoolentry`,
  verbose `getrawmempool`, and verbose `getmempoolancestors` /
  `getmempooldescendants` now return Core's field: `true` when the
  transaction or an in-mempool ancestor has an input sequence at or below
  `0xfffffffd`. Full RBF still replaces an opt-out transaction. Typed
  clients such as `bitcoincore-rpc` require the field and failed to decode
  the entry without it.
