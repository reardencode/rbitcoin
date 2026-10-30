Fixed

- **Mempool entries carry `bip125-replaceable`.** `getmempoolentry`,
  verbose `getrawmempool`, and verbose `getmempoolancestors` /
  `getmempooldescendants` now return Core's field: `true` when the
  transaction or an in-mempool ancestor has an input sequence at or below
  `0xfffffffd`. Full RBF still replaces an opt-out transaction. Typed
  clients such as `bitcoincore-rpc` require the field and failed to decode
  the entry without it.
- **`getblockstats` returns `utxo_size_inc` and `utxo_size_inc_actual`.**
  As in Core, each output adds its serialized size plus 40 bytes, each
  spent prevout subtracts the same, and `utxo_size_inc_actual` counts only
  outputs that enter the UTXO set. `bitcoincore-rpc` requires both fields.
  A `stats` list that names neither skips the prevout reads. The Core
  functional harness no longer computes them in its proxy.
