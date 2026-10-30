Fixed

- **A transaction id repeated in one INV is handled once, as in Core.**
  A peer could list the same txid or wtxid many times in one INV. Each
  repeat of a hash already in the mempool took the mempool write lock
  again to record the announcer, and each repeat of an orphan's wtxid
  scheduled its parents again. A connection without a peer session also
  put every repeat of an unknown hash into its `getdata` reply and the
  `inv_tx` meter. `tx` and `witness-tx` now share one txid set per
  message, and `wtx` has its own (Core #35878). A wtxid with the same
  bytes as a txid is still a different id. The same id in a later INV is
  handled again.
