Added

- **`getmempoolentry` and verbose `getrawmempool` report
  `bip125-replaceable`**: true when the transaction or an unconfirmed ancestor
  signals BIP 125. `bitcoincore-rpc`'s `GetMempoolEntryResult` requires it.
