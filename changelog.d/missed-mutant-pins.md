Fixed

- **An output above the money limit is a block error, `bad-txns-vout-toolarge`, even when that transaction has no precomputed value row.** That path used to report a transaction error.
