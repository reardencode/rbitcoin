Fixed

- **`gettxout` hides an output of a mempool transaction that another mempool
  transaction spends.** Core's mempool coins view drops it; the confirmed
  branch already did. A wallet that picked coins with
  `gettxout(include_mempool=true)` double-spent its own unconfirmed change.
