Fixed

- **A spend of an output index past the parent's output count is a
  block reject.** A block that spends `(txid, vout)` where `txid` is
  confirmed, or created earlier in the same batch, but has no output at
  `vout` is rejected with `bad-txns-inputs-missingorspent`, as in Core.
  Before, load reported store corruption, IBD retried the block without
  end, and the tip path cached a store error string as the reject reason.
- **A store fault during tip connect or `submitblock` does not mark the
  block invalid.** A store IO error or a store invariant failure now
  returns a store error, and a cancelled connect returns `confirm
  cancelled`. Neither puts the block hash in the invalid-block cache. A
  second `submitblock` of the same block tries again instead of
  answering `duplicate-invalid`.
  Before, the valid block was refused for the rest of the process.
  Consensus rejects are still cached.
