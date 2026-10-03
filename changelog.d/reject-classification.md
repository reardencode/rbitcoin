Fixed

- **A spend of an output index past the parent's output count is a
  block reject.** A block that spends `(txid, vout)` where `txid` is
  confirmed, or created earlier in the same batch, but has no output at
  `vout` is rejected with `bad-txns-inputs-missingorspent`, as in Core.
  Before, load reported store corruption, IBD retried the block without
  end, and the tip path cached a store error string as the reject reason.
- **A store fault during tip connect or `submitblock` does not mark the
  block invalid.** A store IO error or a store invariant failure is no
  longer cached as an invalid block, and neither is a connect cancelled
  by shutdown. Before, the valid block was refused for the rest of the
  process. Consensus rejects are still cached. `submitblock` answers a
  store fault, including one reading the parent header, with RPC error
  `-25` (`RPC_VERIFY_ERROR`), as Core does for `state.IsError()`. A
  cancelled connect answers `inconclusive`, as Core does when shutdown
  interrupts the block check. Consensus rejects still return their
  BIP22 reason string.
