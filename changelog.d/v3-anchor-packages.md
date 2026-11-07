Added

- **RPC submit accepts version 3.** `sendrawtransaction`,
  `testmempoolaccept`, and `submitpackage` take `nVersion` 1 to 3, as Core
  does. Other versions are still `version`. P2P already took any version.
  Bark's server broadcasts version 3 for its vtxo tree, forfeit, connector,
  and exit transactions.
- **Version 3 follows BIP 431 TRUC.** A version-3 transaction may have one
  unconfirmed parent and one unconfirmed child, both version 3, at most
  10,000 vB, or 1,000 vB when its parent is unconfirmed. A non-version-3
  child of a version-3 parent is rejected too. Replacing the existing child
  is allowed, and so is a second child that pays to evict the first
  (sibling eviction). The limit is checked again when the transaction
  commits, so two children admitted at the same time cannot both enter.
- **A 0-fee transaction may carry one 0-value output (an anchor).** As in
  Core's ephemeral dust rule, the output is allowed only when the
  transaction pays no fee, and any child of it must spend that output or
  is `missing-ephemeral-spends`. A fee-paying transaction with a 0-value
  output, or two such outputs, is still `dust`. Alone the parent fails the
  minimum relay fee like any low-fee parent, so `submitpackage` admits it
  beside the child that pays for it. This is the shape of Bark's exit
  package. A package that replaces such a pair and then fails puts the
  pair back. `prioritisetransaction` refuses a transaction in the mempool
  that has a 0-value output, as Core does.
- **Peers relay the anchor pair.** A peer's 0-fee anchor parent and the
  child that spends the anchor are admitted together as 1p1c, whichever
  arrives first, so an exit package one node accepts reaches the rest of
  the network, also when a full mempool has raised the fee floor. The
  pair's combined feerate must clear that floor. A peer's child of any
  other low-fee parent still waits in the orphanage. A peer pair that
  fails, or a parent that fails inside a pair, is not tried again until
  the next block. One waiting child is tried per parent delivery, the
  parent's sender's child first, and a child that fails hard is dropped
  rather than parked again. If a pair's child fails after another peer's
  child of the same parent got in, the parent stays.
