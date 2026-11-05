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
  is allowed; a second child is `TRUC-violation` (there is no sibling
  eviction). The limit is checked again when the transaction commits, so
  two children admitted at the same time cannot both enter.
- **A 0-fee transaction may carry one 0-value output (an anchor).** As in
  Core's ephemeral dust rule, the output is allowed only when the
  transaction pays no fee, and any child of it must spend that output or
  is `missing-ephemeral-spends`. A fee-paying transaction with a 0-value
  output, or two such outputs, is still `dust`. Alone the parent fails the
  minimum relay fee like any low-fee parent, so `submitpackage` admits it
  beside the child that pays for it. This is the shape of Bark's exit
  package. A package that replaces such a pair and then fails puts the
  pair back.
