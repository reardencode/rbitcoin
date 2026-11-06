Added

- **TRUC sibling eviction.** A second child of a version-3 parent no longer
  fails with `TRUC-violation` when it pays enough. As in Core (BIP 431), it
  evicts the first child under the usual replacement fee rules, and is
  `insufficient fee (including sibling eviction)` when it does not pay
  enough. Without this, whoever got the first child in could pin the
  parent. As in Core, it applies only to a transaction judged alone: a
  package or a multi-transaction `testmempoolaccept` still gets
  `TRUC-violation`.
