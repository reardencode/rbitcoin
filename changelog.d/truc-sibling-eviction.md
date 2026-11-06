Added

- **TRUC sibling eviction.** A second child of a version-3 parent no longer
  fails with `TRUC-violation` when it pays enough. As in Core (BIP 431), it
  evicts the first child under Core's replacement fee rules (Libre's
  replace-by-feerate does not apply here), and is
  `insufficient fee (including sibling eviction)` when it does not pay
  enough. Without this, whoever got the first child in could pin the
  parent. As in Core, it applies to a transaction that pays its own way,
  sent alone or in a package. A package child that needs the package
  feerate to pay for it, and a multi-transaction `testmempoolaccept`, still
  get `TRUC-violation`.
