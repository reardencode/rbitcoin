Added

- **RPC submit accepts version 3.** `sendrawtransaction`,
  `testmempoolaccept`, and `submitpackage` take `nVersion` 1 to 3, as Core
  does. Other versions are still `version`. P2P already took any version.
  Bark's server broadcasts version 3 for its vtxo tree, forfeit, connector,
  and exit transactions.
