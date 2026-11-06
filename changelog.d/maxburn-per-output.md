Fixed

- **`maxburnamount` checks each output, as in Core.** `sendrawtransaction`
  and `submitpackage` compared the sum of all unspendable outputs with the
  cap, so two 1,000 sat `OP_RETURN` outputs failed a 1,000 sat cap that Core
  accepts. Each output is now compared alone, and an output whose script
  does not parse counts as a burn, as in Core's `HasValidOps`.
