Fixed

- **A negative output is `bad-txns-vout-negative`.** Blocks, `submitblock`,
  `testmempoolaccept`, `sendrawtransaction` and peer transactions reported
  it as `bad-txns-vout-toolarge`. Outputs are now checked in Core's
  `CheckTransaction` order (negative, above `MAX_MONEY`, then the running
  sum), and before a repeated input, in a block as in the mempool.
- **A block on an invalid parent is `bad-prevblk`.** `submitblock` answered
  `inconclusive` and kept the block, and `reconsiderblock` of the parent then
  made it the tip. As in Core, it is refused and not kept.
- **Side blocks are checked against their parent.** A block that did not
  extend the tip was kept with a non-final transaction, a wrong BIP34
  height, or a header older than its side parent's median time. As in
  Core's `AcceptBlock`, these are rejected before the block is kept, from
  `submitblock` and from peers.
