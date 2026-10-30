Fixed

- **Every compact block that fails Core's `InitData` checks disconnects the peer (Core #35321).** A `cmpctblock` with no short ids and no prefilled txs, more than `MAX_BLOCK_TX_COUNT` (100,000) txs, or a prefilled index past 16 bits now disconnects, the same as an out-of-range prefilled index already did. This holds for a requested block and for an unsolicited one. Before, such a block got a `getdata` reply and the peer kept its score.
