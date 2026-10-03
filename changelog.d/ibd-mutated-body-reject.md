Fixed

- **A peer can no longer make IBD give up on a valid block by sending a
  bad body for it.** A body with no transactions, garbage transactions,
  a repeated tail (CVE-2012-2459), a first transaction that is not a
  coinbase plus any 64-byte transaction, or witness data the coinbase
  does not commit to marked the block hash invalid, and IBD never asked
  for it again. Block checks now test the merkle root before the other
  body rules, as Bitcoin Core does. IBD treats these failures as a bad
  copy of the block: it drops the body and requests the block again.
  That request is no longer skipped: before, near the end of IBD, a
  block whose bad body was dropped could wait forever.
- **A block with a second coinbase or a repeated transaction is now
  remembered as invalid.** These blocks reported `bad-txns-duplicate`,
  the reason Bitcoin Core keeps for a mutated body, so the node did not
  remember them and asked for them again. They now report Core's
  `bad-cb-multiple` and `bad-txns-inputs-missingorspent`.
