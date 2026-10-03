Fixed

- **A peer can no longer make IBD give up on a valid block by sending a
  bad body for it.** A body with no transactions, garbage transactions,
  a repeated tail (CVE-2012-2459), or witness data the coinbase does not
  commit to marked the block hash invalid, and IBD never asked for it
  again. Block checks now test the merkle root before the other body
  rules, as Bitcoin Core does. IBD treats these failures as a bad copy
  of the block: it drops the body and requests the block again.
