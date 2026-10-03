Fixed

- **A miner can no longer get a valid block refused at the tip by first
  sending a fake body for its header.** A body with no coinbase that holds
  a 64-byte transaction can be the block's inner merkle nodes read as a
  transaction, so it matches the header's merkle root. The tip path cached
  that hash as invalid and then refused the real block. As in Bitcoin
  Core, such a body is now a mutated block on the tip, P2P `block`,
  compact block, and `submitblock` paths: a `block` message is dropped
  and its peer punished, a compact block falls back to a full download,
  and the hash is not marked invalid. `submitblock` also no longer caches
  a mutated body (for example padded witness bytes) as an invalid block.
  The IBD body path is covered by a separate change.
