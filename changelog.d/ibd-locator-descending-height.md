Fixed

- **IBD finds a heavier fork of the confirmed chain.** The `getheaders`
  locator named the header walk's checkpoints before the confirmed tip. Core
  answers after the first hash on its chain, so with a candidate whose bodies
  nobody serves, a peer on a heavier fork sent 2,000 headers from a checkpoint
  the node already had, and the node stayed on that candidate
  ([#1337](https://github.com/reardencode/rbitcoin/issues/1337)). After the
  refill prefix, the stored tip and the proved points under an unproved
  queue, the locator now descends by height, as in Core.
