Fixed

- **IBD finds a heavier fork of the confirmed chain.** The `getheaders`
  locator named the header walk's checkpoints before the confirmed tip. Core
  answers after the first hash on its chain, so with a candidate whose bodies
  nobody serves, a peer on a heavier fork sent 2,000 headers from a checkpoint
  the node already had, and the node stayed on that candidate
  ([#1337](https://github.com/reardencode/rbitcoin/issues/1337)). While the
  queue has room the locator starts at the stored tip, then a lighter fork
  still being weighed when it is taller than the confirmed tip, then the
  proved points under an unproved queue. After that prefix it descends by
  height, as in Core, so the next ask continues that fork instead of
  resending the window that did not beat the candidate.
