Fixed

- **A high-bandwidth compact announce can be served immediately.**
  `getblocktxn` and full-block `getdata` for that block are answered
  before the body is connected, including when the tip is past the
  ten-block `getblocktxn` depth and the five-block compact depth, and
  when a sibling or a different held branch wins the tip. A block that
  is not valid yet because its timestamp is too new, or whose parent
  was invalidated, stays servable. A mutated body does not.
  An invalidated block is not served. Peers that did not ask for
  high-bandwidth are not offered the block.
