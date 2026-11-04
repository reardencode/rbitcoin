Fixed

- **A high-bandwidth compact announce can be served immediately.**
  `getblocktxn` and full-block `getdata` for that block are answered
  before the body is connected, including when the tip is past the
  ten-block `getblocktxn` depth and when a sibling wins the tip.
  An invalidated block is not served. Peers that did not ask for
  high-bandwidth are not offered the block.
