Fixed

- **A high-bandwidth compact announce can be served immediately.**
  `getblocktxn` for a transaction in that block is answered before the
  body is connected. Peers that did not ask for high-bandwidth are not
  offered the block.
