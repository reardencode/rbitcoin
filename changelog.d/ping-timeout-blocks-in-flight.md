Changed

- **The ping timeout waits while a peer is sending us blocks.** A peer
  answers our block requests before our ping, so on a slow link it could
  miss the 20-minute ping timeout and be disconnected while doing nothing
  wrong. As in Core
  ([bitcoin/bitcoin#36080](https://github.com/bitcoin/bitcoin/pull/36080)),
  the timeout is skipped while a requested block or a compact block that
  waits on `blocktxn` is in flight from that peer. After the last block it
  sent, the peer has one minute to answer before the timeout applies again.
