Changed

- **The ping timeout waits while a peer is sending us blocks.** A peer
  answers our block requests before our ping, so on a slow link it could
  miss the 20-minute ping timeout and be disconnected while doing nothing
  wrong. As in Core
  ([bitcoin/bitcoin#36080](https://github.com/bitcoin/bitcoin/pull/36080)),
  the timeout is skipped while a requested block or a compact block that
  waits on `blocktxn` is in flight from that peer. After the last new block
  it sent, the peer has one minute to answer before the timeout applies
  again.
- **A tip-follow peer that stops delivering requested blocks is
  disconnected.** As in Core, a peer that keeps a block in flight for one
  block interval (10 minutes on mainnet), plus half of one for each other
  peer we are downloading from, is dropped and its requests go to other
  peers. Before, an announced body the peer never sent was asked again
  every 10 seconds from that peer alone.
- **`getpeerinfo` `last_block` counts new blocks only.** As in Core, it
  is set when a block from that peer is new to us, not when the peer
  re-sends one we already have. The ping timeout's one-minute grace and
  inbound eviction read the same time.
