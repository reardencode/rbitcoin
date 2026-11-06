Fixed

- **A new peer is not offered a tip that did not move during the handshake.**
  The peer asks for that header itself. A block mined while the handshake
  was in progress is still announced once, as an inv. That inv does not
  count as a header the peer already has, so the next block after a long
  reorg stays an inv until the peer catches up.
