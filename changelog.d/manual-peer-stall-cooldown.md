Changed

- **IBD keeps a `--connect` peer that stalls block download, as in Core.**
  As in [bitcoin/bitcoin#34743](https://github.com/bitcoin/bitcoin/pull/34743),
  a `--connect` or `--trust-peer` peer that trips the IBD stall check is no
  longer disconnected and its address is not cooled. Its block requests go
  to the other peers, and it is sent no block `getdata` for two minutes on
  the node clock, then it is asked again. With no other peer, catch-up
  waits out those two minutes. INFO `ibd: Pausing block downloads from
  stalling manual peer=<id> for 120 seconds` marks the pause. If the peer
  then sends the blocks it was released from, they are accepted (or
  dropped as duplicates) and do not count as unsolicited. Any other
  stalling peer is still disconnected.
